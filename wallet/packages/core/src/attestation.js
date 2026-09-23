/**
 * Address attestations: the mesh is the address book.
 *
 * This is the part that makes Gabriel's wallet Gabriel's rather than a
 * generic one. A Gabriel device already has an Ed25519 identity whose
 * public key *is* its device id, and peers already verify signatures from
 * it on every discovery beacon. So a device can sign a statement of the
 * form "device <id> receives on these addresses", publish it over the mesh
 * the same way it publishes anything else, and any peer can check it with
 * machinery that already exists. No directory server, no registry
 * contract, no trusted third party.
 *
 * What that buys: "pay the laptop called roland-laptop" resolves to a
 * chain address that provably came from the device holding that identity.
 * What it does not buy: any assurance the *person* is who you think. This
 * binds an address to a key, not to a human. Pairing and contact
 * verification are a separate problem, and this file does not pretend to
 * solve it.
 *
 * The signature is over canonical JSON -- keys sorted, no whitespace -- so
 * the Rust side (ed25519-dalek over raw bytes) and this side agree on
 * exactly which bytes were signed.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { CHAIN_IDS, getChain } from "./chains.js";
import { isValidAddress, bytesToHex, hexToBytes } from "./addresses.js";

export const ATTESTATION_VERSION = 1;
/** Long enough to be useful offline, short enough that a rotated address propagates. */
export const DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60;

/**
 * Deterministic bytes for a value: object keys sorted at every level, no
 * insignificant whitespace. Two implementations that both do this produce
 * identical bytes, which is the whole requirement for a signature to
 * cross a language boundary.
 */
export function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(",")}}`;
}

export function canonicalBytes(value) {
  return new TextEncoder().encode(canonicalize(value));
}

/**
 * Builds the unsigned body. `addresses` is {chainId: address}; unknown
 * chains and addresses that fail their chain's format check are rejected
 * here rather than being signed and discovered to be junk by a payer.
 */
export function buildAttestation({ deviceId, addresses, issuedAt, ttlSeconds = DEFAULT_TTL_SECONDS }) {
  if (!/^[0-9a-f]{64}$/i.test(deviceId)) {
    throw new Error("deviceId must be a 64-character hex Ed25519 public key");
  }
  const entries = Object.entries(addresses);
  if (entries.length === 0) throw new Error("an attestation with no addresses says nothing");

  const clean = {};
  for (const [chainId, address] of entries) {
    if (!CHAIN_IDS.includes(chainId)) {
      throw new Error(`unknown chain "${chainId}" in attestation`);
    }
    if (!isValidAddress(address, chainId)) {
      throw new Error(`"${address}" is not a valid ${getChain(chainId).name} address`);
    }
    clean[chainId] = address;
  }

  const now = issuedAt ?? Math.floor(Date.now() / 1000);
  return {
    v: ATTESTATION_VERSION,
    deviceId: deviceId.toLowerCase(),
    addresses: clean,
    issuedAt: now,
    expiresAt: now + ttlSeconds,
  };
}

/**
 * Signs with the device's Ed25519 *private* key -- the same 32-byte seed
 * gabriel-core stores in identity.key. Returns a detached signature, so
 * the body stays readable.
 */
export function signAttestation(attestation, privateKey) {
  const key = typeof privateKey === "string" ? hexToBytes(privateKey) : privateKey;
  if (key.length !== 32) {
    throw new Error("an Ed25519 private key is 32 bytes -- this is gabriel-core's identity.key");
  }
  const signature = ed25519.sign(canonicalBytes(attestation), key);
  return { attestation, signature: bytesToHex(signature) };
}

/**
 * Verifies a signed attestation. Fails closed on every path: bad shape,
 * bad signature, expired, or a signature that verifies under some *other*
 * key than the device id it claims.
 *
 * @returns {{valid: boolean, reason?: string}}
 */
export function verifyAttestation(signed, { now = Math.floor(Date.now() / 1000) } = {}) {
  try {
    const { attestation, signature } = signed ?? {};
    if (!attestation || !signature) return { valid: false, reason: "missing attestation or signature" };
    if (attestation.v !== ATTESTATION_VERSION) {
      return { valid: false, reason: `unsupported attestation version ${attestation.v}` };
    }
    if (!/^[0-9a-f]{64}$/i.test(attestation.deviceId)) {
      return { valid: false, reason: "deviceId is not a 64-character hex key" };
    }
    if (typeof attestation.expiresAt !== "number" || attestation.expiresAt <= now) {
      return { valid: false, reason: "attestation has expired" };
    }
    if (typeof attestation.issuedAt !== "number" || attestation.issuedAt > now + 300) {
      // A small skew allowance, then reject: an attestation issued in the
      // future is either a broken clock or someone extending their own TTL.
      return { valid: false, reason: "attestation is issued in the future" };
    }

    // The device id is the verifying key. That is the point: there is
    // nothing else to trust and nothing else to look up.
    const ok = ed25519.verify(
      hexToBytes(signature),
      canonicalBytes(attestation),
      hexToBytes(attestation.deviceId)
    );
    return ok ? { valid: true } : { valid: false, reason: "signature did not verify" };
  } catch (err) {
    return { valid: false, reason: `malformed attestation: ${err.message}` };
  }
}

/**
 * Resolves "pay this Gabriel device on this chain" to an address, refusing
 * to return anything from an attestation that does not verify.
 */
export function resolveAddress(signed, chainId, opts = {}) {
  const check = verifyAttestation(signed, opts);
  if (!check.valid) throw new Error(`cannot trust this attestation: ${check.reason}`);
  const address = signed.attestation.addresses[chainId];
  if (!address) {
    const has = Object.keys(signed.attestation.addresses).join(", ");
    throw new Error(`that device published no ${chainId} address (it has: ${has})`);
  }
  return address;
}

/**
 * An in-memory directory of attestations seen on the mesh. Keeps the
 * freshest valid one per device and never stores an invalid one, so a
 * caller reading from it cannot accidentally pay an unverified address.
 */
export class AddressDirectory {
  #byDevice = new Map();

  /** @returns {{accepted: boolean, reason?: string}} */
  record(signed, opts = {}) {
    const check = verifyAttestation(signed, opts);
    if (!check.valid) return { accepted: false, reason: check.reason };

    const deviceId = signed.attestation.deviceId;
    const existing = this.#byDevice.get(deviceId);
    if (existing && existing.attestation.issuedAt >= signed.attestation.issuedAt) {
      // Older or replayed. Rejecting equal timestamps too means a captured
      // attestation can never displace the one already held.
      return { accepted: false, reason: "not newer than the attestation already held" };
    }
    this.#byDevice.set(deviceId, signed);
    return { accepted: true };
  }

  lookup(deviceId, chainId, opts = {}) {
    const signed = this.#byDevice.get(deviceId.toLowerCase());
    if (!signed) throw new Error(`no attestation seen for device ${deviceId.slice(0, 12)}...`);
    return resolveAddress(signed, chainId, opts);
  }

  devices() {
    return [...this.#byDevice.keys()];
  }

  get size() {
    return this.#byDevice.size;
  }
}
