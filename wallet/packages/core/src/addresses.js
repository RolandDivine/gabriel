/**
 * Public key -> address, per chain family.
 *
 * Every function here is pure: bytes in, string out, no network, no state.
 * That is deliberate -- address derivation is the part of a wallet where a
 * bug silently sends money to a hole, so it is kept small enough to read
 * in one sitting and is checked against published BIP-39/BIP-84 test
 * vectors in test/addresses.test.js.
 *
 * Primitives come from @noble and @scure (audited, minimal, same authors
 * as the BIP-32/39 implementations) rather than from a chain SDK per
 * chain. Five families need five address rules; pulling in five heavyweight
 * SDKs to get five rules would be a much larger surface to trust.
 */

import { keccak_256 } from "@noble/hashes/sha3";
import { sha256 } from "@noble/hashes/sha256";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { secp256k1 } from "@noble/curves/secp256k1";
import { base58, base58check, bech32 } from "@scure/base";

import { getChain } from "./chains.js";

const b58check = base58check(sha256);

// ---------------------------------------------------------------------
// EVM
// ---------------------------------------------------------------------

/**
 * Ethereum and every EVM chain: keccak256 of the 64-byte uncompressed
 * public key (minus its 0x04 prefix), last 20 bytes, EIP-55 checksummed.
 */
export function evmAddress(publicKey) {
  const uncompressed = secp256k1.ProjectivePoint.fromHex(publicKey).toRawBytes(false);
  const hash = keccak_256(uncompressed.slice(1));
  return toChecksumAddress(bytesToHex(hash.slice(-20)));
}

/** EIP-55: mixed-case checksum. Wrong case is how a typo'd address is caught. */
export function toChecksumAddress(hexAddress) {
  const addr = hexAddress.toLowerCase().replace(/^0x/, "");
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(addr)));
  let out = "0x";
  for (let i = 0; i < addr.length; i++) {
    out += parseInt(hash[i], 16) >= 8 ? addr[i].toUpperCase() : addr[i];
  }
  return out;
}

// ---------------------------------------------------------------------
// Tron
// ---------------------------------------------------------------------

/**
 * Tron takes Ethereum's 20 bytes, prepends 0x41, and base58check-encodes
 * the result -- which is why every Tron address starts with "T".
 */
export function tronAddress(publicKey, chain = getChain("tron")) {
  const uncompressed = secp256k1.ProjectivePoint.fromHex(publicKey).toRawBytes(false);
  const raw = keccak_256(uncompressed.slice(1)).slice(-20);
  const payload = new Uint8Array(21);
  payload[0] = chain.addressPrefix;
  payload.set(raw, 1);
  return b58check.encode(payload);
}

// ---------------------------------------------------------------------
// UTXO: Bitcoin, Litecoin, Dogecoin
// ---------------------------------------------------------------------

/** HASH160 = RIPEMD160(SHA256(pubkey)). The basis of every UTXO address. */
export function hash160(publicKey) {
  return ripemd160(sha256(publicKey));
}

/** BIP-84 native segwit (P2WPKH), e.g. bc1q... -- the modern default. */
export function segwitAddress(publicKey, chain) {
  const c = typeof chain === "string" ? getChain(chain) : chain;
  if (!c.bech32Prefix) {
    throw new Error(`${c.name} has no segwit deployment -- use legacyAddress`);
  }
  const words = bech32.toWords(hash160(publicKey));
  return bech32.encode(c.bech32Prefix, [0, ...words]);
}

/** BIP-44 legacy (P2PKH): version byte + HASH160, base58check. */
export function legacyAddress(publicKey, chain) {
  const c = typeof chain === "string" ? getChain(chain) : chain;
  const h = hash160(publicKey);
  const payload = new Uint8Array(21);
  payload[0] = c.p2pkhVersion;
  payload.set(h, 1);
  return b58check.encode(payload);
}

/** Whichever the chain config says this chain's default is. */
export function utxoAddress(publicKey, chain) {
  const c = typeof chain === "string" ? getChain(chain) : chain;
  return c.purpose === 84 ? segwitAddress(publicKey, c) : legacyAddress(publicKey, c);
}

// ---------------------------------------------------------------------
// Cosmos
// ---------------------------------------------------------------------

/** Cosmos: bech32 over HASH160 of the *compressed* secp256k1 key. */
export function cosmosAddress(publicKey, chain = getChain("cosmos")) {
  const compressed =
    publicKey.length === 33
      ? publicKey
      : secp256k1.ProjectivePoint.fromHex(publicKey).toRawBytes(true);
  return bech32.encode(chain.bech32Prefix, bech32.toWords(hash160(compressed)));
}

// ---------------------------------------------------------------------
// Solana
// ---------------------------------------------------------------------

/** Solana: the ed25519 public key itself, base58-encoded. No hashing. */
export function solanaAddress(publicKey) {
  return base58.encode(publicKey);
}

// ---------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------

/**
 * The one call site the rest of the wallet uses. Mirrors the shape of
 * gabriel-core's crypto::verify: dispatch on a declared family rather than
 * letting every caller re-derive which rule applies.
 */
export function deriveAddress(publicKey, chain) {
  const c = typeof chain === "string" ? getChain(chain) : chain;
  switch (c.family) {
    case "evm": return evmAddress(publicKey);
    case "tron": return tronAddress(publicKey, c);
    case "utxo": return utxoAddress(publicKey, c);
    case "cosmos": return cosmosAddress(publicKey, c);
    case "solana": return solanaAddress(publicKey);
    default: throw new Error(`no address rule for family "${c.family}"`);
  }
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

/**
 * Cheap structural validation before a send. Not a substitute for the
 * recipient confirming the address -- it catches a truncated paste or a
 * wrong-chain address, not a malicious one.
 */
export function isValidAddress(address, chain) {
  const c = typeof chain === "string" ? getChain(chain) : chain;
  try {
    switch (c.family) {
      case "evm": {
        if (!/^0x[0-9a-fA-F]{40}$/.test(address)) return false;
        // A mixed-case EVM address carries an EIP-55 checksum; an
        // all-one-case one predates it and can only be checked for shape.
        const body = address.slice(2);
        if (body === body.toLowerCase() || body === body.toUpperCase()) return true;
        return toChecksumAddress(address) === address;
      }
      case "tron":
        return address.startsWith("T") && b58check.decode(address).length === 21;
      case "cosmos": {
        const d = bech32.decode(address);
        return d.prefix === c.bech32Prefix && bech32.fromWords(d.words).length === 20;
      }
      case "solana": {
        const d = base58.decode(address);
        return d.length === 32;
      }
      case "utxo": {
        if (c.bech32Prefix && address.startsWith(c.bech32Prefix + "1")) {
          const d = bech32.decode(address);
          return d.prefix === c.bech32Prefix && d.words[0] === 0;
        }
        const d = b58check.decode(address);
        return d.length === 21 && d[0] === c.p2pkhVersion;
      }
      default:
        return false;
    }
  } catch {
    return false; // any decode failure is an invalid address, not a crash
  }
}

// ---------------------------------------------------------------------

export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex) {
  const clean = hex.replace(/^0x/, "");
  if (clean.length % 2 !== 0) throw new Error("hex string has an odd length");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex at byte ${i}`);
    out[i] = byte;
  }
  return out;
}
