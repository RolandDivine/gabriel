/**
 * Attestations are what let one Gabriel device pay another without a
 * directory server, so the tests here are mostly about what must *fail*:
 * a tampered address, a replayed old attestation, an expired one, one
 * signed by a different key than it claims.
 *
 * The canonicalisation tests matter for a reason that isn't obvious: the
 * signer may be Rust (ed25519-dalek over raw bytes) and the verifier
 * JavaScript, or the reverse. If the two sides disagree by one byte about
 * what was signed, every signature fails and the failure looks like a
 * crypto bug rather than a serialisation bug.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519";

import {
  canonicalize, buildAttestation, signAttestation, verifyAttestation,
  resolveAddress, AddressDirectory, DEFAULT_TTL_SECONDS,
} from "../src/attestation.js";
import { Keyring } from "../src/keyring.js";
import { bytesToHex } from "../src/addresses.js";

/** Stands in for a gabriel-core identity.key: a raw 32-byte Ed25519 seed. */
function device() {
  const privateKey = ed25519.utils.randomPrivateKey();
  return { privateKey, deviceId: bytesToHex(ed25519.getPublicKey(privateKey)) };
}

const wallet = Keyring.create();
const addresses = {
  ethereum: wallet.address("ethereum"),
  bitcoin: wallet.address("bitcoin"),
  solana: wallet.address("solana"),
};

// ---------------------------------------------------------------------
// Canonicalisation (cross-language agreement)
// ---------------------------------------------------------------------

test("canonicalisation is independent of key insertion order", () => {
  const a = { b: 1, a: 2, c: { z: 3, y: 4 } };
  const b = { c: { y: 4, z: 3 }, a: 2, b: 1 };
  assert.equal(canonicalize(a), canonicalize(b));
  assert.equal(canonicalize(a), '{"a":2,"b":1,"c":{"y":4,"z":3}}');
});

test("canonicalisation emits no insignificant whitespace", () => {
  const out = canonicalize({ a: [1, 2, { b: "x" }] });
  assert.equal(out, '{"a":[1,2,{"b":"x"}]}');
  assert.ok(!/\s/.test(out.replace(/"[^"]*"/g, "")), "no stray whitespace outside strings");
});

// ---------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------

test("a device can attest its addresses and any peer can verify them", () => {
  const { privateKey, deviceId } = device();
  const signed = signAttestation(buildAttestation({ deviceId, addresses }), privateKey);

  assert.deepEqual(verifyAttestation(signed), { valid: true });
  assert.equal(resolveAddress(signed, "ethereum"), addresses.ethereum);
  assert.equal(resolveAddress(signed, "bitcoin"), addresses.bitcoin);
});

test("the device id is the verifying key -- there is nothing else to look up", () => {
  const { privateKey, deviceId } = device();
  const signed = signAttestation(buildAttestation({ deviceId, addresses }), privateKey);
  // Verified with nothing but the bytes in the attestation itself.
  assert.ok(verifyAttestation(signed).valid);
  assert.equal(signed.attestation.deviceId, deviceId.toLowerCase());
});

// ---------------------------------------------------------------------
// What must fail
// ---------------------------------------------------------------------

test("tampering with an address invalidates the signature", () => {
  const { privateKey, deviceId } = device();
  const signed = signAttestation(buildAttestation({ deviceId, addresses }), privateKey);

  const attacker = Keyring.create().address("ethereum");
  signed.attestation.addresses.ethereum = attacker;

  const check = verifyAttestation(signed);
  assert.equal(check.valid, false);
  assert.match(check.reason, /signature did not verify/);
  assert.throws(() => resolveAddress(signed, "ethereum"), /cannot trust/);
});

test("an attestation signed by a different key than it claims is rejected", () => {
  const alice = device();
  const mallory = device();
  // Mallory signs a body that names Alice's device id.
  const forged = signAttestation(
    buildAttestation({ deviceId: alice.deviceId, addresses }),
    mallory.privateKey
  );
  assert.equal(verifyAttestation(forged).valid, false);
});

test("an expired attestation is rejected", () => {
  const { privateKey, deviceId } = device();
  const issuedAt = Math.floor(Date.now() / 1000) - DEFAULT_TTL_SECONDS - 10;
  const signed = signAttestation(buildAttestation({ deviceId, addresses, issuedAt }), privateKey);

  const check = verifyAttestation(signed);
  assert.equal(check.valid, false);
  assert.match(check.reason, /expired/);
});

test("an attestation issued in the future is rejected", () => {
  const { privateKey, deviceId } = device();
  const issuedAt = Math.floor(Date.now() / 1000) + 3600;
  const signed = signAttestation(buildAttestation({ deviceId, addresses, issuedAt }), privateKey);
  assert.match(verifyAttestation(signed).reason, /future/);
});

test("building refuses a malformed address instead of signing it", () => {
  const { deviceId } = device();
  assert.throws(
    () => buildAttestation({ deviceId, addresses: { ethereum: "0xnope" } }),
    /not a valid Ethereum address/
  );
  assert.throws(
    () => buildAttestation({ deviceId, addresses: { dogecoin: addresses.bitcoin } }),
    /not a valid Dogecoin address/
  );
  assert.throws(
    () => buildAttestation({ deviceId, addresses: { fakechain: "x" } }),
    /unknown chain/
  );
  assert.throws(() => buildAttestation({ deviceId, addresses: {} }), /says nothing/);
});

test("verification never throws on hostile input", () => {
  for (const junk of [null, {}, { attestation: {} }, { signature: "zz" },
                      { attestation: { v: 99 }, signature: "00" },
                      { attestation: { v: 1, deviceId: "x" }, signature: "00" }]) {
    assert.doesNotThrow(() => verifyAttestation(junk));
    assert.equal(verifyAttestation(junk).valid, false);
  }
});

// ---------------------------------------------------------------------
// Directory: replay and freshness
// ---------------------------------------------------------------------

test("the directory keeps the newest attestation and rejects a replayed older one", () => {
  const { privateKey, deviceId } = device();
  const now = Math.floor(Date.now() / 1000);

  const oldWallet = Keyring.create();
  const older = signAttestation(
    buildAttestation({ deviceId, addresses: { ethereum: oldWallet.address("ethereum") }, issuedAt: now - 600 }),
    privateKey
  );
  const newer = signAttestation(
    buildAttestation({ deviceId, addresses: { ethereum: addresses.ethereum }, issuedAt: now }),
    privateKey
  );

  const dir = new AddressDirectory();
  assert.equal(dir.record(older).accepted, true);
  assert.equal(dir.record(newer).accepted, true);
  assert.equal(dir.lookup(deviceId, "ethereum"), addresses.ethereum);

  // Replaying the older one -- validly signed, just stale -- must not
  // roll the directory back to the superseded address.
  const replay = dir.record(older);
  assert.equal(replay.accepted, false);
  assert.match(replay.reason, /not newer/);
  assert.equal(dir.lookup(deviceId, "ethereum"), addresses.ethereum);
});

test("the directory never stores an attestation that does not verify", () => {
  const { privateKey, deviceId } = device();
  const signed = signAttestation(buildAttestation({ deviceId, addresses }), privateKey);
  signed.attestation.addresses.bitcoin = Keyring.create().address("bitcoin");

  const dir = new AddressDirectory();
  assert.equal(dir.record(signed).accepted, false);
  assert.equal(dir.size, 0);
  assert.throws(() => dir.lookup(deviceId, "bitcoin"), /no attestation seen/);
});

test("looking up a chain the device never attested is an error, not a guess", () => {
  const { privateKey, deviceId } = device();
  const signed = signAttestation(
    buildAttestation({ deviceId, addresses: { ethereum: addresses.ethereum } }),
    privateKey
  );
  const dir = new AddressDirectory();
  dir.record(signed);
  assert.throws(() => dir.lookup(deviceId, "bitcoin"), /published no bitcoin address/);
});
