/**
 * EVM transaction signing.
 *
 * A wrong signature here does not fail loudly -- it moves money somewhere
 * unrecoverable. So this is checked two independent ways:
 *
 *   1. **EIP-155's published vector**, byte for byte. The EIP specifies a
 *      transaction, a private key and the exact signed result. Reproducing
 *      it means the RLP, the signing hash, the recovery id and the v
 *      calculation are all right, verified against a specification rather
 *      than against this code.
 *
 *   2. **Address recovery on every signature produced.** Recovering the
 *      signer from a signature is what a node does to decide who sent a
 *      transaction. If the RLP, the hash or the recovery id were wrong
 *      anywhere, recovery returns a different address. That makes it a
 *      real check across cases with no published vector, rather than a
 *      restatement of the code under test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { keccak_256 } from "@noble/hashes/sha3";

import {
  signTransaction, recoverAddress, decodeSigned, encodeErc20Transfer,
  serializeUnsignedLegacy, serializeUnsigned1559,
  TX_TYPE_LEGACY, TX_TYPE_EIP1559, ERC20_TRANSFER_SELECTOR,
} from "../src/evm/transaction.js";
import { encode, decode, bytesToHex, hexToBytes } from "../src/evm/rlp.js";
import { formatUnits, parseUnits } from "../src/evm/provider.js";
import { Keyring } from "../src/keyring.js";
import { toChecksumAddress } from "../src/addresses.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { CHAINS } from "../src/chains.js";

// ---------------------------------------------------------------------
// RLP
// ---------------------------------------------------------------------

test("RLP matches the spec's own examples", () => {
  assert.equal(bytesToHex(encode("0x64")), "0x64", "a single byte under 0x80 encodes as itself");
  assert.equal(bytesToHex(encode(0n)), "0x80", "zero is the empty string, not 0x00");
  assert.equal(bytesToHex(encode([])), "0xc0", "the empty list");
  assert.equal(bytesToHex(encode(new Uint8Array(0))), "0x80");
  // "dog" -> 0x83 'd' 'o' 'g'
  assert.equal(bytesToHex(encode("0x646f67")), "0x83646f67");
  // ["cat", "dog"]
  assert.equal(bytesToHex(encode(["0x636174", "0x646f67"])), "0xc88363617483646f67");
});

test("RLP switches to the long form past 55 bytes", () => {
  const long = "0x" + "61".repeat(56);
  const encoded = encode(long);
  assert.equal(encoded[0], 0xb8, "0xb7 + 1 length byte");
  assert.equal(encoded[1], 56);
});

test("RLP round-trips nested structures", () => {
  const original = ["0x01", ["0x02", "0x0304"], "0x", "0x" + "ff".repeat(100)];
  const decoded = decode(encode(original));
  assert.equal(bytesToHex(decoded[0]), "0x01");
  assert.equal(bytesToHex(decoded[1][1]), "0x0304");
  assert.equal(decoded[2].length, 0);
  assert.equal(decoded[3].length, 100);
});

test("RLP rejects malformed input rather than guessing", () => {
  assert.throws(() => decode("0xc8836361"), /overruns|ended early|overran/);
  assert.throws(() => decode("0x8364" + "6f6700"), /trailing/);
  assert.throws(() => encode(-1n), /negative/);
  assert.throws(() => encode("no-0x-prefix"), /0x-prefixed/);
});

// ---------------------------------------------------------------------
// The published vector
// ---------------------------------------------------------------------

/**
 * Straight from EIP-155. This is the only assertion here that is checked
 * against an authority rather than against ourselves, which makes it the
 * foundation everything below rests on.
 */
const EIP155 = {
  privateKey: "0x4646464646464646464646464646464646464646464646464646464646464646",
  tx: {
    nonce: 9,
    gasPrice: 20000000000n,
    gasLimit: 21000,
    to: "0x3535353535353535353535353535353535353535",
    value: 1000000000000000000n,
    data: "0x",
    chainId: 1,
  },
  raw:
    "0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025" +
    "a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276" +
    "a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83",
};

test("the EIP-155 signing hash is the one the published signature was made over", () => {
  // Deliberately NOT asserted against a hash literal. Checking our own
  // output against a number we produced would prove nothing, and the
  // published EIP quotes the signed transaction rather than the hash.
  //
  // Instead this anchors in the published data: recover a signer from OUR
  // computed signing hash combined with the EIP's OWN r, s and v. If our
  // serialisation or hash were wrong by a single bit, recovery returns a
  // different address and this fails.
  const published = decodeSigned(EIP155.raw);
  const ourHash = keccak_256(serializeUnsignedLegacy(EIP155.tx));

  const expectedSigner = toChecksumAddress(
    bytesToHex(
      keccak_256(
        secp256k1.getPublicKey(hexToBytes(EIP155.privateKey), false).slice(1)
      ).slice(-20)
    )
  );

  const recovered = recoverAddress(ourHash, {
    r: published.r,
    s: published.s,
    yParity: published.yParity,
  });
  assert.equal(recovered, expectedSigner);
});

test("the EIP-155 signed transaction matches the specification byte for byte", () => {
  const signed = signTransaction(EIP155.tx, EIP155.privateKey, { type: TX_TYPE_LEGACY });
  assert.equal(signed.raw, EIP155.raw);
});

test("the EIP-155 vector decodes back to the transaction it encoded", () => {
  const decoded = decodeSigned(EIP155.raw);
  assert.equal(decoded.nonce, 9n);
  assert.equal(decoded.gasPrice, 20000000000n);
  assert.equal(decoded.gasLimit, 21000n);
  assert.equal(decoded.to.toLowerCase(), EIP155.tx.to);
  assert.equal(decoded.value, 1000000000000000000n);
  assert.equal(decoded.v, 37n, "v = recovery + chainId*2 + 35");
  assert.equal(decoded.chainId, 1n);
});

// ---------------------------------------------------------------------
// Recovery: the check that covers everything without a vector
// ---------------------------------------------------------------------

const keyring = Keyring.fromMnemonic(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
);
const account = keyring.deriveKey("ethereum");
const ADDRESS = keyring.address("ethereum");

test("an EIP-1559 signature recovers to the address that signed it", () => {
  const signed = signTransaction(
    {
      chainId: 1,
      nonce: 0,
      maxPriorityFeePerGas: 1000000000n,
      maxFeePerGas: 30000000000n,
      gasLimit: 21000,
      to: "0x3535353535353535353535353535353535353535",
      value: 1000000000000000n,
      data: "0x",
    },
    account.privateKey
  );
  assert.equal(signed.from, ADDRESS, "recovered signer must be the account that signed");
  assert.equal(signed.type, TX_TYPE_EIP1559);
  assert.ok(signed.raw.startsWith("0x02"), "type 2 envelope");
});

test("recovery holds across all seven EVM chains", () => {
  const evm = Object.values(CHAINS).filter((c) => c.family === "evm");
  assert.equal(evm.length, 7);
  for (const chain of evm) {
    const signed = signTransaction(
      {
        chainId: chain.chainId,
        nonce: 3,
        maxPriorityFeePerGas: 1000000n,
        maxFeePerGas: 50000000n,
        gasLimit: 65000,
        to: "0x3535353535353535353535353535353535353535",
        value: 0n,
        data: encodeErc20Transfer("0x3535353535353535353535353535353535353535", 1000000n),
      },
      account.privateKey
    );
    assert.equal(signed.from, ADDRESS, `${chain.name} recovered the wrong signer`);
    assert.equal(decodeSigned(signed.raw).chainId, BigInt(chain.chainId), `${chain.name} chainId`);
  }
});

test("a signature over a tampered transaction recovers to a different address", () => {
  const tx = {
    chainId: 1, nonce: 0, maxPriorityFeePerGas: 1n, maxFeePerGas: 2n,
    gasLimit: 21000, to: "0x3535353535353535353535353535353535353535",
    value: 1000n, data: "0x",
  };
  const signed = signTransaction(tx, account.privateKey);

  // Same signature, different transaction body -- what an attacker who
  // altered a transaction in flight would produce.
  const tamperedHash = keccak_256(serializeUnsigned1559({ ...tx, value: 999999n }));
  const recovered = recoverAddress(tamperedHash, {
    r: BigInt(signed.signature.r), s: BigInt(signed.signature.s), yParity: signed.signature.yParity,
  });
  assert.notEqual(recovered, ADDRESS, "a tampered body must not recover to the real signer");
});

test("every chain id produces a distinct signature for an otherwise identical transaction", () => {
  const base = {
    nonce: 1, maxPriorityFeePerGas: 1000000n, maxFeePerGas: 2000000n,
    gasLimit: 21000, to: "0x3535353535353535353535353535353535353535", value: 1n, data: "0x",
  };
  const raws = new Set(
    Object.values(CHAINS)
      .filter((c) => c.family === "evm")
      .map((c) => signTransaction({ ...base, chainId: c.chainId }, account.privateKey).raw)
  );
  // This is replay protection: the same transaction on Base must not be a
  // valid transaction on Arbitrum.
  assert.equal(raws.size, 7, "signatures must be bound to their chain id");
});

// ---------------------------------------------------------------------
// ERC-20 calldata
// ---------------------------------------------------------------------

test("the ERC-20 transfer selector is keccak('transfer(address,uint256)')[0..4]", () => {
  const expected = bytesToHex(keccak_256(new TextEncoder().encode("transfer(address,uint256)")).slice(0, 4));
  assert.equal(ERC20_TRANSFER_SELECTOR, expected);
  assert.equal(ERC20_TRANSFER_SELECTOR, "0xa9059cbb");
});

test("ERC-20 calldata is the selector plus two left-padded 32-byte words", () => {
  const data = encodeErc20Transfer("0x3535353535353535353535353535353535353535", 1500000n);
  assert.equal(hexToBytes(data).length, 4 + 32 + 32);
  assert.ok(data.startsWith("0xa9059cbb"));
  assert.ok(
    data.includes("0000000000000000000000003535353535353535353535353535353535353535"),
    "address is right-aligned in its word"
  );
  // 1,500,000 = 0x16e360 -- i.e. 1.5 USDC at 6 decimals
  assert.ok(data.endsWith("16e360"));
});

test("ERC-20 encoding refuses the mistakes that lose a balance", () => {
  assert.throws(() => encodeErc20Transfer("0x3535", 1n), /not a 20-byte address/);
  assert.throws(() => encodeErc20Transfer("0x3535353535353535353535353535353535353535", 1),
    /must be a bigint/, "a Number amount silently loses precision past 2^53");
  assert.throws(() => encodeErc20Transfer("0x3535353535353535353535353535353535353535", -1n), /negative/);
});

// ---------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------

test("signing refuses an under-specified transaction rather than defaulting", () => {
  const key = account.privateKey;
  assert.throws(() => signTransaction({ chainId: 1, nonce: 0, gasLimit: 21000, to: "0x35".padEnd(42, "3"), maxFeePerGas: 1n }, key),
    /maxPriorityFeePerGas must be a bigint/);
  assert.throws(() => signTransaction({ chainId: 1, nonce: 0, maxPriorityFeePerGas: 1n, maxFeePerGas: 1n, gasLimit: 21000, to: "0xdead" }, key),
    /not a 20-byte address/);
  assert.throws(() => signTransaction(EIP155.tx, "0xdeadbeef", { type: TX_TYPE_LEGACY }),
    /32 bytes/);
});

test("a contract creation (no `to`) is allowed and round-trips as null", () => {
  const signed = signTransaction(
    { chainId: 1, nonce: 0, maxPriorityFeePerGas: 1n, maxFeePerGas: 2n,
      gasLimit: 100000, to: null, value: 0n, data: "0x6000" },
    account.privateKey
  );
  assert.equal(signed.from, ADDRESS);
  assert.equal(decodeSigned(signed.raw).to, null);
});

// ---------------------------------------------------------------------
// Unit conversion
// ---------------------------------------------------------------------

test("parseUnits respects a token's own decimals", () => {
  // USDC is 6 decimals, not 18. Treating it as 18 sends 10^12 times too
  // little -- or, in the other direction, everything you have.
  assert.equal(parseUnits("1.5", 6), 1500000n);
  assert.equal(parseUnits("1.5", 18), 1500000000000000000n);
  assert.equal(parseUnits("0.000001", 6), 1n);
  assert.equal(parseUnits("1", 18), 10n ** 18n);
  assert.equal(parseUnits("0", 6), 0n);
  assert.equal(parseUnits(".5", 6), 500000n);
});

test("parseUnits refuses input it would have to round", () => {
  // Silently truncating a user's amount is how you send the wrong number.
  assert.throws(() => parseUnits("0.0000001", 6), /too many decimal places/);
  assert.throws(() => parseUnits("1.2.3", 6), /not a decimal amount/);
  assert.throws(() => parseUnits("abc", 6), /not a decimal amount/);
  assert.throws(() => parseUnits("", 6), /not a decimal amount/);
  assert.throws(() => parseUnits("-1", 6), /not a decimal amount/);
});

test("formatUnits and parseUnits round-trip", () => {
  for (const [text, decimals] of [["1.5", 6], ["0.000001", 6], ["1234.567891", 6],
                                   ["1", 18], ["0.000000000000000001", 18]]) {
    assert.equal(formatUnits(parseUnits(text, decimals), decimals), text);
  }
});

test("formatUnits trims trailing zeros but keeps significant ones", () => {
  assert.equal(formatUnits(1500000n, 6), "1.5");
  assert.equal(formatUnits(1000000n, 6), "1");
  assert.equal(formatUnits(1n, 6), "0.000001");
  assert.equal(formatUnits(0n, 6), "0");
  assert.equal(formatUnits(1000001n, 6), "1.000001");
});

test("a whole-token amount survives the trip into calldata", () => {
  // 25 USDC, at 6 decimals, ending up as 25000000 in the ABI word.
  const amount = parseUnits("25", 6);
  assert.equal(amount, 25000000n);
  const data = encodeErc20Transfer("0x3535353535353535353535353535353535353535", amount);
  assert.ok(data.endsWith((25000000).toString(16)), `calldata tail: ${data.slice(-16)}`);
});
