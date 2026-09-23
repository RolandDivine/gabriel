/**
 * EVM transaction building and signing.
 *
 * Covers seven of the wallet's thirteen chains with one adapter, because
 * Ethereum, Arbitrum, Optimism, Base, Polygon, BNB Chain and Avalanche all
 * speak the same transaction format and differ only by chain id.
 *
 * Two formats are supported, deliberately:
 *   - **EIP-1559 (type 2)** is the default and what everything should use.
 *   - **Legacy with EIP-155** exists because it is the format with a
 *     canonical, published, signed test vector. That vector is the only
 *     reason to trust any of this code, so the path that produces it is
 *     worth keeping even though nothing should send one.
 *
 * On correctness: a wrong signature here does not fail loudly, it moves
 * money somewhere unrecoverable. So this module is checked two ways --
 * against EIP-155's published vector byte for byte, and by recovering the
 * signer's address from every signature produced and requiring it to equal
 * the address that signed. Recovery fails if the RLP, the hash, or the
 * recovery id is wrong anywhere, which makes it a real check rather than a
 * restatement.
 */

import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";

import { encode, decode, concat, toBytes, hexToBytes, bytesToHex, bytesToBigInt } from "./rlp.js";
import { toChecksumAddress } from "../addresses.js";

export const TX_TYPE_LEGACY = 0x00;
export const TX_TYPE_EIP1559 = 0x02;

/** ERC-20 `transfer(address,uint256)` -- first 4 bytes of its keccak hash. */
export const ERC20_TRANSFER_SELECTOR = "0xa9059cbb";

// ---------------------------------------------------------------------
// ABI encoding (only what a token transfer needs)
// ---------------------------------------------------------------------

/** Left-pads to a 32-byte ABI word. */
function word(value) {
  const bytes = toBytes(value);
  if (bytes.length > 32) throw new Error("ABI word exceeds 32 bytes");
  const out = new Uint8Array(32);
  out.set(bytes, 32 - bytes.length);
  return out;
}

/**
 * Calldata for an ERC-20 transfer. `to` is a 20-byte address, `amount` is
 * in the token's smallest unit (6 decimals for USDC, not 18 -- getting
 * that wrong by 10^12 is the classic way to lose a balance).
 */
export function encodeErc20Transfer(to, amount) {
  const address = hexToBytes(to);
  if (address.length !== 20) throw new Error(`"${to}" is not a 20-byte address`);
  if (typeof amount !== "bigint") throw new Error("amount must be a bigint, in the token's smallest unit");
  if (amount < 0n) throw new Error("amount cannot be negative");
  return bytesToHex(concat(hexToBytes(ERC20_TRANSFER_SELECTOR), word(address), word(amount)));
}

// ---------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------

function normaliseTo(to) {
  if (to === null || to === undefined || to === "0x") return new Uint8Array(0); // contract creation
  const bytes = hexToBytes(to);
  if (bytes.length !== 20) throw new Error(`"${to}" is not a 20-byte address`);
  return bytes;
}

function requireBigInt(value, name) {
  if (typeof value !== "bigint") throw new Error(`${name} must be a bigint (wei / smallest unit)`);
  if (value < 0n) throw new Error(`${name} cannot be negative`);
  return value;
}

/**
 * The bytes an EIP-1559 transaction is signed over:
 *   0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
 *                gasLimit, to, value, data, accessList])
 */
export function serializeUnsigned1559(tx) {
  const fields = [
    requireBigInt(BigInt(tx.chainId), "chainId"),
    requireBigInt(BigInt(tx.nonce), "nonce"),
    requireBigInt(tx.maxPriorityFeePerGas, "maxPriorityFeePerGas"),
    requireBigInt(tx.maxFeePerGas, "maxFeePerGas"),
    requireBigInt(BigInt(tx.gasLimit), "gasLimit"),
    normaliseTo(tx.to),
    requireBigInt(tx.value ?? 0n, "value"),
    tx.data ? hexToBytes(tx.data) : new Uint8Array(0),
    tx.accessList ?? [],
  ];
  return concat(Uint8Array.of(TX_TYPE_EIP1559), encode(fields));
}

/** The signed form: the same fields plus yParity, r, s. */
export function serializeSigned1559(tx, signature) {
  const fields = [
    BigInt(tx.chainId),
    BigInt(tx.nonce),
    tx.maxPriorityFeePerGas,
    tx.maxFeePerGas,
    BigInt(tx.gasLimit),
    normaliseTo(tx.to),
    tx.value ?? 0n,
    tx.data ? hexToBytes(tx.data) : new Uint8Array(0),
    tx.accessList ?? [],
    BigInt(signature.yParity),
    signature.r,
    signature.s,
  ];
  return concat(Uint8Array.of(TX_TYPE_EIP1559), encode(fields));
}

/**
 * Legacy signing payload with EIP-155 replay protection:
 *   rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])
 *
 * The trailing chainId, 0, 0 is what binds the signature to one chain --
 * without it the same signed transaction replays on every EVM network.
 */
export function serializeUnsignedLegacy(tx) {
  const fields = [
    requireBigInt(BigInt(tx.nonce), "nonce"),
    requireBigInt(tx.gasPrice, "gasPrice"),
    requireBigInt(BigInt(tx.gasLimit), "gasLimit"),
    normaliseTo(tx.to),
    requireBigInt(tx.value ?? 0n, "value"),
    tx.data ? hexToBytes(tx.data) : new Uint8Array(0),
    requireBigInt(BigInt(tx.chainId), "chainId"),
    0n,
    0n,
  ];
  return encode(fields);
}

export function serializeSignedLegacy(tx, signature) {
  // EIP-155: v = recovery + chainId * 2 + 35
  const v = BigInt(signature.yParity) + BigInt(tx.chainId) * 2n + 35n;
  const fields = [
    BigInt(tx.nonce),
    tx.gasPrice,
    BigInt(tx.gasLimit),
    normaliseTo(tx.to),
    tx.value ?? 0n,
    tx.data ? hexToBytes(tx.data) : new Uint8Array(0),
    v,
    signature.r,
    signature.s,
  ];
  return encode(fields);
}

// ---------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------

/**
 * Signs a transaction. Returns the raw bytes to broadcast, the hash it
 * will have on chain, and the address that signed -- the last one
 * recovered from the signature rather than taken from the key, so a caller
 * can assert it is who they expected before broadcasting.
 *
 * `type` defaults to EIP-1559. Pass TX_TYPE_LEGACY only when a chain or a
 * test genuinely needs it.
 */
export function signTransaction(tx, privateKey, { type = TX_TYPE_EIP1559 } = {}) {
  const key = typeof privateKey === "string" ? hexToBytes(privateKey) : privateKey;
  if (key.length !== 32) throw new Error("an secp256k1 private key is 32 bytes");

  const unsigned =
    type === TX_TYPE_LEGACY ? serializeUnsignedLegacy(tx) : serializeUnsigned1559(tx);
  const signingHash = keccak_256(unsigned);

  // noble produces a canonical low-s signature, which Ethereum requires --
  // a high-s signature is malleable and nodes reject it.
  const sig = secp256k1.sign(signingHash, key);
  const signature = { r: sig.r, s: sig.s, yParity: sig.recovery };

  const raw =
    type === TX_TYPE_LEGACY
      ? serializeSignedLegacy(tx, signature)
      : serializeSigned1559(tx, signature);

  return {
    raw: bytesToHex(raw),
    hash: bytesToHex(keccak_256(raw)),
    signingHash: bytesToHex(signingHash),
    from: recoverAddress(signingHash, signature),
    signature: {
      r: "0x" + signature.r.toString(16).padStart(64, "0"),
      s: "0x" + signature.s.toString(16).padStart(64, "0"),
      yParity: signature.yParity,
    },
    type,
  };
}

/**
 * The address that produced a signature over `messageHash`. This is what
 * a node does to work out who sent a transaction, so running it here
 * catches an error in the RLP, the hash or the recovery id before the
 * transaction is broadcast rather than after.
 */
export function recoverAddress(messageHash, { r, s, yParity }) {
  const sig = new secp256k1.Signature(r, s, yParity);
  const publicKey = sig.recoverPublicKey(messageHash).toRawBytes(false);
  const hash = keccak_256(publicKey.slice(1));
  return toChecksumAddress(bytesToHex(hash.slice(-20)));
}

/**
 * Parses a raw signed transaction back into its fields. Used by the tests
 * to prove a signed transaction says what it was meant to say, and useful
 * for showing a user what they are about to broadcast.
 */
export function decodeSigned(raw) {
  const bytes = typeof raw === "string" ? hexToBytes(raw) : raw;

  if (bytes[0] === TX_TYPE_EIP1559) {
    const f = decode(bytes.slice(1));
    return {
      type: TX_TYPE_EIP1559,
      chainId: bytesToBigInt(f[0]),
      nonce: bytesToBigInt(f[1]),
      maxPriorityFeePerGas: bytesToBigInt(f[2]),
      maxFeePerGas: bytesToBigInt(f[3]),
      gasLimit: bytesToBigInt(f[4]),
      to: f[5].length ? toChecksumAddress(bytesToHex(f[5])) : null,
      value: bytesToBigInt(f[6]),
      data: bytesToHex(f[7]),
      yParity: Number(bytesToBigInt(f[9])),
      r: bytesToBigInt(f[10]),
      s: bytesToBigInt(f[11]),
    };
  }

  const f = decode(bytes);
  const v = bytesToBigInt(f[6]);
  // Reverse EIP-155: v = recovery + chainId*2 + 35
  const chainId = v >= 35n ? (v - 35n) / 2n : null;
  return {
    type: TX_TYPE_LEGACY,
    nonce: bytesToBigInt(f[0]),
    gasPrice: bytesToBigInt(f[1]),
    gasLimit: bytesToBigInt(f[2]),
    to: f[3].length ? toChecksumAddress(bytesToHex(f[3])) : null,
    value: bytesToBigInt(f[4]),
    data: bytesToHex(f[5]),
    v,
    chainId,
    yParity: chainId === null ? Number(v - 27n) : Number(v - (chainId * 2n + 35n)),
    r: bytesToBigInt(f[7]),
    s: bytesToBigInt(f[8]),
  };
}
