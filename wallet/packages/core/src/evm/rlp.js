/**
 * RLP: Ethereum's recursive length prefix encoding.
 *
 * Every Ethereum transaction is RLP under the hood, so this is the
 * foundation of the whole signing path. It is ~80 lines and fully
 * specified, which is why it is implemented here rather than pulled in --
 * an auditable 80 lines beats a dependency for something this central, and
 * `decode` exists so the tests can prove a round trip rather than trusting
 * `encode` on its own.
 *
 * The rules, in full:
 *   - a single byte in [0x00, 0x7f] encodes as itself
 *   - a byte string of length 0..55: 0x80 + length, then the bytes
 *   - a longer byte string: 0xb7 + byteLength(length), length, then bytes
 *   - a list whose payload is 0..55 bytes: 0xc0 + length, then payload
 *   - a longer list: 0xf7 + byteLength(length), length, then payload
 *
 * Integers are big-endian with no leading zeros, and zero is the *empty*
 * string rather than a 0x00 byte. Getting that wrong produces a valid-
 * looking transaction with a different hash, so `toBytes` is strict about
 * it rather than permissive.
 */

/** @typedef {Uint8Array|string|number|bigint|null|undefined|RlpInput[]} RlpInput */

/** Big-endian, minimal-length bytes. Zero becomes empty, per the spec. */
export function toBytes(value) {
  if (value === null || value === undefined) return new Uint8Array(0);
  if (value instanceof Uint8Array) return value;

  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`RLP integers must be safe non-negative integers, got ${value}`);
    }
    return toBytes(BigInt(value));
  }

  if (typeof value === "bigint") {
    if (value < 0n) throw new Error("RLP cannot encode a negative integer");
    if (value === 0n) return new Uint8Array(0); // zero is the empty string
    let hex = value.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    return hexToBytes(hex);
  }

  if (typeof value === "string") {
    if (!value.startsWith("0x")) {
      throw new Error(`RLP strings must be 0x-prefixed hex, got ${JSON.stringify(value.slice(0, 20))}`);
    }
    return hexToBytes(value);
  }

  throw new Error(`cannot RLP-encode a ${typeof value}`);
}

function encodeLength(length, offset) {
  if (length < 56) return Uint8Array.of(offset + length);
  const hex = length.toString(16);
  const lengthBytes = hexToBytes(hex.length % 2 ? "0" + hex : hex);
  return concat(Uint8Array.of(offset + 55 + lengthBytes.length), lengthBytes);
}

export function encode(input) {
  if (Array.isArray(input)) {
    const payload = concat(...input.map(encode));
    return concat(encodeLength(payload.length, 0xc0), payload);
  }
  const bytes = toBytes(input);
  // A lone byte below 0x80 is its own encoding -- no prefix.
  if (bytes.length === 1 && bytes[0] < 0x80) return bytes;
  return concat(encodeLength(bytes.length, 0x80), bytes);
}

/**
 * Decodes back to nested Uint8Arrays. Used by the tests to prove
 * `encode` round-trips, and by the transaction decoder.
 */
export function decode(data) {
  const bytes = data instanceof Uint8Array ? data : hexToBytes(data);
  const { value, consumed } = decodeItem(bytes, 0);
  if (consumed !== bytes.length) {
    throw new Error(`RLP has ${bytes.length - consumed} trailing byte(s)`);
  }
  return value;
}

function decodeItem(bytes, offset) {
  if (offset >= bytes.length) throw new Error("RLP input ended early");
  const prefix = bytes[offset];

  if (prefix < 0x80) {
    return { value: bytes.slice(offset, offset + 1), consumed: 1 };
  }
  if (prefix < 0xb8) {
    const length = prefix - 0x80;
    requireLength(bytes, offset + 1, length);
    return { value: bytes.slice(offset + 1, offset + 1 + length), consumed: 1 + length };
  }
  if (prefix < 0xc0) {
    const lengthOfLength = prefix - 0xb7;
    requireLength(bytes, offset + 1, lengthOfLength);
    const length = bytesToInt(bytes.slice(offset + 1, offset + 1 + lengthOfLength));
    requireLength(bytes, offset + 1 + lengthOfLength, length);
    const start = offset + 1 + lengthOfLength;
    return { value: bytes.slice(start, start + length), consumed: 1 + lengthOfLength + length };
  }

  // Lists
  let headerSize, payloadLength;
  if (prefix < 0xf8) {
    headerSize = 1;
    payloadLength = prefix - 0xc0;
  } else {
    const lengthOfLength = prefix - 0xf7;
    requireLength(bytes, offset + 1, lengthOfLength);
    headerSize = 1 + lengthOfLength;
    payloadLength = bytesToInt(bytes.slice(offset + 1, offset + 1 + lengthOfLength));
  }
  requireLength(bytes, offset + headerSize, payloadLength);

  const items = [];
  let cursor = offset + headerSize;
  const end = cursor + payloadLength;
  while (cursor < end) {
    const item = decodeItem(bytes, cursor);
    items.push(item.value);
    cursor += item.consumed;
  }
  if (cursor !== end) throw new Error("an RLP list item overran its parent");
  return { value: items, consumed: headerSize + payloadLength };
}

function requireLength(bytes, offset, length) {
  if (length < 0 || offset + length > bytes.length) {
    throw new Error("RLP length prefix overruns the input");
  }
}

function bytesToInt(bytes) {
  let n = 0;
  for (const b of bytes) n = n * 256 + b;
  if (!Number.isSafeInteger(n)) throw new Error("RLP length exceeds a safe integer");
  return n;
}

export function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2) throw new Error("hex string has an odd length");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex at byte ${i}`);
    out[i] = byte;
  }
  return out;
}

export function bytesToHex(bytes) {
  return "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function bytesToBigInt(bytes) {
  return bytes.length === 0 ? 0n : BigInt(bytesToHex(bytes));
}
