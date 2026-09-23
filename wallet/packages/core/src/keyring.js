/**
 * The keyring: one mnemonic, every chain.
 *
 * BIP-39 seed -> BIP-32 (secp256k1) or SLIP-0010 (ed25519) -> per-chain
 * key -> address. Twelve of the thirteen chains ride BIP-32; Solana needs
 * SLIP-0010 because ed25519 has no non-hardened derivation, so it gets a
 * small implementation here rather than a second HD library.
 *
 * Private key material stays inside this module's objects. Nothing here
 * logs, serialises or transmits a private key, and the only way one leaves
 * is `exportMnemonic()`, which a caller has to ask for by name.
 */

import { HDKey } from "@scure/bip32";
import * as bip39 from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";
import { ed25519 } from "@noble/curves/ed25519";

import { CHAINS, CHAIN_IDS, getChain, derivationPath } from "./chains.js";
import { deriveAddress, bytesToHex } from "./addresses.js";

const ED25519_CURVE = new TextEncoder().encode("ed25519 seed");
const HARDENED = 0x80000000;

// ---------------------------------------------------------------------
// SLIP-0010 for ed25519 (Solana)
// ---------------------------------------------------------------------

/**
 * SLIP-0010 ed25519 derivation. Only hardened children exist on this
 * curve, so a path with a non-hardened segment is a caller error rather
 * than something to silently coerce.
 */
function deriveEd25519(seed, path) {
  const I = hmac(sha512, ED25519_CURVE, seed);
  let key = I.slice(0, 32);
  let chainCode = I.slice(32);

  const segments = path.split("/").slice(1); // drop the leading "m"
  for (const segment of segments) {
    if (!segment.endsWith("'") && !segment.endsWith("h")) {
      throw new Error(
        `ed25519 has no non-hardened derivation, but path segment "${segment}" is not hardened`
      );
    }
    const index = parseInt(segment.slice(0, -1), 10) + HARDENED;

    // data = 0x00 || key || index (big-endian)
    const data = new Uint8Array(1 + 32 + 4);
    data.set(key, 1);
    new DataView(data.buffer).setUint32(33, index, false);

    const child = hmac(sha512, chainCode, data);
    key = child.slice(0, 32);
    chainCode = child.slice(32);
  }
  return { privateKey: key, publicKey: ed25519.getPublicKey(key) };
}

// ---------------------------------------------------------------------
// Keyring
// ---------------------------------------------------------------------

export class Keyring {
  #mnemonic;
  #seed;
  #root;

  constructor(mnemonic, passphrase = "") {
    if (!bip39.validateMnemonic(mnemonic, wordlist)) {
      throw new Error("not a valid BIP-39 mnemonic (check the word list and the checksum)");
    }
    this.#mnemonic = mnemonic;
    this.#seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
    this.#root = HDKey.fromMasterSeed(this.#seed);
  }

  /** A fresh 12- or 24-word wallet. 256 bits gives 24 words. */
  static create({ strength = 128, passphrase = "" } = {}) {
    return new Keyring(bip39.generateMnemonic(wordlist, strength), passphrase);
  }

  static fromMnemonic(mnemonic, passphrase = "") {
    return new Keyring(mnemonic, passphrase);
  }

  /**
   * The recovery phrase. Named so that it is obvious at every call site
   * that secret material is being handed out.
   */
  exportMnemonic() {
    return this.#mnemonic;
  }

  /**
   * The key for one chain at one index. `privateKey` is present so a
   * signer can use it; callers that only need an address should use
   * `address()` and never hold the private half at all.
   */
  deriveKey(chainId, { account = 0, change = 0, index = 0 } = {}) {
    const chain = getChain(chainId);
    const path = derivationPath(chain, { account, change, index });

    if (chain.family === "solana") {
      const { privateKey, publicKey } = deriveEd25519(this.#seed, path);
      return { chain, path, privateKey, publicKey, curve: "ed25519" };
    }

    const node = this.#root.derive(path);
    if (!node.privateKey) throw new Error(`derivation produced no private key for ${path}`);
    return {
      chain,
      path,
      privateKey: node.privateKey,
      publicKey: node.publicKey, // compressed secp256k1
      curve: "secp256k1",
    };
  }

  /** The receive address for one chain. */
  address(chainId, opts = {}) {
    const key = this.deriveKey(chainId, opts);
    return deriveAddress(key.publicKey, key.chain);
  }

  /**
   * Every chain's address for one account index -- what a wallet shows on
   * its "receive" screen, and what gets published in a Gabriel address
   * attestation.
   */
  addresses({ account = 0, index = 0 } = {}) {
    const out = {};
    for (const id of CHAIN_IDS) {
      const key = this.deriveKey(id, { account, index });
      out[id] = {
        chainId: id,
        name: CHAINS[id].name,
        symbol: CHAINS[id].symbol,
        family: CHAINS[id].family,
        path: key.path,
        address: deriveAddress(key.publicKey, key.chain),
        publicKey: bytesToHex(key.publicKey),
      };
    }
    return out;
  }

  /**
   * The seven EVM chains share one address, so listing them separately on
   * a receive screen is noise. This collapses them.
   */
  addressBook(opts = {}) {
    const all = this.addresses(opts);
    const groups = [];
    const seen = new Map();
    for (const entry of Object.values(all)) {
      const key = entry.family === "evm" ? `evm:${entry.address}` : entry.chainId;
      if (seen.has(key)) {
        seen.get(key).chains.push(entry.name);
        continue;
      }
      const group = {
        address: entry.address,
        family: entry.family,
        path: entry.path,
        chains: [entry.name],
        primaryChainId: entry.chainId,
      };
      seen.set(key, group);
      groups.push(group);
    }
    return groups;
  }
}
