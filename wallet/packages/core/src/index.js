/**
 * @gabriel/wallet-core
 *
 * One mnemonic, thirteen chains, five address families, and a way to
 * publish "this device receives here" over the Gabriel mesh without a
 * directory server.
 *
 * Non-custodial by construction: there is no code path in this package
 * that holds someone else's key, and no ledger of balances between users.
 * A transfer between two Gabriel users is an ordinary on-chain transfer
 * between two addresses they each control.
 */

export { CHAINS, CHAIN_IDS, FAMILIES, getChain, chainsInFamily, derivationPath } from "./chains.js";
export {
  deriveAddress, isValidAddress, toChecksumAddress,
  evmAddress, tronAddress, segwitAddress, legacyAddress, utxoAddress,
  cosmosAddress, solanaAddress, hash160, bytesToHex, hexToBytes,
} from "./addresses.js";
export { Keyring } from "./keyring.js";
export {
  ATTESTATION_VERSION, DEFAULT_TTL_SECONDS,
  canonicalize, canonicalBytes, buildAttestation, signAttestation,
  verifyAttestation, resolveAddress, AddressDirectory,
} from "./attestation.js";
