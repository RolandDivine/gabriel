# Gabriel wallet

Non-custodial multi-chain wallet infrastructure. One recovery phrase,
thirteen chains, and a way to publish "this device receives here" over the
Gabriel mesh without a directory server.

## Why non-custodial

The brief was "users send crypto deposits to Gabriel, it stores them, and
they send to other users." Built literally, that means Gabriel holds
everyone's keys in a pooled wallet and settles transfers on an internal
ledger. That is a money transmitter: it needs licensing and AML controls
in every jurisdiction it operates in, and it recreates the off-chain
untraceable transfer layer this project already ruled out as a non-goal.

Non-custodial gives the same user-facing features — a deposit address on
every chain, balances, and paying another Gabriel user by name — with two
differences: the user holds their own keys, and every transfer settles
on-chain where anyone can audit it.

If custody is later a deliberate product decision, none of the code here
changes. The chain registry, the derivation, the address rules and the
attestation layer are identical. What changes is licensing, and that is
not a thing code can supply.

## The thirteen chains

Five families, because a family is what actually matters to a wallet:
which curve signs, how a public key becomes an address, how a transaction
is encoded.

| Family   | Chains                                                                   | Curve     | Address rule            |
|----------|--------------------------------------------------------------------------|-----------|-------------------------|
| `evm`    | Ethereum, Arbitrum, Optimism, Base, Polygon, BNB Chain, Avalanche         | secp256k1 | keccak256, EIP-55       |
| `utxo`   | Bitcoin, Litecoin, Dogecoin                                              | secp256k1 | bech32 (P2WPKH) / base58check |
| `solana` | Solana                                                                   | ed25519   | base58 of the key       |
| `tron`   | Tron                                                                     | secp256k1 | keccak256 + 0x41, base58check |
| `cosmos` | Cosmos Hub                                                               | secp256k1 | bech32 over HASH160     |

The seven EVM chains share one address on purpose: one Ethereum address is
the same address on Arbitrum and Base, which is what users expect. Adding
an eighth EVM chain is a config entry; adding another Solana is an adapter.

## The mesh is the address book

A Gabriel device already has an Ed25519 identity whose public key **is**
its device id, and peers already verify signatures from it on every
discovery beacon. So a device can sign a statement — "device `<id>`
receives on these addresses" — publish it over the mesh like anything
else, and any peer verifies it with machinery that already exists.

No directory server. No registry contract. No trusted third party.

```
$ gabriel-wallet attest --chains ethereum,bitcoin,solana --out att.json
signed attestation for device 26ceaae4650387d9... -> att.json

$ gabriel-wallet verify att.json
VALID  device 26ceaae4650387d9bc8b4b60419ac9b58489e2cf21a42e14094cf25af6870f67
  Ethereum   0x9858EfFD232B4033E47d90003D41EC34EcaEda94
  Bitcoin    bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
  Solana     HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk
```

Change one character of one address and it fails closed:

```
$ gabriel-wallet verify att-tampered.json
INVALID -- signature did not verify
```

**What this proves and what it does not.** It proves which device
published an address. It does not prove who owns the device. Binding a
device to a person is pairing and contact verification — a separate
problem this layer does not pretend to solve.

### Cross-language interop

The signer may be Rust (`gabriel-core`'s `Identity`, ed25519-dalek over raw
bytes) and the verifier JavaScript. Both sides sign **canonical JSON** —
keys sorted at every level, no insignificant whitespace — so they agree on
exactly which bytes were signed. Verified against the live node: reading
the Rust-written `identity.key` in JavaScript and deriving its public key
reproduces the device id the desktop app reports, byte for byte.

## Usage

```bash
npm install
node packages/cli/src/index.js new            # generate a recovery phrase
export GABRIEL_WALLET_MNEMONIC='word word ...'
node packages/cli/src/index.js addresses      # all 13 chains
node packages/cli/src/index.js chains
node packages/cli/src/index.js validate <address> <chain>
node packages/cli/src/index.js attest --out att.json
node packages/cli/src/index.js verify att.json
```

The mnemonic goes in the environment rather than a flag so it stays out of
shell history.

## Tests

```bash
node --test packages/core/test/addresses.test.js
node --test packages/core/test/attestation.test.js
```

Address derivation is checked against **published BIP-39/44/84 vectors**,
not against itself — the canonical all-"abandon" mnemonic must produce
`0x9858EfFD232B4033E47d90003D41EC34EcaEda94`,
`bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` and
`1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA`. Two independent implementations
agreeing on those is the actual assurance; asserting that our code equals
our code is not.

For the chains without a vector quoted here, the tests assert what would
actually catch a derivation bug: determinism, format validity under the
chain's own validator, and a decode that recovers exactly the bytes that
were encoded.

The attestation tests are mostly about what must *fail* — a tampered
address, a replayed older attestation, an expired one, one signed by a
different key than it claims.

## Not built yet

**Transaction building and broadcast.** This package derives, validates
and attests addresses. It does not yet sign a transfer.

That is deliberate sequencing, not an oversight. Signing a transaction
wrong loses money irreversibly, so the send path lands one family at a
time with its own test vectors rather than thirteen chains of
plausible-looking code at once. EVM first, since it covers seven of the
thirteen.

Also not built: balance indexing (needs an RPC layer with failover — the
public endpoints in the chain registry are fine for reading, not for a
product), fee estimation, and token transfers beyond the stablecoin
addresses already in the registry.
