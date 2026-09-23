#!/usr/bin/env node
/**
 * gabriel-wallet -- a CLI over @gabriel/wallet-core.
 *
 * Exists for the same reason gabriel-client does: so the library can be
 * exercised end-to-end before any UI depends on it, and so every claim in
 * the README can be checked by running something.
 *
 * Nothing here writes a private key to disk on its own. `new` prints a
 * mnemonic once and it is the operator's job to store it; every other
 * command takes the mnemonic from GABRIEL_WALLET_MNEMONIC so it never
 * lands in shell history.
 */

import { readFileSync, writeFileSync } from "node:fs";
import process from "node:process";

import {
  Keyring, CHAINS, CHAIN_IDS, getChain,
  buildAttestation, signAttestation, verifyAttestation, resolveAddress,
  isValidAddress, bytesToHex,
} from "@gabriel/wallet-core";
import { ed25519 } from "@noble/curves/ed25519";

const BOLD = "\u001b[1m", DIM = "\u001b[2m", RESET = "\u001b[0m";
const GREEN = "\u001b[32m", RED = "\u001b[31m", YELLOW = "\u001b[33m";

function die(message) {
  console.error(`${RED}error:${RESET} ${message}`);
  process.exit(1);
}

function mnemonic() {
  const m = process.env.GABRIEL_WALLET_MNEMONIC;
  if (!m) {
    die(
      "set GABRIEL_WALLET_MNEMONIC first.\n" +
      "  PowerShell:  $env:GABRIEL_WALLET_MNEMONIC = \"word word ...\"\n" +
      "  bash:        export GABRIEL_WALLET_MNEMONIC='word word ...'\n" +
      "Run `gabriel-wallet new` to generate one."
    );
  }
  try {
    return Keyring.fromMnemonic(m.trim());
  } catch (err) {
    die(err.message);
  }
}

function flag(args, name, fallback) {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? fallback : args[i + 1];
}

// ---------------------------------------------------------------------

const COMMANDS = {
  new(args) {
    const words = flag(args, "words", "12") === "24" ? 256 : 128;
    const keyring = Keyring.create({ strength: words });
    console.log(`${YELLOW}Write these words down and keep them offline.${RESET}`);
    console.log(`${YELLOW}Anyone who has them owns every address below, on all 13 chains.${RESET}\n`);
    console.log(`  ${BOLD}${keyring.exportMnemonic()}${RESET}\n`);
    console.log(`${DIM}Then:  $env:GABRIEL_WALLET_MNEMONIC = "<those words>"${RESET}`);
  },

  addresses(args) {
    const keyring = mnemonic();
    const account = Number(flag(args, "account", "0"));

    if (flag(args, "json", null) !== null) {
      console.log(JSON.stringify(keyring.addresses({ account }), null, 2));
      return;
    }

    console.log(`${BOLD}Receive addresses${RESET} ${DIM}(account ${account})${RESET}\n`);
    for (const group of keyring.addressBook({ account })) {
      const chains = group.chains.length > 1
        ? `${group.chains.length} chains: ${group.chains.join(", ")}`
        : group.chains[0];
      console.log(`  ${BOLD}${chains}${RESET}`);
      console.log(`  ${group.address}`);
      console.log(`  ${DIM}${group.path}${RESET}\n`);
    }
    console.log(`${DIM}The seven EVM chains share one address on purpose -- one`);
    console.log(`Ethereum address is the same address on Arbitrum, Base and the rest.${RESET}`);
  },

  chains() {
    console.log(`${BOLD}${CHAIN_IDS.length} chains across 5 families${RESET}\n`);
    const byFamily = {};
    for (const id of CHAIN_IDS) (byFamily[CHAINS[id].family] ??= []).push(CHAINS[id]);
    for (const [family, chains] of Object.entries(byFamily)) {
      console.log(`  ${BOLD}${family}${RESET} ${DIM}(${chains.length})${RESET}`);
      for (const c of chains) {
        const extra = c.chainId ? `chainId ${c.chainId}` : `coinType ${c.coinType}`;
        console.log(`    ${c.symbol.padEnd(6)} ${c.name.padEnd(22)} ${DIM}${extra}${RESET}`);
      }
      console.log();
    }
  },

  validate(args) {
    const [, address, chainId] = args;
    if (!address || !chainId) die("usage: gabriel-wallet validate <address> <chain>");
    getChain(chainId);
    const ok = isValidAddress(address, chainId);
    console.log(ok
      ? `${GREEN}valid${RESET} ${getChain(chainId).name} address`
      : `${RED}not a valid${RESET} ${getChain(chainId).name} address`);
    process.exit(ok ? 0 : 1);
  },

  /**
   * Signs an address attestation with this device's gabriel-core identity
   * key, so peers on the mesh can resolve "pay this device" to an address
   * with no directory server involved.
   */
  attest(args) {
    const keyring = mnemonic();
    const keyPath = flag(args, "identity",
      `${process.env.LOCALAPPDATA ?? "."}\\Gabriel\\identity.key`);
    const out = flag(args, "out", null);
    const only = flag(args, "chains", null);

    let seed;
    try {
      seed = new Uint8Array(readFileSync(keyPath));
    } catch {
      die(`couldn't read the Gabriel identity key at ${keyPath}\n` +
          "pass --identity <path>, or start the Gabriel desktop app once to create one.");
    }
    if (seed.length !== 32) die(`${keyPath} is ${seed.length} bytes; an Ed25519 seed is 32`);

    const deviceId = bytesToHex(ed25519.getPublicKey(seed));
    const wanted = only ? only.split(",").map((s) => s.trim()) : CHAIN_IDS;
    const addresses = {};
    for (const id of wanted) addresses[id] = keyring.address(id);

    const signed = signAttestation(buildAttestation({ deviceId, addresses }), seed);
    const json = JSON.stringify(signed, null, 2);

    if (out) {
      writeFileSync(out, json);
      console.log(`${GREEN}signed${RESET} attestation for device ${deviceId.slice(0, 16)}... -> ${out}`);
    } else {
      console.log(json);
    }
    console.log(`\n${DIM}This binds ${wanted.length} address(es) to a Gabriel device id.`);
    console.log(`It proves which device published them. It does NOT prove who owns the device.${RESET}`);
  },

  verify(args) {
    const file = args[1];
    if (!file) die("usage: gabriel-wallet verify <attestation.json> [--chain <id>]");
    let signed;
    try {
      signed = JSON.parse(readFileSync(file, "utf8"));
    } catch (err) {
      die(`couldn't read ${file}: ${err.message}`);
    }

    const check = verifyAttestation(signed);
    if (!check.valid) {
      console.log(`${RED}INVALID${RESET} -- ${check.reason}`);
      process.exit(1);
    }
    const { deviceId, addresses, expiresAt } = signed.attestation;
    console.log(`${GREEN}VALID${RESET}  device ${deviceId}`);
    console.log(`${DIM}expires ${new Date(expiresAt * 1000).toISOString()}${RESET}\n`);

    const chain = flag(args, "chain", null);
    if (chain) {
      console.log(`${getChain(chain).name}: ${resolveAddress(signed, chain)}`);
      return;
    }
    for (const [id, address] of Object.entries(addresses)) {
      console.log(`  ${getChain(id).name.padEnd(22)} ${address}`);
    }
  },

  help() {
    console.log(`${BOLD}gabriel-wallet${RESET} -- non-custodial multi-chain wallet for Gabriel

${BOLD}Commands${RESET}
  new [--words 24]              Generate a recovery phrase
  addresses [--account N]       Show receive addresses on all 13 chains
             [--json]
  chains                        List the supported chains by family
  validate <address> <chain>    Check an address is well-formed for a chain
  attest [--identity <path>]    Sign "this Gabriel device receives here"
         [--chains a,b] [--out f]
  verify <file> [--chain <id>]  Verify a signed attestation

${BOLD}Environment${RESET}
  GABRIEL_WALLET_MNEMONIC       Your recovery phrase (never passed as a flag,
                                so it stays out of shell history)

${BOLD}What this is${RESET}
  Non-custodial. Your keys derive from your phrase and never leave this
  machine. Gabriel holds nothing and settles nothing -- a payment between
  two Gabriel users is an ordinary on-chain transfer between two addresses
  they each control.

${BOLD}What is not built yet${RESET}
  Transaction building and broadcast. This package derives, validates and
  attests addresses; it does not yet sign a transfer. Signing a transaction
  wrong loses money, so the send path lands per family with its own test
  vectors rather than all at once.`);
  },
};

const args = process.argv.slice(2);
const command = args[0] ?? "help";
const handler = COMMANDS[command] ?? COMMANDS.help;
try {
  handler(args);
} catch (err) {
  die(err.message);
}
