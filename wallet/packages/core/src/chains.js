/**
 * The chain registry.
 *
 * Thirteen chains across five families. A "family" is the thing that
 * actually matters to a wallet: which curve signs, how a public key
 * becomes an address, and how a transaction is encoded. Seven of the
 * thirteen are EVM chains, which is why adding an eighth EVM chain is a
 * config entry and adding a Solana is an adapter.
 *
 * `coinType` is the SLIP-0044 registered value used as the second level of
 * the BIP-44 path (m/44'/coinType'/account'/change/index). EVM chains all
 * share coin type 60 on purpose: one Ethereum address is the same address
 * on Arbitrum, Base, Polygon and the rest, which is what users expect.
 */

/** @typedef {"evm"|"utxo"|"solana"|"tron"|"cosmos"} Family */

export const CHAINS = Object.freeze({
  // ---- UTXO (secp256k1, base58check / bech32) ----
  bitcoin: {
    id: "bitcoin",
    name: "Bitcoin",
    family: "utxo",
    symbol: "BTC",
    decimals: 8,
    coinType: 0,
    // BIP-84 native segwit is the sane 2026 default: cheaper, and every
    // wallet and exchange handles bech32 now.
    purpose: 84,
    bech32Prefix: "bc",
    p2pkhVersion: 0x00,
    explorer: "https://mempool.space",
  },
  litecoin: {
    id: "litecoin",
    name: "Litecoin",
    family: "utxo",
    symbol: "LTC",
    decimals: 8,
    coinType: 2,
    purpose: 84,
    bech32Prefix: "ltc",
    p2pkhVersion: 0x30,
    explorer: "https://blockchair.com/litecoin",
  },
  dogecoin: {
    id: "dogecoin",
    name: "Dogecoin",
    family: "utxo",
    symbol: "DOGE",
    decimals: 8,
    coinType: 3,
    // Dogecoin has no segwit deployment, so legacy P2PKH is not a
    // preference here -- it is the only option.
    purpose: 44,
    bech32Prefix: null,
    p2pkhVersion: 0x1e,
    explorer: "https://blockchair.com/dogecoin",
  },

  // ---- EVM (secp256k1, keccak256) ----
  ethereum: {
    id: "ethereum", name: "Ethereum", family: "evm", symbol: "ETH",
    decimals: 18, coinType: 60, purpose: 44, chainId: 1,
    rpc: "https://eth.llamarpc.com", explorer: "https://etherscan.io",
    stablecoins: {
      USDC: { address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", decimals: 6 },
      USDT: { address: "0xdAC17F958D2ee523a2206206994597C13D831ec7", decimals: 6 },
    },
  },
  arbitrum: {
    id: "arbitrum", name: "Arbitrum One", family: "evm", symbol: "ETH",
    decimals: 18, coinType: 60, purpose: 44, chainId: 42161,
    rpc: "https://arb1.arbitrum.io/rpc", explorer: "https://arbiscan.io",
    stablecoins: {
      USDC: { address: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", decimals: 6 },
      USDT: { address: "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", decimals: 6 },
    },
  },
  optimism: {
    id: "optimism", name: "OP Mainnet", family: "evm", symbol: "ETH",
    decimals: 18, coinType: 60, purpose: 44, chainId: 10,
    rpc: "https://mainnet.optimism.io", explorer: "https://optimistic.etherscan.io",
    stablecoins: {
      USDC: { address: "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", decimals: 6 },
    },
  },
  base: {
    id: "base", name: "Base", family: "evm", symbol: "ETH",
    decimals: 18, coinType: 60, purpose: 44, chainId: 8453,
    rpc: "https://mainnet.base.org", explorer: "https://basescan.org",
    stablecoins: {
      USDC: { address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", decimals: 6 },
    },
  },
  polygon: {
    id: "polygon", name: "Polygon", family: "evm", symbol: "POL",
    decimals: 18, coinType: 60, purpose: 44, chainId: 137,
    rpc: "https://polygon-rpc.com", explorer: "https://polygonscan.com",
    stablecoins: {
      USDC: { address: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", decimals: 6 },
    },
  },
  bnb: {
    id: "bnb", name: "BNB Smart Chain", family: "evm", symbol: "BNB",
    decimals: 18, coinType: 60, purpose: 44, chainId: 56,
    rpc: "https://bsc-dataseed.binance.org", explorer: "https://bscscan.com",
    stablecoins: {
      USDT: { address: "0x55d398326f99059fF775485246999027B3197955", decimals: 18 },
    },
  },
  avalanche: {
    id: "avalanche", name: "Avalanche C-Chain", family: "evm", symbol: "AVAX",
    decimals: 18, coinType: 60, purpose: 44, chainId: 43114,
    rpc: "https://api.avax.network/ext/bc/C/rpc", explorer: "https://snowtrace.io",
    stablecoins: {
      USDC: { address: "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", decimals: 6 },
    },
  },

  // ---- Solana (ed25519, base58) ----
  solana: {
    id: "solana",
    name: "Solana",
    family: "solana",
    symbol: "SOL",
    decimals: 9,
    coinType: 501,
    purpose: 44,
    // Solana wallets derive m/44'/501'/i'/0' with every level hardened,
    // because ed25519 (SLIP-0010) has no non-hardened derivation at all.
    hardenedOnly: true,
    rpc: "https://api.mainnet-beta.solana.com",
    explorer: "https://solscan.io",
  },

  // ---- Tron (secp256k1, keccak256, base58check) ----
  tron: {
    id: "tron",
    name: "Tron",
    family: "tron",
    symbol: "TRX",
    decimals: 6,
    coinType: 195,
    purpose: 44,
    // Same keccak-of-pubkey as Ethereum, then a 0x41 version byte and
    // base58check instead of hex -- which is why this is a thin adapter
    // over the EVM one rather than its own implementation.
    addressPrefix: 0x41,
    rpc: "https://api.trongrid.io",
    explorer: "https://tronscan.org",
  },

  // ---- Cosmos (secp256k1, bech32) ----
  cosmos: {
    id: "cosmos",
    name: "Cosmos Hub",
    family: "cosmos",
    symbol: "ATOM",
    decimals: 6,
    coinType: 118,
    purpose: 44,
    bech32Prefix: "cosmos",
    rpc: "https://cosmos-rest.publicnode.com",
    explorer: "https://www.mintscan.io/cosmos",
  },
});

export const CHAIN_IDS = Object.freeze(Object.keys(CHAINS));

/** @returns {Family[]} */
export const FAMILIES = Object.freeze([...new Set(CHAIN_IDS.map((id) => CHAINS[id].family))]);

export function getChain(id) {
  const chain = CHAINS[id];
  if (!chain) {
    throw new Error(`unknown chain "${id}" -- known chains: ${CHAIN_IDS.join(", ")}`);
  }
  return chain;
}

export function chainsInFamily(family) {
  return CHAIN_IDS.filter((id) => CHAINS[id].family === family).map((id) => CHAINS[id]);
}

/**
 * The BIP-44 path for a chain. Solana is the exception: ed25519 has no
 * non-hardened derivation, so its path stops at the account level with
 * everything hardened.
 */
export function derivationPath(chain, { account = 0, change = 0, index = 0 } = {}) {
  const c = typeof chain === "string" ? getChain(chain) : chain;
  if (c.hardenedOnly) {
    return `m/${c.purpose}'/${c.coinType}'/${account}'/${change}'`;
  }
  return `m/${c.purpose}'/${c.coinType}'/${account}'/${change}/${index}`;
}
