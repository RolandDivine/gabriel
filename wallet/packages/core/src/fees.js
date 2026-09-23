/**
 * Live settlement cost, measured rather than assumed.
 *
 * The bandwidth market lives or dies on one ratio: what a transfer costs
 * versus what the bytes are worth. At $0.10/GB a 100MB session is worth
 * $0.01, which is small enough that a transaction fee can eat most of it,
 * so guessing at gas prices is not good enough -- this asks the chains.
 *
 * Deliberately read-only and dependency-free: plain JSON-RPC over fetch,
 * against the endpoints already in the chain registry. Native token prices
 * have to come from the caller, because a price feed is a product decision
 * (and a trust decision) rather than something to hardcode here.
 */

import { CHAINS, chainsInFamily } from "./chains.js";

/**
 * Gas used by an ERC-20 `transfer`. The real figure depends on whether the
 * recipient already holds a balance -- writing a zero slot to non-zero
 * costs far more than updating a non-zero one -- so this is the expensive
 * case, which is the honest one to plan against.
 */
export const ERC20_TRANSFER_GAS = 65000n;
/** A plain native-token send. */
export const NATIVE_TRANSFER_GAS = 21000n;

async function rpc(url, method, params = [], { timeoutMs = 8000 } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = await response.json();
    if (body.error) throw new Error(body.error.message ?? "RPC error");
    return body.result;
  } finally {
    clearTimeout(timer);
  }
}

/** Current gas price in wei, as the chain reports it. */
export async function gasPrice(chainId, opts = {}) {
  const chain = CHAINS[chainId];
  if (!chain?.rpc || chain.family !== "evm") {
    throw new Error(`${chainId} is not an EVM chain with an RPC endpoint`);
  }
  return BigInt(await rpc(chain.rpc, "eth_gasPrice", [], opts));
}

/**
 * What one stablecoin transfer costs on `chainId`, in USD.
 *
 * `nativePriceUsd` is the price of the chain's gas token. Passing it in
 * rather than fetching it keeps this function honest about where the
 * number came from.
 */
export async function transferCostUsd(chainId, nativePriceUsd, opts = {}) {
  const wei = await gasPrice(chainId, opts);
  const gas = opts.gas ?? ERC20_TRANSFER_GAS;
  const totalWei = wei * gas;
  // 1e18 wei per token. Done in floating point only at the end, after the
  // integer arithmetic that actually matters.
  const nativeUnits = Number(totalWei) / 1e18;
  return {
    chainId,
    name: CHAINS[chainId].name,
    gasPriceGwei: Number(wei) / 1e9,
    gas: Number(gas),
    nativeUnits,
    usd: nativeUnits * nativePriceUsd,
  };
}

/**
 * The question the bandwidth market actually asks: at this price per
 * gigabyte, how much data must one settlement cover before the fee stops
 * being a significant cut of it?
 *
 * Returns the fee as a share of a settlement of `gigabytes`, plus the
 * smallest settlement that keeps the fee under `maxFeeShare`.
 */
export function settlementViability({ feeUsd, usdPerGigabyte, gigabytes = 1, maxFeeShare = 0.01 }) {
  const revenue = usdPerGigabyte * gigabytes;
  const feeShare = revenue > 0 ? feeUsd / revenue : Infinity;
  // Smallest settlement whose fee is at most maxFeeShare of its value.
  const minGigabytes = feeUsd / (usdPerGigabyte * maxFeeShare);
  return {
    revenue,
    feeUsd,
    feeShare,
    viable: feeShare <= maxFeeShare,
    minGigabytes,
    minMegabytes: minGigabytes * 1024,
  };
}

/**
 * Same question for a payment channel: the buyer and seller pay to open
 * and to close, and everything in between is off-chain. Two transactions
 * amortised over a whole relationship instead of one per session.
 */
export function channelViability({ feeUsd, usdPerGigabyte, gigabytesPerPeriod }) {
  const revenue = usdPerGigabyte * gigabytesPerPeriod;
  const total = feeUsd * 2; // open + close
  return {
    revenue,
    feeUsd: total,
    feeShare: revenue > 0 ? total / revenue : Infinity,
    transactions: 2,
  };
}

/** Every EVM chain in the registry, measured in parallel. */
export async function surveyEvmFees(nativePrices, opts = {}) {
  const chains = chainsInFamily("evm");
  const results = await Promise.allSettled(
    chains.map((c) => transferCostUsd(c.id, nativePrices[c.symbol] ?? 0, opts))
  );
  return results.map((r, i) =>
    r.status === "fulfilled"
      ? r.value
      : { chainId: chains[i].id, name: chains[i].name, error: r.reason.message }
  );
}
