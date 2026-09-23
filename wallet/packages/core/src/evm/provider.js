/**
 * Talking to an EVM chain: nonces, fees, balances, broadcast.
 *
 * Plain JSON-RPC over fetch against the endpoints in the chain registry.
 * Reads are safe to call freely; `broadcast` is the one irreversible
 * function in this package and is kept separate from `prepareTransfer` and
 * `signTransaction` for exactly that reason -- a caller has to build, sign
 * and broadcast as three deliberate steps, with a chance to show the user
 * what they are about to send in between.
 */

import { getChain } from "../chains.js";
import { encodeErc20Transfer, ERC20_TRANSFER_SELECTOR } from "./transaction.js";
import { hexToBytes, bytesToHex } from "./rlp.js";

/** `balanceOf(address)` -- for reading a token balance. */
const ERC20_BALANCE_OF_SELECTOR = "0x70a08231";

export async function rpc(url, method, params = [], { timeoutMs = 10000 } = {}) {
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

function endpoint(chainId) {
  const chain = getChain(chainId);
  if (chain.family !== "evm" || !chain.rpc) {
    throw new Error(`${chain.name} is not an EVM chain with an RPC endpoint`);
  }
  return chain;
}

export async function call(chainId, method, params, opts) {
  return rpc(endpoint(chainId).rpc, method, params, opts);
}

/**
 * The next nonce for `address`, counting transactions already in the
 * mempool. Using "pending" rather than "latest" is what stops a second
 * transaction reusing the nonce of one that hasn't been mined yet.
 */
export async function getNonce(chainId, address, opts) {
  return Number(BigInt(await call(chainId, "eth_getTransactionCount", [address, "pending"], opts)));
}

export async function getBalance(chainId, address, opts) {
  return BigInt(await call(chainId, "eth_getBalance", [address, "latest"], opts));
}

/** An ERC-20 balance, read with `balanceOf` -- no ABI library needed. */
export async function getTokenBalance(chainId, tokenAddress, holder, opts) {
  const padded = hexToBytes(holder);
  if (padded.length !== 20) throw new Error(`"${holder}" is not a 20-byte address`);
  const data = ERC20_BALANCE_OF_SELECTOR + "0".repeat(24) + holder.replace(/^0x/, "").toLowerCase();
  const result = await call(chainId, "eth_call", [{ to: tokenAddress, data }, "latest"], opts);
  return result === "0x" ? 0n : BigInt(result);
}

/**
 * EIP-1559 fees for the next block.
 *
 * `maxFeePerGas` is set to twice the current base fee plus the tip, which
 * gives room for the base fee to rise (it can climb 12.5% per block)
 * without overpaying: the base fee is refunded, so only the tip and the
 * actual base fee are ever charged.
 */
export async function getFees(chainId, opts) {
  const chain = endpoint(chainId);
  const [block, tipHex] = await Promise.all([
    rpc(chain.rpc, "eth_getBlockByNumber", ["latest", false], opts),
    rpc(chain.rpc, "eth_maxPriorityFeePerGas", [], opts).catch(() => null),
  ]);

  const baseFee = block?.baseFeePerGas ? BigInt(block.baseFeePerGas) : 0n;
  // Not every chain implements eth_maxPriorityFeePerGas; fall back to
  // eth_gasPrice, which every chain does.
  const tip = tipHex
    ? BigInt(tipHex)
    : BigInt(await rpc(chain.rpc, "eth_gasPrice", [], opts)) - baseFee;

  const maxPriorityFeePerGas = tip > 0n ? tip : 1n;
  return {
    baseFeePerGas: baseFee,
    maxPriorityFeePerGas,
    maxFeePerGas: baseFee * 2n + maxPriorityFeePerGas,
  };
}

export async function estimateGas(chainId, tx, opts) {
  const params = {
    from: tx.from,
    to: tx.to,
    value: tx.value ? "0x" + tx.value.toString(16) : "0x0",
    data: tx.data ?? "0x",
  };
  return BigInt(await call(chainId, "eth_estimateGas", [params], opts));
}

/**
 * Builds a ready-to-sign transaction: native send when `token` is absent,
 * ERC-20 transfer when it is present. Fetches the nonce, the fees and a
 * gas estimate, so the only thing the caller still supplies is intent.
 *
 * Does not sign and does not broadcast.
 */
export async function prepareTransfer({ chainId, from, to, amount, token, gasLimit }, opts) {
  const chain = endpoint(chainId);
  if (typeof amount !== "bigint") {
    throw new Error("amount must be a bigint, in the smallest unit (wei, or the token's)");
  }

  const isToken = Boolean(token);
  const target = isToken ? token : to;
  const data = isToken ? encodeErc20Transfer(to, amount) : "0x";
  const value = isToken ? 0n : amount;

  const [nonce, fees] = await Promise.all([getNonce(chainId, from, opts), getFees(chainId, opts)]);

  let gas = gasLimit ? BigInt(gasLimit) : null;
  if (!gas) {
    try {
      const estimated = await estimateGas(chainId, { from, to: target, value, data }, opts);
      gas = (estimated * 12n) / 10n; // 20% headroom
    } catch (err) {
      // A failed estimate usually means the transfer would revert -- an
      // empty balance, most often. Say so rather than guessing a limit and
      // letting the user pay for a failed transaction.
      throw new Error(
        `gas estimation failed, so this transfer would probably revert: ${err.message}`
      );
    }
  }

  return {
    chainId: chain.chainId,
    nonce,
    maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
    maxFeePerGas: fees.maxFeePerGas,
    gasLimit: Number(gas),
    to: target,
    value,
    data,
    // Not part of the signed payload -- carried alongside so a UI can show
    // what is about to happen before anyone signs.
    meta: {
      chain: chain.name,
      from,
      recipient: to,
      amount,
      token: token ?? null,
      symbol: chain.symbol,
      maxCostWei: fees.maxFeePerGas * gas,
    },
  };
}

/**
 * Broadcasts a signed transaction. **Irreversible.** Returns the hash the
 * chain assigned, which should match the hash `signTransaction` computed.
 */
export async function broadcast(chainId, rawSignedTx, opts) {
  const hash = await call(chainId, "eth_sendRawTransaction", [rawSignedTx], opts);
  return { hash, explorer: `${getChain(chainId).explorer}/tx/${hash}` };
}

/** Polls for a receipt. Returns null if it hasn't been mined in time. */
export async function waitForReceipt(chainId, hash, { timeoutMs = 120000, intervalMs = 3000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const receipt = await call(chainId, "eth_getTransactionReceipt", [hash]).catch(() => null);
    if (receipt) {
      return {
        ...receipt,
        succeeded: BigInt(receipt.status ?? "0x0") === 1n,
        gasUsed: BigInt(receipt.gasUsed ?? "0x0"),
      };
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return null;
}

/** Human-readable amount from a smallest-unit bigint. Display only. */
export function formatUnits(value, decimals) {
  const negative = value < 0n;
  const abs = negative ? -value : value;
  const base = 10n ** BigInt(decimals);
  const whole = abs / base;
  const fraction = (abs % base).toString().padStart(decimals, "0").replace(/0+$/, "");
  return `${negative ? "-" : ""}${whole}${fraction ? "." + fraction : ""}`;
}

/** Smallest-unit bigint from a decimal string. Used for user input. */
export function parseUnits(value, decimals) {
  const text = String(value).trim();
  if (!/^\d*\.?\d*$/.test(text) || text === "" || text === ".") {
    throw new Error(`"${value}" is not a decimal amount`);
  }
  const [whole = "0", fraction = ""] = text.split(".");
  if (fraction.length > decimals) {
    throw new Error(`too many decimal places: this token has ${decimals}`);
  }
  return BigInt(whole + fraction.padEnd(decimals, "0"));
}

export { ERC20_TRANSFER_SELECTOR, bytesToHex };
