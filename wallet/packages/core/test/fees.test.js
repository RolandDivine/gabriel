/**
 * The settlement-viability maths, which is what decides whether the
 * bandwidth market is a product or a rounding error.
 *
 * Pure arithmetic only -- no network. The live measurement in
 * `surveyEvmFees` is deliberately not asserted here: gas prices move every
 * block, so a test that pinned them would fail for reasons that have
 * nothing to do with this code. What is asserted is that the maths
 * converting a fee into "how much data must one settlement cover" is
 * right, because that is the number the roadmap was re-planned around.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { settlementViability, channelViability, ERC20_TRANSFER_GAS } from "../src/fees.js";

const USD_PER_GB = 0.10; // Roland's figure: $0.10/GB, $0.01 per 100MB

test("a 100MB session is worth one cent at $0.10/GB", () => {
  const v = settlementViability({ feeUsd: 0, usdPerGigabyte: USD_PER_GB, gigabytes: 100 / 1024 });
  assert.ok(Math.abs(v.revenue - 0.0098) < 0.0002, `got $${v.revenue.toFixed(5)}`);
});

test("Optimism's measured fee clears 1% on a sub-gigabyte settlement", () => {
  // $0.00017 measured 2026-09-23. The point of the assertion is the
  // threshold behaviour, not the exact fee.
  const v = settlementViability({ feeUsd: 0.00017, usdPerGigabyte: USD_PER_GB });
  assert.ok(v.minMegabytes < 200, `needs ${v.minMegabytes.toFixed(0)}MB, expected under 200`);
  assert.equal(v.viable, true, "a full gigabyte should be comfortably viable");
});

test("Ethereum L1 cannot settle a 100MB session at all", () => {
  // A single L1 transfer measured at $0.0113 -- more than the data is worth.
  const revenue = USD_PER_GB * (100 / 1024);
  const v = settlementViability({ feeUsd: 0.0113, usdPerGigabyte: USD_PER_GB, gigabytes: 100 / 1024 });
  assert.ok(v.feeUsd > revenue, "the fee exceeds the entire value of the session");
  assert.equal(v.viable, false);
  assert.ok(v.minGigabytes > 10, `needs ${v.minGigabytes.toFixed(1)}GB per settlement`);
});

test("the minimum settlement scales inversely with the fee", () => {
  const cheap = settlementViability({ feeUsd: 0.0001, usdPerGigabyte: USD_PER_GB });
  const dear = settlementViability({ feeUsd: 0.0010, usdPerGigabyte: USD_PER_GB });
  assert.ok(Math.abs(dear.minGigabytes / cheap.minGigabytes - 10) < 1e-9,
    "a 10x fee should require a 10x larger settlement");
});

test("a higher price per gigabyte lowers the minimum settlement", () => {
  const atTenCents = settlementViability({ feeUsd: 0.001, usdPerGigabyte: 0.10 });
  const atTwentyCents = settlementViability({ feeUsd: 0.001, usdPerGigabyte: 0.20 });
  assert.ok(atTwentyCents.minGigabytes < atTenCents.minGigabytes);
});

test("a payment channel amortises two transactions over the whole relationship", () => {
  const c = channelViability({ feeUsd: 0.00017, usdPerGigabyte: USD_PER_GB, gigabytesPerPeriod: 10 });
  assert.equal(c.transactions, 2);
  assert.equal(c.revenue, 1.0);
  assert.ok(c.feeShare < 0.001, `got ${(c.feeShare * 100).toFixed(3)}%`);
});

test("channels beat per-session settlement at every fee level", () => {
  for (const feeUsd of [0.00017, 0.00105, 0.0035, 0.0113]) {
    const perSession = settlementViability({
      feeUsd, usdPerGigabyte: USD_PER_GB, gigabytes: 100 / 1024,
    });
    const channel = channelViability({
      feeUsd, usdPerGigabyte: USD_PER_GB, gigabytesPerPeriod: 10,
    });
    assert.ok(channel.feeShare < perSession.feeShare,
      `at $${feeUsd} a channel (${(channel.feeShare * 100).toFixed(2)}%) should beat ` +
      `per-session (${(perSession.feeShare * 100).toFixed(2)}%)`);
  }
});

test("zero revenue is reported as unviable rather than dividing by zero", () => {
  const v = settlementViability({ feeUsd: 0.001, usdPerGigabyte: 0, gigabytes: 1 });
  assert.equal(v.feeShare, Infinity);
  assert.equal(v.viable, false);
  const c = channelViability({ feeUsd: 0.001, usdPerGigabyte: 0, gigabytesPerPeriod: 10 });
  assert.equal(c.feeShare, Infinity);
});

test("the gas estimate is the expensive case, not the optimistic one", () => {
  // An ERC-20 transfer to an address holding no balance writes a zero slot
  // to non-zero, which costs far more than updating an existing balance.
  // Planning against the cheap case would understate every fee above.
  assert.ok(ERC20_TRANSFER_GAS >= 60000n, "should assume a cold-slot transfer");
});
