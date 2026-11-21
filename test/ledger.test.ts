import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canSpend, idempotencyKey, LedgerCorruptError, loadLedger, recordSpend, SpendCapError, spendEntryKey } from "../src/ledger.js";
import { SPEND } from "../src/config.js";

describe("ledger", () => {
  it("enforces the $1 total cap", () => {
    const ledger = { totalUusdc: SPEND.maxUusdcTotal - 10_000, entries: [] };
    expect(canSpend(ledger, 10_000)).toBe(true);
    expect(canSpend(ledger, 10_001)).toBe(false);
  });
  it("records spend and persists it", () => {
    const dir = mkdtempSync(join(tmpdir(), "kuroguard-ledger-"));
    const path = join(dir, "ledger.json");
    const ledger = loadLedger(path);
    expect(ledger.totalUusdc).toBe(0);
    recordSpend(ledger, { idempotencyKey: "k", check: "sanctions", intent: "SANCTIONS_SCREENING_MATCH_GENERAL", amountUusdc: 10_000, at: new Date().toISOString(), billing: "settled" }, path);
    expect(loadLedger(path).totalUusdc).toBe(10_000);
    rmSync(dir, { recursive: true, force: true });
  });
  it("idempotency keys are deterministic per tx per day, and differ per contract", () => {
    const a = idempotencyKey({ chainId: 56, contract: "0x4200000000000000000000000000000000000006" });
    const b = idempotencyKey({ chainId: 56, contract: "0x4200000000000000000000000000000000000006" });
    const c = idempotencyKey({ chainId: 56, contract: "0x9c6a008f73a1d1941f4763b88c6ee8c8e4ef8b0a" });
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a).toMatch(/^[0-9a-f]{32}$/);
  });
  it("M3: keys differ per calldata (mint vs transfer to the same contract)", () => {
    const base = { chainId: 56, contract: "0x4200000000000000000000000000000000000006", value: "0" };
    const mint = idempotencyKey({ ...base, calldata: "0x40c10f19" + "00".repeat(32) });
    const transfer = idempotencyKey({ ...base, calldata: "0xa9059cbb" + "00".repeat(32) });
    const noCalldata = idempotencyKey(base);
    expect(mint).not.toBe(transfer);
    expect(mint).not.toBe(noCalldata);
    expect(transfer).not.toBe(noCalldata);
    expect(idempotencyKey({ ...base, calldata: "0x40c10f19" + "00".repeat(32) })).toBe(mint);
  });
  it("M3: keys differ per label (the label changes the miners' question)", () => {
    const a = idempotencyKey({ chainId: 56, contract: "0x4200000000000000000000000000000000000006", label: "WETH" });
    const b = idempotencyKey({ chainId: 56, contract: "0x4200000000000000000000000000000000000006", label: "Honeypot?" });
    expect(a).not.toBe(b);
  });
  it("M6: a corrupt ledger fails closed instead of silently resetting to $0", () => {
    const dir = mkdtempSync(join(tmpdir(), "kuroguard-ledger-"));
    const path = join(dir, "ledger.json");
    writeFileSync(path, "{not json,,,", "utf8");
    expect(() => loadLedger(path)).toThrow(LedgerCorruptError);
    writeFileSync(path, JSON.stringify({ totalUusdc: "lots", entries: [] }), "utf8");
    expect(() => loadLedger(path)).toThrow(LedgerCorruptError);
    writeFileSync(path, JSON.stringify({ totalUusdc: 0, entries: "nope" }), "utf8");
    expect(() => loadLedger(path)).toThrow(LedgerCorruptError);
    rmSync(dir, { recursive: true, force: true });
  });
  it("M7: recordSpend refuses a spend that would exceed the total cap, ledger untouched", () => {
    const dir = mkdtempSync(join(tmpdir(), "kuroguard-ledger-"));
    const path = join(dir, "ledger.json");
    const ledger = { totalUusdc: SPEND.maxUusdcTotal - 5_000, entries: [] };
    expect(() =>
      recordSpend(ledger, { idempotencyKey: "k", check: "sanctions", intent: "SANCTIONS_SCREENING_MATCH_GENERAL", amountUusdc: 10_000, at: new Date().toISOString(), billing: "settled" }, path),
    ).toThrow(SpendCapError);
    expect(ledger.totalUusdc).toBe(SPEND.maxUusdcTotal - 5_000);
    expect(ledger.entries).toHaveLength(0);
    rmSync(dir, { recursive: true, force: true });
  });
  it("L3: spend entry keys are unique per ask", () => {
    const at = new Date().toISOString();
    const k1 = spendEntryKey({ check: "sanctions", intent: "SANCTIONS_SCREENING_MATCH_GENERAL", amountUusdc: 10_000, receiptHash: "0x" + "aa".repeat(32), at });
    const k2 = spendEntryKey({ check: "sanctions", intent: "SANCTIONS_SCREENING_MATCH_GENERAL", amountUusdc: 10_000, receiptHash: "0x" + "bb".repeat(32), at });
    const k3 = spendEntryKey({ check: "contract_audit", intent: "SMART_CONTRACT_AUDIT_GENERAL", amountUusdc: 10_000, receiptHash: "0x" + "aa".repeat(32), at });
    expect(new Set([k1, k2, k3]).size).toBe(3);
  });
});
