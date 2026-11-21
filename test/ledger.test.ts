import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canSpend, idempotencyKey, loadLedger, recordSpend } from "../src/ledger.js";
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
});
