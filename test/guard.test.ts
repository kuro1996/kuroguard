import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { KuroGuard } from "../src/guard.js";
import { TelegraphClient, TESTNET } from "../src/telegraph.js";
import { SPEND } from "../src/config.js";

function stubFetch(): typeof fetch {
  return (async (_url: string | URL | Request) => {
    const body = JSON.stringify({
      count: 3,
      intents: [
        { intent_id: "SMART_CONTRACT_AUDIT_GENERAL", miner_count: 19, canonical: true },
        { intent_id: "WASH_TRADING_DETECTION_GENERAL", miner_count: 17, canonical: true },
        { intent_id: "SANCTIONS_SCREENING_MATCH_GENERAL", miner_count: 29, canonical: true },
      ],
    });
    return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
}

function demoGuard(scenario: "clean" | "honeypot", dir: string): KuroGuard {
  const client = new TelegraphClient({ network: TESTNET, maxUusdcPerCall: SPEND.maxUusdcPerAsk, fetch: stubFetch() });
  return new KuroGuard({ client, demo: true, demoScenario: scenario, ledgerPath: join(dir, "ledger.json"), evidenceDir: join(dir, "verdicts") });
}

describe("KuroGuard demo mode ($0, no wallet)", () => {
  it("GO on a clean contract", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kuroguard-demo-"));
    const guard = demoGuard("clean", dir);
    const run = await guard.guard({ chainId: 8453, chainName: "base", contract: "0x4200000000000000000000000000000000000006", value: "0", label: "WETH" });
    expect(run.decision.verdict).toBe("GO");
    expect(run.costUusdc).toBe(0);
    expect(run.decision.findings).toHaveLength(3);
    expect(run.decision.verdictHash).toMatch(/^0x[0-9a-f]{64}$/);
    rmSync(dir, { recursive: true, force: true });
  });

  it("BLOCK on the honeypot fixture", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kuroguard-demo-"));
    const guard = demoGuard("honeypot", dir);
    const run = await guard.guard({ chainId: 56, chainName: "bsc", contract: "0x9c6a008f73a1d1941f4763b88c6ee8c8e4ef8b0a", value: "0", label: "Backdoor Pass" });
    expect(run.decision.verdict).toBe("BLOCK");
    expect(run.decision.reasons.some((r) => r.code === "BLOCKER")).toBe(true);
    rmSync(dir, { recursive: true, force: true });
  });

  it("replays the same tx without re-spending", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kuroguard-demo-"));
    const guard = demoGuard("clean", dir);
    const tx = { chainId: 8453, chainName: "base", contract: "0x4200000000000000000000000000000000000006", value: "0" };
    const first = await guard.guard(tx);
    expect(first.replayed).toBe(false);
    const second = await guard.guard(tx);
    expect(second.replayed).toBe(true);
    expect(second.decision.verdictHash).toBe(first.decision.verdictHash);
    rmSync(dir, { recursive: true, force: true });
  });
});
