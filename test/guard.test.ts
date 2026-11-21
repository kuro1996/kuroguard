import { describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { KuroGuard } from "../src/guard.js";
import { TelegraphClient, TESTNET, type MessageSigner } from "../src/telegraph.js";
import { loadLedger } from "../src/ledger.js";
import { SPEND } from "../src/config.js";

const DIAMOND = "0x3624EB012B5E998BB57B6bE6C9Cfc9c4bc5eb99b";
const USDC = "0xcc194e1a843B658526D0D5C431f670028582Ae17";

const fakeSigner: MessageSigner = {
  address: "0x1111111111111111111111111111111111111111",
  signMessage: async (m: string) => `signed:${m.slice(0, 12)}`,
};

const TEMPLATE = [
  "Telegraph Escrow Payment",
  "",
  "Wallet: {from}",
  `Pay To: ${DIAMOND}`,
  "Network: eip155:11155111",
  "Amount: 10000 uUSDC",
  "Resource: /v1/ask",
  "Nonce: {nonce}",
  "Valid After: {validAfter}",
  "Valid Before: {validBefore}",
].join("\n");

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function intentsResponse(): Response {
  return jsonResponse({
    count: 3,
    intents: [
      { intent_id: "SMART_CONTRACT_AUDIT_GENERAL", miner_count: 19, canonical: true },
      { intent_id: "WASH_TRADING_DETECTION_GENERAL", miner_count: 17, canonical: true },
      { intent_id: "SANCTIONS_SCREENING_MATCH_GENERAL", miner_count: 29, canonical: true },
    ],
  });
}

function stubFetch(): typeof fetch {
  return (async (_url: string | URL | Request) => intentsResponse()) as unknown as typeof fetch;
}

/** A fetch mock that always fails — the upstream is down. */
function failingFetch(): typeof fetch {
  return (async () => new Response(JSON.stringify({ error: "down" }), { status: 500, headers: { "content-type": "application/json" } })) as unknown as typeof fetch;
}

const CLEAN_BY_INTENT: Record<string, string> = {
  SMART_CONTRACT_AUDIT_GENERAL: "Audit complete. No issues found, no vulnerabilities, contract is safe. Severity: none.",
  WASH_TRADING_DETECTION_GENERAL: "No wash trading detected. Volume comes from distinct wallets with no circular transfers. No match for wash trading.",
  SANCTIONS_SCREENING_MATCH_GENERAL: "Screened against OFAC SDN, EU consolidated and UN lists. No match found for this address. Not listed.",
};

/**
 * A mock Telegraph node: canonical asks return a short, unusable answer
 * ("ok"); ONE direct fallback ask per check returns a clean, usable one.
 * Every paid answer carries a matching receipt + signal hash.
 */
function mockNodeFetch(): { fetch: typeof fetch; calls: { method: string; path: string; paid: boolean }[] } {
  const calls: { method: string; path: string; paid: boolean }[] = [];
  const fetchFn = (async (url: string | URL | Request, init?: RequestInit) => {
    const u = new URL(String(url));
    const path = u.pathname;
    const headers = new Headers(init?.headers as Record<string, string> | undefined);
    const paid = !!headers.get("X-PAYMENT");
    calls.push({ method: init?.method ?? "GET", path, paid });
    if (path === "/engine/v1/intents") return intentsResponse();
    if (path.startsWith("/engine/v1/signal/")) return jsonResponse({});
    if (path === "/engine/v1/ask" || path.startsWith("/engine/v1/ask/")) {
      const minerId = path === "/engine/v1/ask" ? undefined : decodeURIComponent(path.slice("/engine/v1/ask/".length));
      const resource = minerId ? `/v1/ask/${minerId}` : "/v1/ask";
      if (!paid) {
        const tpl = TEMPLATE.replace("Resource: /v1/ask", `Resource: ${resource}`);
        return jsonResponse(
          { error: "payment required", accepts: [{ scheme: "escrow", network: "eip155:11155111", payTo: DIAMOND, amount: "10000", asset: USDC, extra: { message: tpl, resource } }] },
          402,
        );
      }
      const reqBody = JSON.parse(typeof init?.body === "string" ? init.body : "{}") as { intent?: string };
      const result = minerId ? (CLEAN_BY_INTENT[reqBody.intent ?? ""] ?? "ok") : "ok";
      const receipt = { receipt_hash: "0x" + "ab".repeat(32), rail: "escrow", payer: fakeSigner.address, miner: minerId ?? "200001", amount_uusdc: "10000", timestamp: 1 };
      return new Response(JSON.stringify({ miner_id: minerId ?? "200001", miner_name: "Mock Miner", result, signal_hash: "0x" + "cd".repeat(32) }), {
        status: 200,
        headers: { "content-type": "application/json", "x-payment-response": Buffer.from(JSON.stringify(receipt)).toString("base64") },
      });
    }
    return new Response("not found", { status: 404 });
  }) as unknown as typeof fetch;
  return { fetch: fetchFn, calls };
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

  it("demo replays keep the original events (L7) and stay labelled simulated", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kuroguard-demo-"));
    const guard = demoGuard("clean", dir);
    const tx = { chainId: 8453, chainName: "base", contract: "0x4200000000000000000000000000000000000006", value: "0" };
    const first = await guard.guard(tx);
    const second = await guard.guard(tx);
    expect(second.replayed).toBe(true);
    expect(second.simulated).toBe(true);
    expect(second.events.length).toBeGreaterThan(0);
    expect(second.events).toEqual(first.events);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("KuroGuard demo/live namespaces (H1) + quote cache (M4)", () => {
  const tx = { chainId: 8453, chainName: "base", contract: "0x4200000000000000000000000000000000000006", value: "0", label: "WETH" };

  it("H1: a demo GO is never replayed by a live run of the same contract", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kuroguard-h1-"));
    const demo = demoGuard("clean", dir);
    const d = await demo.guard(tx);
    expect(d.decision.verdict).toBe("GO");
    expect(d.simulated).toBe(true);
    // Live run, same evidence dir, same tx — upstream is down here, so it
    // cannot buy checks; the point is it must NOT replay the demo GO.
    const liveClient = new TelegraphClient({ network: TESTNET, signer: fakeSigner, maxUusdcPerCall: SPEND.maxUusdcPerAsk, fetch: failingFetch() });
    const live = new KuroGuard({ client: liveClient, ledgerPath: join(dir, "ledger.json"), evidenceDir: join(dir, "verdicts") });
    const run = await live.guard(tx);
    expect(run.replayed).toBe(false);
    expect(run.simulated).toBe(false);
    expect(run.decision.verdict).toBe("ABSTAIN");
    rmSync(dir, { recursive: true, force: true });
  });

  it("M4: a quote-failure ABSTAIN is not cached — the next run retries", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kuroguard-m4-"));
    const client = new TelegraphClient({ network: TESTNET, signer: fakeSigner, maxUusdcPerCall: SPEND.maxUusdcPerAsk, fetch: failingFetch() });
    const guard = new KuroGuard({ client, ledgerPath: join(dir, "ledger.json"), evidenceDir: join(dir, "verdicts") });
    const first = await guard.guard(tx);
    expect(first.decision.verdict).toBe("ABSTAIN");
    expect(first.replayed).toBe(false);
    expect(first.cacheable).toBe(false);
    const second = await guard.guard(tx);
    expect(second.replayed).toBe(false);
    expect(second.cacheable).toBe(false);
    // Nothing was sealed to disk.
    expect(existsSync(join(dir, "verdicts"))).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("KuroGuard live fallback (M1, mock node)", () => {
  it("uses at most ONE fallback per check, checks usability, and bills canonical + fallback", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kuroguard-m1-"));
    const node = mockNodeFetch();
    const client = new TelegraphClient({ network: TESTNET, signer: fakeSigner, maxUusdcPerCall: SPEND.maxUusdcPerAsk, fetch: node.fetch });
    const guard = new KuroGuard({ client, ledgerPath: join(dir, "ledger.json"), evidenceDir: join(dir, "verdicts") });
    const run = await guard.guard({ chainId: 8453, chainName: "base", contract: "0x4200000000000000000000000000000000000006", value: "0", label: "WETH" });
    expect(run.decision.verdict).toBe("GO");
    // 3 checks × (canonical $0.01 unusable + fallback $0.01 usable) = $0.06.
    expect(run.costUusdc).toBe(60_000);
    expect(loadLedger(join(dir, "ledger.json")).totalUusdc).toBe(60_000);
    // Exactly one PAID fallback ask per check (3 total), to the FIRST
    // fallback miner of each intent — never the 2nd/3rd fallback.
    const fallbackCalls = node.calls.filter((c) => c.path.startsWith("/engine/v1/ask/"));
    expect(fallbackCalls.filter((c) => c.paid)).toHaveLength(3);
    expect(fallbackCalls.map((c) => c.path).sort()).toEqual(["/engine/v1/ask/200001", "/engine/v1/ask/200001", "/engine/v1/ask/73181", "/engine/v1/ask/73181", "/engine/v1/ask/78004", "/engine/v1/ask/78004"]);
    expect(node.calls.some((c) => c.path.includes("200002") || c.path.includes("501") || c.path.includes("7378"))).toBe(false);
    expect(run.replayed).toBe(false);
    expect(run.simulated).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("quote budgets the worst case: canonical + one fallback per check (M1/L2)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kuroguard-quote-"));
    const client = new TelegraphClient({ network: TESTNET, signer: fakeSigner, maxUusdcPerCall: SPEND.maxUusdcPerAsk, fetch: stubFetch() });
    const guard = new KuroGuard({ client, ledgerPath: join(dir, "ledger.json"), evidenceDir: join(dir, "verdicts") });
    const q = await guard.quote({ chainId: 8453, chainName: "base", contract: "0x4200000000000000000000000000000000000006", value: "0" });
    expect(q.ok).toBe(true);
    expect(q.priceUusdc).toBe(30_000);
    expect(q.fallbackBudgetUusdc).toBe(30_000);
    expect(q.maxPriceUusdc).toBe(60_000);
    expect(q.priceAssumption).toMatch(/assumed/);
    rmSync(dir, { recursive: true, force: true });
  });
});
