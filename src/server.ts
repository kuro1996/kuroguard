/**
 * KuroGuard demo server — a small panel for the hackathon demo (2–5 min).
 *
 *   GET  /            demo panel (public/index.html)
 *   GET  /health      node + escrow balance status
 *   POST /api/quote   {chainId, contract} → free quote
 *   POST /api/guard   {chainId, contract, value?, to?, label?, demo?} → verdict
 *   GET  /api/verdicts/:idempotencyKey → stored verdict + evidence
 *   GET  /api/spend   ledger totals vs caps
 *
 * The server never holds a key other than the burner in .env, and never
 * signs anything except Telegraph escrow payments under the caps.
 */
import { config as loadEnv } from "dotenv";
import express from "express";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

process.chdir(new URL("..", import.meta.url).pathname);
loadEnv({ path: join(process.cwd(), ".env") });

import { SPEND } from "./config.js";
import { KuroGuard, renderVerdict, type TxPlan } from "./guard.js";
import { loadLedger, usdc } from "./ledger.js";
import { TelegraphClient, TESTNET, viemSigner } from "./telegraph.js";

const __dirname = join(fileURLToPath(import.meta.url), "..");
const app = express();
app.use(express.json({ limit: "64kb" }));
app.use(express.static(join(__dirname, "..", "public")));

function makeClient(): TelegraphClient {
  const key = process.env.KUROGUARD_PRIVATE_KEY;
  return new TelegraphClient({
    network: TESTNET,
    signer: key ? viemSigner(key as `0x${string}`) : undefined,
    maxUusdcPerCall: SPEND.maxUusdcPerAsk,
  });
}

function parseTx(body: Record<string, unknown>): TxPlan | { error: string } {
  const chainId = Number(body.chainId);
  const contract = String(body.contract ?? "");
  if (!Number.isInteger(chainId)) return { error: "chainId must be an integer" };
  if (!/^0x[0-9a-fA-F]{40}$/.test(contract)) return { error: "contract must be a 0x address" };
  return {
    chainId,
    chainName: String(body.chainName ?? `chain-${chainId}`),
    contract: contract.toLowerCase(),
    to: typeof body.to === "string" ? body.to : undefined,
    value: typeof body.value === "string" ? body.value : "0",
    label: typeof body.label === "string" ? body.label : undefined,
  };
}

app.get("/health", async (_req, res) => {
  try {
    const client = makeClient();
    const intents = await client.getIntents();
    res.json({ ok: true, node: "devnode.telegraphprotocol.com", intents: intents.count, caps: { perAskUusdc: SPEND.maxUusdcPerAsk, totalUusdc: SPEND.maxUusdcTotal } });
  } catch (e) {
    res.status(502).json({ ok: false, error: (e as Error).message });
  }
});

app.get("/api/spend", (_req, res) => {
  try {
    const ledger = loadLedger();
    res.json({ totalUusdc: ledger.totalUusdc, totalUsdc: usdc(ledger.totalUusdc), remainingUusdc: SPEND.maxUusdcTotal - ledger.totalUusdc, capUusdc: SPEND.maxUusdcTotal, asks: ledger.entries.length });
  } catch (e) {
    // A corrupt ledger fails closed — report it, never silently reset to $0.
    res.status(500).json({ error: (e as Error).message });
  }
});

app.post("/api/quote", async (req, res) => {
  const tx = parseTx(req.body ?? {});
  if ("error" in tx) return res.status(400).json(tx);
  const guard = new KuroGuard({ client: makeClient() });
  res.json(await guard.quote(tx));
});

app.post("/api/guard", async (req, res) => {
  // L1: a paid guard run spends real (test) money. When
  // KUROGUARD_API_TOKEN is set, /api/guard requires it as an
  // `x-kuroguard-token` header; without the token the endpoint refuses
  // even on loopback. (The server also binds 127.0.0.1 only — see below.)
  const token = process.env.KUROGUARD_API_TOKEN;
  if (token && req.header("x-kuroguard-token") !== token) {
    return res.status(401).json({ error: "missing or wrong x-kuroguard-token for /api/guard" });
  }
  const tx = parseTx(req.body ?? {});
  if ("error" in tx) return res.status(400).json(tx);
  const demo = req.body?.demo === "clean" || req.body?.demo === "honeypot" ? (req.body.demo as "clean" | "honeypot") : undefined;
  if (!demo && !process.env.KUROGUARD_PRIVATE_KEY) {
    return res.status(402).json({ error: "burner wallet not funded — pass {\"demo\":\"clean\"} for a $0 simulated run, or fund the burner first (npm run fund)" });
  }
  const guard = new KuroGuard({ client: makeClient(), demo: !!demo, demoScenario: demo });
  try {
    const run = await guard.guard(tx);
    res.json({ ...run, text: renderVerdict(run) });
  } catch (e) {
    res.status(500).json({ error: (e as Error).message });
  }
});

app.get("/api/verdicts/:key", (req, res) => {
  const key = req.params.key;
  if (!/^[0-9a-f]{32}$/.test(key)) return res.status(400).json({ error: "bad key" });
  // Live verdicts live in evidence/verdicts/, demo verdicts in
  // evidence/verdicts/demo/ (separate namespaces — see guard.ts).
  for (const sub of ["", "demo"]) {
    try {
      const run = JSON.parse(readFileSync(join(process.cwd(), "evidence", "verdicts", sub, `${key}.json`), "utf8"));
      return res.json(run);
    } catch {
      /* try the next namespace */
    }
  }
  res.status(404).json({ error: "verdict not found" });
});

const PORT = Number(process.env.PORT ?? 3000);
const HOST = "127.0.0.1"; // loopback only: the panel can trigger paid asks,
// so it must never listen on the LAN (L1).
app.listen(PORT, HOST, () => {
  console.log(`KuroGuard panel on http://${HOST}:${PORT} — POST /api/guard to run the gate`);
  if (!process.env.KUROGUARD_API_TOKEN) {
    console.log("WARNING: KUROGUARD_API_TOKEN is not set — /api/guard accepts loopback requests without a token. Set it for any shared machine.");
  }
});
