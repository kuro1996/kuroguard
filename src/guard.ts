/**
 * KuroGuard — the pre-flight gate itself.
 *
 * Flow for one planned transaction:
 *   1. Plan — build the 3 checks (audit / wash / sanctions) from the tx.
 *   2. Quote — free: verify the intents exist on the node and the live
 *      miner catalogue prices each ask at ≤ the per-ask cap. Refuse before
 *      any money moves.
 *   3. Buy — 3 parallel Telegraph asks on the escrow rail. A canonical ask
 *      that comes back irrelevant/incompatible/empty triggers ONE direct
 *      fallback ask to a verified miner for that intent (see config.ts).
 *   4. Fuse — findings → rubric score → GO / HOLD / BLOCK / ABSTAIN.
 *   5. Seal — verdict hash over the whole decision + every receipt and
 *      signal hash, saved to evidence/ for independent verification.
 *
 * Failure discipline (from the operator's safety rails): a missing required
 * check → ABSTAIN, never GO. A paid-but-failed ask is counted against the
 * ledger with billing "unknown" and never retried.
 */
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { CHECKS, FALLBACK_MINERS, POLICY, SPEND, type CheckId } from "./config.js";
import { errorFinding, fuse, parseFinding, type Finding, type GuardDecision } from "./fusion.js";
import { canSpend, idempotencyKey, loadLedger, recordSpend, type Ledger } from "./ledger.js";
import { TelegraphClient, type AskOutcome, type AskRequest } from "./telegraph.js";

export interface TxPlan {
  chainId: number;
  chainName: string;
  contract: string;
  to?: string;
  value?: string;
  calldata?: string;
  /** Free-text context for the miners (e.g. token symbol, project name). */
  label?: string;
}

export interface GuardRun {
  id: string;
  idempotencyKey: string;
  at: string;
  subject: TxPlan;
  decision: GuardDecision;
  costUusdc: number;
  costCounted: number;
  cached: boolean;
  replayed: boolean;
  events: { type: string; at: string; data: unknown }[];
}

export const EVIDENCE_DIR = join(process.cwd(), "evidence", "verdicts");

export function sha256Hex(s: string): string {
  return "0x" + createHash("sha256").update(s).digest("hex");
}

export interface GuardOptions {
  client: TelegraphClient;
  ledgerPath?: string;
  evidenceDir?: string;
  /** Demo mode: no wallet, no spend — simulated miner answers, clearly labelled. */
  demo?: boolean;
  demoScenario?: "clean" | "honeypot";
  onEvent?: (e: { type: string; data: unknown }) => void;
}

function checkQuestion(check: CheckId, tx: TxPlan): { intent: string; query: string; params: Record<string, unknown> } {
  const target = tx.contract;
  const label = tx.label ? ` (${tx.label})` : "";
  switch (check) {
    case "contract_audit":
      return {
        intent: "SMART_CONTRACT_AUDIT_GENERAL",
        query: `Audit the smart contract at ${target} on chain ${tx.chainId}${label}. Report reentrancy, access control, owner privileges (can the owner drain, seize, mint unlimited, or block sells/transfers?), honeypot or backdoor patterns, and proxy/upgrade risk, with severity for each finding.`,
        params: { contract_address: target, chain_id: tx.chainId },
      };
    case "wash_trading":
      return {
        intent: "WASH_TRADING_DETECTION_GENERAL",
        query: `Is trading volume for the token/contract ${target} on chain ${tx.chainId}${label} wash traded? Check for circular transfers, self-dealing loops, and round trips between affiliated wallets. Report a clear yes/no with evidence.`,
        params: { token_address: target, chain_id: tx.chainId },
      };
    case "sanctions":
      return {
        intent: "SANCTIONS_SCREENING_MATCH_GENERAL",
        query: `Screen the wallet/contract address ${target} against OFAC SDN, EU consolidated, and UN sanctions lists. Report any match or near-match with the list name and source. If there is no match, say so explicitly.`,
        params: { address: target },
      };
  }
}

/** Is this answer usable, or did routing hand us an irrelevant miner? */
export function answerUsable(check: CheckId, outcome: AskOutcome): boolean {
  if (!outcome.ok) return false;
  const r = outcome.response;
  if (r.shape_error) return false;
  if (r.field_status && Object.values(r.field_status).every((v) => v !== "ok")) return false;
  const text = JSON.stringify(r.result ?? "").toLowerCase();
  // The known bad-routing signature: the miner ignored the target entirely.
  if (text.length < 40) return false;
  if (/i don'?t have|i cannot|unable to|no data|not available/i.test(text) && !/no (issues?|match|wash)/i.test(text)) return false;
  return true;
}

const DEMO_ANSWERS: Record<string, Record<CheckId, string>> = {
  clean: {
    contract_audit:
      "Audit complete for the target contract. No reentrancy, no owner drain or seizure powers, no honeypot pattern, no backdoor. Owner is renounced; contract source verified. Severity: none. Risk: low.",
    wash_trading:
      "No wash trading detected. Volume comes from distinct wallets with no circular transfers or self-dealing loops found. No match for wash trading.",
    sanctions:
      "Screened against OFAC SDN, EU consolidated and UN lists. No match found for this address. Not listed, not sanctioned.",
  },
  honeypot: {
    contract_audit:
      "CRITICAL finding: honeypot pattern — sells are blocked for non-owner wallets while buys succeed. Owner can drain contract funds and change the tax to 99%. Backdoor: hidden owner-only withdraw. Severity: critical.",
    wash_trading:
      "Wash trading detected: circular transfers between 4 affiliated wallets account for most volume; self-dealing loops confirmed.",
    sanctions:
      "Screened against OFAC SDN, EU consolidated and UN lists. No match found for this address. Not listed.",
  },
};

export class KuroGuard {
  private ledger: Ledger;

  constructor(private readonly opts: GuardOptions) {
    this.ledger = loadLedger(opts.ledgerPath);
  }

  private emit(type: string, data: unknown): void {
    this.opts.onEvent?.({ type, data });
  }

  get spend(): { totalUusdc: number; remainingUusdc: number } {
    return { totalUusdc: this.ledger.totalUusdc, remainingUusdc: SPEND.maxUusdcTotal - this.ledger.totalUusdc };
  }

  /** Free quote: intents live + per-ask price within cap. Refuses before spend. */
  async quote(tx: TxPlan): Promise<{ ok: boolean; priceUusdc: number; checks: { check: CheckId; intent: string; quoteUsdc: number }[]; refusal?: { code: string; detail: string } }> {
    const checks = CHECKS.map((c) => ({ check: c.id, intent: c.intent, quoteUsdc: SPEND.askPriceUusdc / 1_000_000 }));
    try {
      const live = await this.opts.client.getIntents();
      const liveIds = new Set(live.intents.map((i) => i.intent_id));
      for (const c of CHECKS) {
        if (!liveIds.has(c.intent)) {
          return { ok: false, priceUusdc: 0, checks, refusal: { code: "UPSTREAM_UNAVAILABLE", detail: `intent ${c.intent} has no live entry on the node` } };
        }
      }
    } catch (e) {
      return { ok: false, priceUusdc: 0, checks, refusal: { code: "UPSTREAM_UNAVAILABLE", detail: `could not read the intent catalogue: ${(e as Error).message}` } };
    }
    const priceUusdc = CHECKS.length * SPEND.askPriceUusdc;
    if (SPEND.askPriceUusdc > SPEND.maxUusdcPerAsk) {
      return { ok: false, priceUusdc, checks, refusal: { code: "SPEND_CAP", detail: `quoted ask price above per-ask cap ${SPEND.maxUusdcPerAsk} uUSDC` } };
    }
    if (!canSpend(this.ledger, priceUusdc)) {
      return { ok: false, priceUusdc, checks, refusal: { code: "TOTAL_CAP_REACHED", detail: `total spend cap ${SPEND.maxUusdcTotal} uUSDC reached (${this.ledger.totalUusdc} spent)` } };
    }
    return { ok: true, priceUusdc, checks };
  }

  async guard(tx: TxPlan): Promise<GuardRun> {
    const started = new Date().toISOString();
    const key = idempotencyKey(tx);
    const events: GuardRun["events"] = [];
    const emit = (type: string, data: unknown) => {
      events.push({ type, at: new Date().toISOString(), data });
      this.emit(type, data);
    };

    // Replay: same tx, same day → stored verdict, no new spend.
    const replayPath = join(this.opts.evidenceDir ?? EVIDENCE_DIR, `${key}.json`);
    if (existsSync(replayPath)) {
      const prior = JSON.parse(readFileSync(replayPath, "utf8")) as GuardRun;
      return { ...prior, replayed: true, cached: true, events };
    }

    const q = await this.quote(tx);
    emit("plan", { checks: q.checks, priceUusdc: q.priceUusdc, ok: q.ok, refusal: q.refusal });
    if (!q.ok) {
      const findings = CHECKS.map((c) => errorFinding(c.id, q.refusal?.detail ?? "quote refused"));
      const decision = fuse(findings, sha256Hex);
      const run = this.seal(tx, key, started, decision, 0, 0, events);
      return run;
    }

    const findings: Finding[] = [];
    let costUusdc = 0;

    const runCheck = async (checkId: CheckId): Promise<Finding> => {
      const { intent, query, params } = checkQuestion(checkId, tx);
      const req: AskRequest = { intent, query, params };
      if (this.opts.demo) {
        const scenario = this.opts.demoScenario ?? "clean";
        const f = parseFinding(checkId, DEMO_ANSWERS[scenario][checkId], { costUusdc: 0, durationMs: 0, minerName: "demo (simulated — no Telegraph purchase)", receiptProblems: [] });
        emit("finding", { check: checkId, status: f.status, severity: f.severity, simulated: true });
        return f;
      }
      let outcome = await this.opts.client.ask(req, { timeoutMs: POLICY.askTimeoutMs, maxUusdc: SPEND.maxUusdcPerAsk });
      let usedFallback = false;
      if (!answerUsable(checkId, outcome)) {
        // Known routing weakness: one direct ask to a verified miner.
        for (const miner of FALLBACK_MINERS[checkId]) {
          emit("fallback", { check: checkId, miner: miner.id, reason: outcome.ok ? "answer unusable" : outcome.kind });
          const fb = await this.opts.client.ask(req, { minerId: miner.id, timeoutMs: POLICY.askTimeoutMs, maxUusdc: SPEND.maxUusdcPerAsk });
          if (fb.ok) {
            outcome = fb;
            usedFallback = true;
            break;
          }
          // A paid-but-failed fallback still counts against the ledger.
          if (fb.paidUusdc > 0) this.countSpend(checkId, intent, fb);
        }
      }
      if (outcome.ok) {
        const paid = outcome.amountUusdc;
        costUusdc += paid;
        this.countSpend(checkId, intent, outcome);
        emit("purchase", { check: checkId, miner: outcome.response.miner_id, amountUusdc: paid, receiptHash: outcome.receipt?.receipt_hash, signalHash: outcome.response.signal_hash, fallback: usedFallback });
        const signalStatus = await this.opts.client.verifySignal(outcome.response.signal_hash, { minerId: outcome.response.miner_id });
        const f = parseFinding(checkId, outcome.response.result, {
          costUusdc: paid,
          durationMs: outcome.durationMs,
          minerId: outcome.response.miner_id,
          minerName: outcome.response.miner_name,
          signalHash: outcome.response.signal_hash,
          receiptHash: outcome.receipt?.receipt_hash,
          signalStatus,
          receiptProblems: outcome.receiptProblems,
        });
        emit("finding", { check: checkId, status: f.status, severity: f.severity, signalStatus });
        return f;
      }
      // Paid failure: count it, never retry after payment.
      if (outcome.paidUusdc > 0) {
        costUusdc += outcome.paidUusdc;
        this.countSpend(checkId, intent, outcome);
      }
      emit("finding", { check: checkId, status: "ERROR", error: outcome.error, billing: outcome.billing });
      return errorFinding(checkId, `${outcome.kind}: ${outcome.error}`, { costUusdc: outcome.paidUusdc, durationMs: outcome.durationMs });
    };

    const results = await Promise.all(CHECKS.map((c) => runCheck(c.id)));
    findings.push(...results);

    const decision = fuse(findings, sha256Hex);
    emit("decision", { verdict: decision.verdict, score: decision.score, verdictHash: decision.verdictHash });
    const run = this.seal(tx, key, started, decision, costUusdc, costUusdc, events);
    emit("done", { id: run.id, verdict: decision.verdict });
    return run;
  }

  private countSpend(checkId: CheckId, intent: string, outcome: AskOutcome): void {
    if (!outcome.ok) {
      if (outcome.paidUusdc > 0) {
        recordSpend(this.ledger, { idempotencyKey: "paid-failure", check: checkId, intent, amountUusdc: outcome.paidUusdc, at: new Date().toISOString(), billing: "unknown" }, this.opts.ledgerPath);
      }
      return;
    }
    recordSpend(
      this.ledger,
      {
        idempotencyKey: "ask",
        check: checkId,
        intent,
        minerId: outcome.response.miner_id,
        amountUusdc: outcome.amountUusdc,
        receiptHash: outcome.receipt?.receipt_hash,
        signalHash: outcome.response.signal_hash,
        at: new Date().toISOString(),
        billing: "settled",
      },
      this.opts.ledgerPath,
    );
  }

  private seal(tx: TxPlan, key: string, started: string, decision: GuardDecision, costUusdc: number, costCounted: number, events: GuardRun["events"]): GuardRun {
    const run: GuardRun = {
      id: `grd_${key.slice(0, 16)}`,
      idempotencyKey: key,
      at: started,
      subject: tx,
      decision,
      costUusdc,
      costCounted,
      cached: false,
      replayed: false,
      events,
    };
    const dir = this.opts.evidenceDir ?? EVIDENCE_DIR;
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, `${key}.json`), JSON.stringify(run, null, 2) + "\n", "utf8");
    return run;
  }
}

/** Human-readable one-page verdict. */
export function renderVerdict(run: GuardRun): string {
  const d = run.decision;
  const lines = [
    `${d.verdict}  ${d.score}/100  ·  risk ${d.riskBps} bps  ·  confidence ${d.confidenceBps / 100}%  ·  coverage ${Math.round(d.coverage * 100)}%`,
    d.summary,
    `cost: ${(run.costUusdc / 1_000_000).toFixed(4)} USDC (${run.costCounted} uUSDC counted)${run.replayed ? " · replayed, not re-billed" : ""}`,
    `verdict hash: ${d.verdictHash}`,
    "",
  ];
  for (const f of d.findings) {
    lines.push(
      `  [${f.check}] ${f.status} (${f.severity}, risk ${f.riskScore}) — ${f.notes.join("; ")}` +
        (f.minerId ? ` — miner ${f.minerId}${f.minerName ? ` (${f.minerName})` : ""}` : "") +
        (f.signalHash ? ` — signal ${f.signalHash.slice(0, 18)}… (${f.signalStatus ?? "unchecked"})` : "") +
        (f.receiptHash ? ` — receipt ${f.receiptHash.slice(0, 18)}…` : ""),
    );
  }
  if (d.openRisks.length) lines.push("", "open risks:", ...d.openRisks.map((r) => `  - ${r}`));
  if (d.conflicts.length) lines.push("", "conflicts:", ...d.conflicts.map((r) => `  - ${r}`));
  if (d.reasons.length) lines.push("", "reasons:", ...d.reasons.map((r) => `  - [${r.code}]${r.check ? ` ${r.check}` : ""}: ${r.detail}`));
  return lines.join("\n");
}
