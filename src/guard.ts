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
import { canSpend, idempotencyKey, loadLedger, recordSpend, spendEntryKey, type Ledger } from "./ledger.js";
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
  /** True when every miner answer in this run was simulated ($0 demo). */
  simulated: boolean;
  /** False for runs that must never be replayed (e.g. a quote failure). */
  cacheable: boolean;
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

  /**
   * Evidence namespace. Demo ($0, simulated) and live (paid) verdicts live
   * in SEPARATE directories — demo verdicts are sealed under
   * `evidence/verdicts/demo/`, live verdicts under `evidence/verdicts/`.
   * A replay only ever reads its own namespace, and only a run sealed by
   * the same mode (matched on the stored `simulated` flag) may replay:
   * a demo GO can never green-light a live signature, and a legacy file
   * without a `simulated` flag replays for nobody.
   */
  private evidenceDir(): string {
    const base = this.opts.evidenceDir ?? EVIDENCE_DIR;
    return this.opts.demo ? join(base, "demo") : base;
  }

  /** Free quote: intents live + per-ask price within cap. Refuses before spend.
   * Prices are ASSUMED ($0.01/ask from the SPEND.askPriceUusdc constant) —
   * the node publishes no price catalogue, so the quote is labelled as an
   * assumption, not a read of the live challenge. The budget covers the
   * canonical asks PLUS one fallback ask per check (M1): the worst case a
   * run can cost is `maxPriceUusdc`, and the total cap is checked against
   * that worst case, not the happy path. */
  async quote(tx: TxPlan): Promise<{
    ok: boolean;
    priceUusdc: number;
    /** Worst-case run cost: canonical asks + one fallback per check. */
    maxPriceUusdc: number;
    fallbackBudgetUusdc: number;
    /** The quote is an assumption from a constant, not a live price read. */
    priceAssumption: string;
    checks: { check: CheckId; intent: string; quoteUsdc: number }[];
    refusal?: { code: string; detail: string };
  }> {
    const checks = CHECKS.map((c) => ({ check: c.id, intent: c.intent, quoteUsdc: SPEND.askPriceUusdc / 1_000_000 }));
    const priceAssumption = `assumed $${(SPEND.askPriceUusdc / 1_000_000).toFixed(2)}/ask from the SPEND.askPriceUusdc constant — not read from a live 402 challenge or price catalogue; the real per-ask charge is validated against the per-ask cap at signing time`;
    const priceUusdc = CHECKS.length * SPEND.askPriceUusdc;
    const fallbackBudgetUusdc = CHECKS.length * SPEND.askPriceUusdc;
    const maxPriceUusdc = priceUusdc + fallbackBudgetUusdc;
    try {
      const live = await this.opts.client.getIntents();
      const liveIds = new Set(live.intents.map((i) => i.intent_id));
      for (const c of CHECKS) {
        if (!liveIds.has(c.intent)) {
          return { ok: false, priceUusdc, maxPriceUusdc, fallbackBudgetUusdc, priceAssumption, checks, refusal: { code: "UPSTREAM_UNAVAILABLE", detail: `intent ${c.intent} has no live entry on the node` } };
        }
      }
    } catch (e) {
      return { ok: false, priceUusdc, maxPriceUusdc, fallbackBudgetUusdc, priceAssumption, checks, refusal: { code: "UPSTREAM_UNAVAILABLE", detail: `could not read the intent catalogue: ${(e as Error).message}` } };
    }
    if (SPEND.askPriceUusdc > SPEND.maxUusdcPerAsk) {
      return { ok: false, priceUusdc, maxPriceUusdc, fallbackBudgetUusdc, priceAssumption, checks, refusal: { code: "SPEND_CAP", detail: `quoted ask price above per-ask cap ${SPEND.maxUusdcPerAsk} uUSDC` } };
    }
    if (!canSpend(this.ledger, maxPriceUusdc)) {
      return {
        ok: false,
        priceUusdc,
        maxPriceUusdc,
        fallbackBudgetUusdc,
        priceAssumption,
        checks,
        refusal: { code: "TOTAL_CAP_REACHED", detail: `worst-case run cost ${maxPriceUusdc} uUSDC does not fit the remaining total cap (${SPEND.maxUusdcTotal - this.ledger.totalUusdc} uUSDC left of ${SPEND.maxUusdcTotal})` },
      };
    }
    return { ok: true, priceUusdc, maxPriceUusdc, fallbackBudgetUusdc, priceAssumption, checks };
  }

  async guard(tx: TxPlan): Promise<GuardRun> {
    const started = new Date().toISOString();
    const key = idempotencyKey(tx);
    const events: GuardRun["events"] = [];
    const emit = (type: string, data: unknown) => {
      events.push({ type, at: new Date().toISOString(), data });
      this.emit(type, data);
    };

    // Replay: same tx, same day, SAME MODE → stored verdict, no new spend.
    // A demo run replays only demo verdicts, a live run only live ones
    // (separate directories + the stored `simulated` flag must match).
    const replayPath = join(this.evidenceDir(), `${key}.json`);
    if (existsSync(replayPath)) {
      try {
        const prior = JSON.parse(readFileSync(replayPath, "utf8")) as GuardRun;
        if (prior.cacheable !== false && prior.simulated === !!this.opts.demo && prior.idempotencyKey === key) {
          // Return the ORIGINAL events, not an empty list: a replayed
          // verdict must stay auditable (L7).
          return { ...prior, replayed: true, cached: true, events: prior.events ?? [] };
        }
      } catch {
        // A corrupt stored verdict is never trusted — fall through and
        // re-run the gate instead of replaying garbage.
      }
    }

    const q = await this.quote(tx);
    emit("plan", { checks: q.checks, priceUusdc: q.priceUusdc, maxPriceUusdc: q.maxPriceUusdc, ok: q.ok, refusal: q.refusal });
    if (!q.ok) {
      // Quote failure → ABSTAIN, but NEVER sealed/cached: the refusal may
      // be transient (upstream down, cap temporarily reached) and caching
      // it would block a retry for the rest of the day. The run is
      // returned unsealed (cacheable: false) and costs $0.
      const findings = CHECKS.map((c) => errorFinding(c.id, q.refusal?.detail ?? "quote refused"));
      const decision = fuse(findings, sha256Hex);
      const run: GuardRun = {
        id: `grd_${key.slice(0, 16)}`,
        idempotencyKey: key,
        at: started,
        subject: tx,
        decision,
        costUusdc: 0,
        costCounted: 0,
        cached: false,
        replayed: false,
        simulated: !!this.opts.demo,
        cacheable: false,
        events,
      };
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

      // Count a paid outcome against the ledger exactly once, however it
      // ends up being used (or discarded as unusable — the money is gone
      // either way). recordSpend enforces the total cap at record time.
      const countOutcome = (o: AskOutcome): void => {
        if (o.ok) {
          costUusdc += o.amountUusdc;
          this.countSpend(checkId, intent, o);
        } else if (o.paidUusdc > 0) {
          costUusdc += o.paidUusdc;
          this.countSpend(checkId, intent, o);
        }
      };

      let outcome = await this.opts.client.ask(req, { timeoutMs: POLICY.askTimeoutMs, maxUusdc: SPEND.maxUusdcPerAsk });
      let usedFallback = false;
      if (!answerUsable(checkId, outcome)) {
        // Known routing weakness: AT MOST ONE direct ask, to the FIRST
        // verified miner for this intent (the docs promise "retry ONCE").
        // Trying all three fallbacks could bill ~$0.20/check against a
        // quoted $0.03/run. The fallback answer must ALSO be usable —
        // a paid but irrelevant answer is not fused.
        const miner = FALLBACK_MINERS[checkId][0];
        if (miner) {
          emit("fallback", { check: checkId, miner: miner.id, reason: outcome.ok ? "answer unusable" : outcome.kind });
          const fb = await this.opts.client.ask(req, { minerId: miner.id, timeoutMs: POLICY.askTimeoutMs, maxUusdc: SPEND.maxUusdcPerAsk });
          if (fb.ok && answerUsable(checkId, fb)) {
            countOutcome(outcome); // discarded canonical ask was still paid
            outcome = fb;
            usedFallback = true;
          } else {
            if (fb.ok || fb.paidUusdc > 0) countOutcome(fb);
            if (outcome.ok) {
              // Canonical was paid but unusable, and the one fallback did
              // not produce a usable answer either: fuse nothing.
              countOutcome(outcome);
              emit("finding", { check: checkId, status: "ERROR", error: "canonical + fallback answers unusable", billing: "settled" });
              return errorFinding(checkId, "canonical + fallback answers unusable", { costUusdc: outcome.amountUusdc, durationMs: outcome.durationMs });
            }
            // Canonical already failed: fall through to the paid-failure
            // path below, which counts it exactly once.
          }
        } else if (outcome.ok) {
          countOutcome(outcome);
          emit("finding", { check: checkId, status: "ERROR", error: "answer unusable, no fallback miner", billing: "settled" });
          return errorFinding(checkId, "answer unusable, no fallback miner configured", { costUusdc: outcome.amountUusdc, durationMs: outcome.durationMs });
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
    // "done" is emitted BEFORE sealing so the sealed verdict carries the
    // complete event log — a replay must return the original events (L7).
    emit("done", { id: `grd_${key.slice(0, 16)}`, verdict: decision.verdict });
    const run = this.seal(tx, key, started, decision, costUusdc, costUusdc, events);
    return run;
  }

  private countSpend(checkId: CheckId, intent: string, outcome: AskOutcome): void {
    const at = new Date().toISOString();
    if (!outcome.ok) {
      if (outcome.paidUusdc > 0) {
        recordSpend(
          this.ledger,
          {
            idempotencyKey: spendEntryKey({ check: checkId, intent, amountUusdc: outcome.paidUusdc, at }),
            check: checkId,
            intent,
            amountUusdc: outcome.paidUusdc,
            at,
            billing: "unknown",
          },
          this.opts.ledgerPath,
        );
      }
      return;
    }
    recordSpend(
      this.ledger,
      {
        idempotencyKey: spendEntryKey({
          check: checkId,
          intent,
          amountUusdc: outcome.amountUusdc,
          receiptHash: outcome.receipt?.receipt_hash,
          signalHash: outcome.response.signal_hash,
          at,
        }),
        check: checkId,
        intent,
        minerId: outcome.response.miner_id,
        amountUusdc: outcome.amountUusdc,
        receiptHash: outcome.receipt?.receipt_hash,
        signalHash: outcome.response.signal_hash,
        at,
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
      simulated: !!this.opts.demo,
      cacheable: true,
      events,
    };
    const dir = this.evidenceDir();
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, `${key}.json`), JSON.stringify(run, null, 2) + "\n", "utf8");
    return run;
  }
}

/** Human-readable one-page verdict. Simulated (demo) and replayed runs are
 * labelled on the FIRST line — a demo verdict must never be mistaken for
 * a live purchase, and a replay must never look like fresh evidence. */
export function renderVerdict(run: GuardRun): string {
  const d = run.decision;
  const banners: string[] = [];
  if (run.simulated) banners.push("SIMULATED — demo answers, $0 spent, no Telegraph purchase");
  if (run.replayed) banners.push("REPLAYED — stored verdict, not re-billed, no new purchase");
  const lines = [
    ...(banners.length ? [`[${banners.join(" · ")}]`] : []),
    `${d.verdict}  ${d.score}/100  ·  risk ${d.riskBps} bps  ·  confidence ${d.confidenceBps / 100}%  ·  coverage ${Math.round(d.coverage * 100)}%`,
    d.summary,
    `cost: ${(run.costUusdc / 1_000_000).toFixed(4)} USDC (${run.costCounted} uUSDC counted)${run.replayed ? " · replayed, not re-billed" : ""}${run.simulated ? " · simulated" : ""}`,
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
