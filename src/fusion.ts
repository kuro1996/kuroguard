/**
 * Fusion: turns three paid Telegraph answers into one pre-flight verdict.
 *
 * Each answer is parsed into a Finding (status + severity + notes). The
 * published rubric then scores 0–100 and decides:
 *
 *   GO    — score ≥ 80, every required check answered, no blocker.
 *   HOLD  — score 50–79, or mixed/conflicting evidence: human reviews.
 *   BLOCK — score < 50, or any blocker fired (sanctions match, honeypot /
 *           drain / seizure pattern, critical audit finding).
 *   ABSTAIN — a required check is missing/errored. Fail closed: a missing
 *           check is NEVER treated as "safe". Charged at upstream cost only.
 *
 * Severity keywords are a heuristic parser over free-text miner answers
 * (the audit intent has no response format of its own — see config.ts).
 * Structured fields (field_status, explicit severity/risk fields) win over
 * keywords whenever the miner returns them.
 */

import { createHash } from "node:crypto";
import { CHECKS, POLICY, type CheckId } from "./config.js";

export type FindingStatus = "PASS" | "WARN" | "FAIL" | "UNKNOWN" | "ERROR";
export type Severity = "none" | "low" | "medium" | "high" | "critical";

export interface Finding {
  check: CheckId;
  status: FindingStatus;
  severity: Severity;
  /** 0–100 risk contribution of this check alone (100 = totally unsafe). */
  riskScore: number;
  notes: string[];
  minerId?: string;
  minerName?: string;
  signalHash?: string;
  receiptHash?: string;
  signalStatus?: "verified" | "missing" | "mismatch" | "unchecked";
  receiptProblems: string[];
  costUusdc: number;
  durationMs: number;
}

export interface GuardDecision {
  verdict: "GO" | "HOLD" | "BLOCK" | "ABSTAIN";
  /** Fused 0–100 safety score (100 = clean). */
  score: number;
  riskBps: number;
  confidenceBps: number;
  coverage: number;
  summary: string;
  reasons: { code: string; check?: CheckId; detail: string }[];
  openRisks: string[];
  conflicts: string[];
  findings: Finding[];
  verdictHash: string;
}

const BLOCKER_PATTERNS: { re: RegExp; detail: string }[] = [
  { re: /honeypot/i, detail: "honeypot pattern reported" },
  { re: /drain/i, detail: "drain pattern reported" },
  { re: /owner can (seize|take|steal|withdraw all|mint unlimited)/i, detail: "owner seizure / unlimited-mint power reported" },
  { re: /seiz(e|ure)|ambil\(\)|rug\s?pull/i, detail: "seizure / rug-pull pattern reported" },
  { re: /sanction(s|ed)? (match|listed|hit)|match (found|identified|on)|appears on|is (listed|sanctioned)/i, detail: "sanctions-list match reported" },
  { re: /critical (vulnerabilit|severity|finding)/i, detail: "critical-severity finding reported" },
  { re: /reentrancy/i, detail: "reentrancy reported" },
  { re: /backdoor/i, detail: "backdoor reported" },
  { re: /cannot (sell|transfer)|sell (blocked|disabled|restricted)|transfer (blocked|locked|disabled)/i, detail: "sell/transfer blocked — no exit" },
  { re: /wash trading (detected|confirmed|present)|circular trad|self-dealing/i, detail: "wash-trading evidence reported" },
];

const WARN_PATTERNS: { re: RegExp; detail: string }[] = [
  { re: /high severity/i, detail: "high-severity finding" },
  { re: /medium severity/i, detail: "medium-severity finding" },
  { re: /upgradeable|proxy|owner|paus(e|able)|centrali[sz]ed/i, detail: "centralised control (owner/proxy/pause)" },
  { re: /unverified (source|contract)|not verified/i, detail: "contract source unverified" },
  { re: /low liquidit|thin liquidit/i, detail: "thin liquidity" },
  { re: /suspicious|anomal/i, detail: "suspicious activity noted" },
  { re: /risk/i, detail: "risk flagged by miner" },
];

const CLEAN_PATTERNS: RegExp[] = [
  /no (issues?|vulnerabilit|findings?|sanctions?|wash trading) (found|detected)/i,
  /no (reentrancy|honeypot|backdoor|drain)/i,
  /severity:\s*none/i,
  /risk:\s*low/i,
  /clean/i,
  /no match/i,
  /not (listed|sanctioned|flagged)/i,
  /safe/i,
  /low risk/i,
];

/** Flatten a miner's free-form/structured answer into searchable text. */
export function answerText(result: unknown): string {
  if (result === null || result === undefined) return "";
  if (typeof result === "string") return result;
  try {
    return JSON.stringify(result);
  } catch {
    return String(result);
  }
}

/** Pull an explicit severity/risk out of a structured answer when present. */
function structuredSeverity(result: unknown): { severity?: Severity; riskScore?: number } {
  if (typeof result !== "object" || result === null) return {};
  const r = result as Record<string, unknown>;
  const sev = typeof r.severity === "string" ? r.severity.toLowerCase() : typeof r.risk_level === "string" ? r.risk_level.toLowerCase() : "";
  const severity: Severity | undefined =
    sev.includes("critical") ? "critical" : sev.includes("high") ? "high" : sev.includes("medium") ? "medium" : sev.includes("low") ? "low" : sev.includes("none") ? "none" : undefined;
  let riskScore: number | undefined;
  for (const k of ["risk_score", "riskScore", "risk", "score"]) {
    const v = r[k];
    if (typeof v === "number" && Number.isFinite(v)) {
      riskScore = v <= 1 ? Math.round(v * 100) : Math.min(100, Math.round(v));
      break;
    }
  }
  return { severity, riskScore };
}

export function parseFinding(check: CheckId, result: unknown, meta: Partial<Finding> = {}): Finding {
  const text = answerText(result);
  const structured = structuredSeverity(result);
  const notes: string[] = [];
  let severity: Severity = structured.severity ?? "none";
  let riskScore = structured.riskScore ?? 0;

  // Negation-aware matching: "no drain", "no honeypot pattern", "no match
  // found" must NOT trip the blocker patterns. Strip `no …` clauses (and
  // explicit low-risk phrasing) before testing for positive signals.
  const positiveText = text
    .replace(/\bno\b[^.;,\n]{0,90}/gi, "")
    .replace(/\bnot\b[^.;,\n]{0,60}/gi, "")
    .replace(/\bowner is renounced\b/gi, "")
    .replace(/\brenounced\b/gi, "")
    .replace(/\blow risk\b/gi, "")
    .replace(/\brisk:\s*low\b/gi, "");

  for (const p of BLOCKER_PATTERNS) {
    if (p.re.test(positiveText)) {
      notes.push(p.detail);
      severity = "critical";
      riskScore = Math.max(riskScore, 95);
    }
  }
  if (severity !== "critical") {
    for (const p of WARN_PATTERNS) {
      if (p.re.test(positiveText)) {
        notes.push(p.detail);
        if (severity === "none") severity = "medium";
        riskScore = Math.max(riskScore, severity === "high" ? 70 : 40);
      }
    }
    if (/high severity/i.test(positiveText)) {
      severity = "high";
      riskScore = Math.max(riskScore, 70);
    }
  }
  if (notes.length === 0 && CLEAN_PATTERNS.some((re) => re.test(text))) {
    notes.push("miner reports no issues");
    severity = "none";
    riskScore = Math.min(riskScore, 5);
  }
  if (notes.length === 0) {
    notes.push("answer parsed, no decisive signal extracted");
    severity = "low";
    riskScore = Math.max(riskScore, 15);
  }

  const status: FindingStatus = severity === "critical" ? "FAIL" : severity === "high" ? "FAIL" : severity === "medium" ? "WARN" : severity === "low" ? "WARN" : "PASS";
  return {
    ...meta,
    check,
    status,
    severity,
    riskScore,
    notes,
    costUusdc: meta.costUusdc ?? 0,
    durationMs: meta.durationMs ?? 0,
    receiptProblems: meta.receiptProblems ?? [],
  };
}

export function errorFinding(check: CheckId, error: string, meta: Partial<Finding> = {}): Finding {
  return {
    ...meta,
    check,
    status: "ERROR",
    severity: "critical",
    riskScore: 100,
    notes: [`check failed: ${error}`],
    costUusdc: meta.costUusdc ?? 0,
    durationMs: meta.durationMs ?? 0,
    receiptProblems: meta.receiptProblems ?? [],
  };
}

/** Default decision hash: real SHA-256 over the decision core. */
export function sha256Hex(input: string): string {
  return "0x" + createHash("sha256").update(input).digest("hex");
}

/**
 * Fuse findings into a verdict. `hashFn` is injected (node:crypto sha256 in
 * production) so the decision hash is a real hash over the whole decision.
 */
export function fuse(findings: Finding[], hashFn: (s: string) => string = sha256Hex): GuardDecision {
  const reasons: GuardDecision["reasons"] = [];
  const openRisks: string[] = [];
  const conflicts: string[] = [];

  const byCheck = new Map<CheckId, Finding>();
  for (const f of findings) byCheck.set(f.check, f);

  const required = CHECKS.filter((c) => c.required);
  const missing = required.filter((c) => {
    const f = byCheck.get(c.id);
    return !f || f.status === "ERROR" || f.status === "UNKNOWN";
  });
  const answered = required.filter((c) => {
    const f = byCheck.get(c.id);
    return f && f.status !== "ERROR" && f.status !== "UNKNOWN";
  });
  const coverage = required.length ? answered.length / required.length : 0;

  // Weighted safety score: each check contributes (100 - risk) * weight.
  let weighted = 0;
  let weightSum = 0;
  for (const c of CHECKS) {
    const f = byCheck.get(c.id);
    if (!f || f.status === "ERROR" || f.status === "UNKNOWN") continue;
    weighted += (100 - f.riskScore) * c.weight;
    weightSum += c.weight;
  }
  let score = weightSum ? Math.round(weighted / weightSum) : 0;

  // Blockers override the score.
  const blockers: Finding[] = [];
  for (const f of findings) {
    if (f.status === "FAIL" && f.severity === "critical") blockers.push(f);
    if (f.check === "sanctions" && f.severity === "critical") blockers.push(f);
  }
  const uniqueBlockers = [...new Map(blockers.map((f) => [f.check, f])).values()];

  for (const f of findings) {
    if (f.status === "ERROR") {
      reasons.push({ code: "MISSING_REQUIRED_CHECK", check: f.check, detail: `required check ${f.check} is ERROR` });
      openRisks.push(`${f.check}: ${f.notes.join("; ")}`);
    } else if (f.status === "FAIL") {
      reasons.push({ code: f.severity === "critical" ? "BLOCKER" : "CHECK_FAILED", check: f.check, detail: `${f.check}: ${f.notes.join("; ")}` });
    } else if (f.status === "WARN") {
      reasons.push({ code: "WARNING", check: f.check, detail: `${f.check}: ${f.notes.join("; ")}` });
      openRisks.push(`${f.check}: ${f.notes.join("; ")}`);
    }
    if (f.receiptProblems.length) {
      reasons.push({ code: "RECEIPT_PROBLEM", check: f.check, detail: f.receiptProblems.join("; ") });
      openRisks.push(`${f.check}: receipt unverified (${f.receiptProblems.join("; ")})`);
    }
    if (f.signalStatus === "missing" || f.signalStatus === "mismatch") {
      openRisks.push(`${f.check}: signal ${f.signalStatus} on the node`);
    }
  }

  // Conflicts: one check clean, another failing on the same subject.
  const fails = findings.filter((f) => f.status === "FAIL");
  const passes = findings.filter((f) => f.status === "PASS");
  if (fails.length && passes.length) conflicts.push(`evidence conflicts: ${fails.map((f) => f.check).join(", ")} FAIL while ${passes.map((f) => f.check).join(", ")} PASS`);

  let verdict: GuardDecision["verdict"];
  let summary: string;
  if (missing.length > 0 && POLICY.abstainOnMissingRequired) {
    verdict = "ABSTAIN";
    score = Math.min(score, 49);
    summary = `Abstained: required check ${missing.map((c) => c.id).join(", ")} missing — never treated as safe.`;
  } else if (uniqueBlockers.length > 0) {
    verdict = "BLOCK";
    score = Math.min(score, 49);
    summary = `Blocked: ${uniqueBlockers.map((f) => `${f.check} (${f.notes[0] ?? "blocker"})`).join("; ")}.`;
  } else if (score >= POLICY.goAt && coverage === 1) {
    verdict = "GO";
    summary = "Go: all required checks answered, no blocker, score " + score + "/100.";
  } else if (score >= POLICY.holdAt) {
    verdict = "HOLD";
    summary = `Hold: score ${score}/100 — mixed evidence, human review required.`;
  } else {
    verdict = "BLOCK";
    summary = `Blocked: score ${score}/100 below the hold floor.`;
  }

  const riskBps = Math.max(0, Math.min(10000, (100 - score) * 100));
  const confidenceBps = Math.round(coverage * 10000 * (conflicts.length ? 0.8 : 1));

  const decisionCore = JSON.stringify({
    policy: `${POLICY.id}@${POLICY.version}`,
    verdict,
    score,
    coverage,
    findings: findings.map((f) => ({ check: f.check, status: f.status, severity: f.severity, riskScore: f.riskScore, signalHash: f.signalHash ?? null, receiptHash: f.receiptHash ?? null })),
  });
  const verdictHash = hashFn(decisionCore);

  return { verdict, score, riskBps, confidenceBps, coverage, summary, reasons, openRisks, conflicts, findings, verdictHash };
}
