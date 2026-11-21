/**
 * Spend ledger — the hard budget. Every paid ask is recorded before the
 * next one is attempted; the caps are checked BEFORE any signature.
 *
 *  - per-ask cap:  $0.05 (50_000 uUSDC) — enforced in the Telegraph client.
 *  - total cap:    $1.00 (1_000_000 uUSDC) across the ledger's lifetime.
 *
 * The ledger is a plain JSON file so a reviewer can audit every micro-USDC.
 * Idempotency keys are derived from the full transaction being gated (chain +
 * contract + value + recipient + calldata hash + label + day), so re-running
 * the same gate replays the stored verdict instead of buying the checks
 * again. A corrupt ledger fails closed (LedgerCorruptError) instead of
 * resetting the cap, and writes are atomic (temp file + rename).
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { SPEND } from "./config.js";

export interface LedgerEntry {
  idempotencyKey: string;
  check: string;
  intent: string;
  minerId?: string;
  amountUusdc: number;
  receiptHash?: string;
  signalHash?: string;
  at: string;
  billing: "settled" | "unknown";
}

export interface Ledger {
  totalUusdc: number;
  entries: LedgerEntry[];
}

export const LEDGER_PATH = join(process.cwd(), "evidence", "ledger.json");

/** Thrown when the ledger file exists but cannot be trusted. Fail closed:
 * a corrupt ledger must never silently reset the $1 total cap to $0. */
export class LedgerCorruptError extends Error {
  readonly code = "LEDGER_CORRUPT";
  constructor(message: string) {
    super(message);
    this.name = "LedgerCorruptError";
  }
}

/** Thrown when recording a spend would push the ledger past the total cap. */
export class SpendCapError extends Error {
  readonly code = "SPEND_CAP_EXCEEDED";
  constructor(message: string) {
    super(message);
    this.name = "SpendCapError";
  }
}

export function loadLedger(path = LEDGER_PATH): Ledger {
  if (!existsSync(path)) return { totalUusdc: 0, entries: [] };
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new LedgerCorruptError(`ledger ${path} is not valid JSON (${(e as Error).message}) — refusing to spend; restore it from backup or delete it deliberately, never auto-reset`);
  }
  const ledger = raw as Ledger;
  if (
    typeof ledger !== "object" ||
    ledger === null ||
    typeof ledger.totalUusdc !== "number" ||
    !Number.isFinite(ledger.totalUusdc) ||
    ledger.totalUusdc < 0 ||
    !Array.isArray(ledger.entries) ||
    ledger.entries.some((e) => typeof e?.amountUusdc !== "number" || !Number.isFinite(e.amountUusdc) || e.amountUusdc < 0 || typeof e?.idempotencyKey !== "string")
  ) {
    throw new LedgerCorruptError(`ledger ${path} has an invalid shape — refusing to spend; restore it from backup or delete it deliberately, never auto-reset`);
  }
  return ledger;
}

/** Atomic write: temp file in the same directory + rename, so a crash can
 * never leave a half-written ledger behind. */
export function saveLedger(ledger: Ledger, path = LEDGER_PATH): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(ledger, null, 2) + "\n", "utf8");
  renameSync(tmp, path);
}

/** True when `amountUusdc` more would stay inside the total cap. */
export function canSpend(ledger: Ledger, amountUusdc: number): boolean {
  return ledger.totalUusdc + amountUusdc <= SPEND.maxUusdcTotal;
}

export function recordSpend(ledger: Ledger, entry: LedgerEntry, path = LEDGER_PATH): Ledger {
  if (!Number.isFinite(entry.amountUusdc) || entry.amountUusdc < 0) {
    throw new SpendCapError(`refusing to record a spend of ${entry.amountUusdc} uUSDC (not a valid non-negative amount)`);
  }
  // Enforce the total cap AT RECORD TIME, not only at quote time: three
  // parallel asks + fallbacks can otherwise overshoot the $1 cap between
  // the quote check and the last receipt. The ledger is left untouched.
  if (ledger.totalUusdc + entry.amountUusdc > SPEND.maxUusdcTotal) {
    throw new SpendCapError(
      `recording ${entry.amountUusdc} uUSDC would exceed the total cap ${SPEND.maxUusdcTotal} uUSDC (${ledger.totalUusdc} already spent) — spend NOT recorded`,
    );
  }
  ledger.entries.push(entry);
  ledger.totalUusdc += entry.amountUusdc;
  saveLedger(ledger, path);
  return ledger;
}

/**
 * One idempotency key per gated transaction per day. The key covers the
 * full transaction identity — chain, contract, value, recipient, CALLDATA
 * and label: two different calls to the same contract (e.g. mint vs
 * transfer, or a different label changing the miners' question) must never
 * replay each other's verdict. Calldata is hashed so the key stays short.
 */
export function idempotencyKey(subject: { chainId: number; contract: string; value?: string; to?: string; calldata?: string; label?: string }): string {
  const day = new Date().toISOString().slice(0, 10);
  const calldataHash = subject.calldata ? createHash("sha256").update(subject.calldata.toLowerCase()).digest("hex").slice(0, 16) : "-";
  const raw = `kuroguard:${subject.chainId}:${subject.contract.toLowerCase()}:${subject.value ?? "0"}:${subject.to ?? ""}:${calldataHash}:${subject.label ?? ""}:${day}`;
  return createHash("sha256").update(raw).digest("hex").slice(0, 32);
}

/** A unique ledger key for one paid ask (or one paid failure): receipt /
 * signal / amount / check / timestamp. Never a shared constant — a shared
 * key would collapse distinct spends into one idempotency bucket. */
export function spendEntryKey(parts: { check: string; intent: string; amountUusdc: number; receiptHash?: string; signalHash?: string; at: string }): string {
  return createHash("sha256").update(JSON.stringify(parts)).digest("hex").slice(0, 32);
}

export function usdc(uusdc: number): string {
  return (uusdc / 1_000_000).toFixed(6).replace(/0+$/, "").replace(/\.$/, ".0") + " USDC";
}
