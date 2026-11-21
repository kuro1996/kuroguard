/**
 * Spend ledger — the hard budget. Every paid ask is recorded before the
 * next one is attempted; the caps are checked BEFORE any signature.
 *
 *  - per-ask cap:  $0.05 (50_000 uUSDC) — enforced in the Telegraph client.
 *  - total cap:    $1.00 (1_000_000 uUSDC) across the ledger's lifetime.
 *
 * The ledger is a plain JSON file so a reviewer can audit every micro-USDC.
 * Idempotency keys are derived from the transaction being gated (chain +
 * contract + value + day), so re-running the same gate replays the stored
 * verdict instead of buying the checks again.
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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

export function loadLedger(path = LEDGER_PATH): Ledger {
  try {
    if (!existsSync(path)) return { totalUusdc: 0, entries: [] };
    const raw = JSON.parse(readFileSync(path, "utf8")) as Ledger;
    if (typeof raw.totalUusdc !== "number" || !Array.isArray(raw.entries)) return { totalUusdc: 0, entries: [] };
    return raw;
  } catch {
    return { totalUusdc: 0, entries: [] };
  }
}

export function saveLedger(ledger: Ledger, path = LEDGER_PATH): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(ledger, null, 2) + "\n", "utf8");
}

/** True when `amountUusdc` more would stay inside the total cap. */
export function canSpend(ledger: Ledger, amountUusdc: number): boolean {
  return ledger.totalUusdc + amountUusdc <= SPEND.maxUusdcTotal;
}

export function recordSpend(ledger: Ledger, entry: LedgerEntry, path = LEDGER_PATH): Ledger {
  ledger.entries.push(entry);
  ledger.totalUusdc += entry.amountUusdc;
  saveLedger(ledger, path);
  return ledger;
}

/** One idempotency key per gated transaction per day. */
export function idempotencyKey(subject: { chainId: number; contract: string; value?: string; to?: string }): string {
  const day = new Date().toISOString().slice(0, 10);
  const raw = `kuroguard:${subject.chainId}:${subject.contract.toLowerCase()}:${subject.value ?? "0"}:${subject.to ?? ""}:${day}`;
  return createHash("sha256").update(raw).digest("hex").slice(0, 32);
}

export function usdc(uusdc: number): string {
  return (uusdc / 1_000_000).toFixed(6).replace(/0+$/, "").replace(/\.$/, ".0") + " USDC";
}
