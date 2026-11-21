/**
 * KuroGuard's own Telegraph client — written from the public protocol
 * behaviour (x402-style escrow challenge on POST /engine/v1/ask), NOT a fork
 * of any other project's SDK. Wire semantics:
 *
 *  1. POST /engine/v1/ask {intent, params?, query?} with no payment
 *     → the node answers 402 with an `accepts[]` list (JSON body and/or
 *     `payment-required` header, base64 JSON).
 *  2. The client takes the `scheme: "escrow"` accept, VALIDATES it against
 *     the pinned network config (chain, payee = escrow Diamond, amount
 *     "N uUSDC", resource /v1/ask[/minerId], per-call cap) and refuses
 *     anything that disagrees — a challenge is untrusted input.
 *  3. It fills the escrow message template, signs it with EIP-191
 *     (personal_sign), and re-POSTs with `X-PAYMENT: base64({x402Version: 2,
 *     scheme: "escrow", network, payload: {signature, authorization}})`.
 *  4. The paid answer comes back with the receipt in the
 *     `x-payment-response` header (base64 JSON: receipt_hash, rail, payer,
 *     miner, amount_uusdc) and a `signal_hash` in the body.
 *  5. GET /engine/v1/signal/<signal_hash> re-checks the network's own
 *     record of the signal.
 *
 * A failure AFTER X-PAYMENT was sent is never retried: the node may have
 * billed it. A failure before payment is retried once with a fresh nonce.
 */

import { privateKeyToAccount } from "viem/accounts";
import { TELEGRAPH } from "./config.js";

export interface NetworkConfig {
  nodeUrl: string;
  caip2: string;
  chainId: number;
  diamond: string;
  usdc: string;
  rpcUrl: string;
  /** Who an escrow payment authorisation pays (default: the Diamond). */
  payee: string;
}

export const TESTNET: NetworkConfig = { ...TELEGRAPH };

export interface MessageSigner {
  address: string;
  signMessage(message: string): Promise<string>;
}

export function viemSigner(privateKey: `0x${string}`): MessageSigner {
  const account = privateKeyToAccount(privateKey);
  return {
    address: account.address,
    signMessage: (message: string) => account.signMessage({ message }),
  };
}

export class ChallengeMismatchError extends Error {
  readonly code = "CHALLENGE_MISMATCH";
  constructor(message: string) {
    super(message);
    this.name = "ChallengeMismatchError";
  }
}

export interface Receipt {
  receipt_hash: string;
  rail: string;
  payer: string;
  miner: string;
  intent?: string;
  amount_uusdc: string;
  epoch_id?: number;
  settlement?: string;
  chain?: string;
  timestamp: number;
  tx_hash?: string;
}

export type AskRequest =
  | { intent: string; params?: Record<string, unknown>; query?: string; context?: Record<string, unknown> }
  | { method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE"; endpoint: string; payload: Record<string, unknown>; acknowledge_warnings?: true };

export interface AskResponse {
  miner_id: string;
  miner_name?: string;
  endpoint?: string;
  result: unknown;
  result_shape?: "intent" | "raw";
  shape_error?: string;
  field_status?: Record<string, "ok" | "missing" | "rejected" | "unavailable">;
  intent?: string;
  cost_usd?: number;
  duration_ms?: number;
  signal_hash?: string;
  warnings?: string[];
}

export type AskFailureKind =
  | "timeout"
  | "network"
  | "refused"
  | "client_error"
  | "server_error"
  | "incompatible"
  | "mismatch"
  | "preseason";

export type AskOutcome =
  | {
      ok: true;
      response: AskResponse;
      receipt: Receipt | null;
      /** Why the receipt is not evidence of this purchase; empty when it checks out. */
      receiptProblems: string[];
      httpStatus: number;
      amountUusdc: number;
      durationMs: number;
      attempts: number;
    }
  | {
      ok: false;
      kind: AskFailureKind;
      httpStatus?: number;
      error: string;
      durationMs: number;
      attempts: number;
      paidUusdc: number;
      billing: "none" | "unknown";
    };

export type SignalStatus = "verified" | "missing" | "mismatch" | "unchecked";

export interface MinerRecord {
  id: string;
  slug: string;
  name: string;
  base_url: string;
  supported_intents: string[];
  activation_status: string;
  min_price_usdc: number;
}

// ---------------------------------------------------------------------------
// Escrow challenge handling
// ---------------------------------------------------------------------------

const WINDOW_BEFORE_SEC = 5;
const WINDOW_AFTER_SEC = 100;
const SEASON_START = Date.parse("2026-11-01T00:00:00Z");

const TEMPLATE_HEADER = "Telegraph Escrow Payment";
const TEMPLATE_KEYS = ["Wallet", "Pay To", "Network", "Amount", "Resource", "Nonce", "Valid After", "Valid Before"] as const;
const PLACEHOLDERS: Record<string, string> = {
  Wallet: "{from}",
  Nonce: "{nonce}",
  "Valid After": "{validAfter}",
  "Valid Before": "{validBefore}",
};

const b64encode = (s: string) => Buffer.from(s, "utf8").toString("base64");
const b64decode = (s: string) => Buffer.from(s, "base64").toString("utf8");

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

interface EscrowAccept {
  scheme: string;
  network: string;
  payTo: string;
  price?: string;
  amount?: string;
  asset?: string;
  extra?: { message?: string; resource?: string; description?: string };
}

/** Find the escrow accept in a 402 challenge (header first, then body). */
export function readChallenge(headerValue: string | null, body: unknown): { escrow: EscrowAccept; assets: string[] } | null {
  const candidates: unknown[] = [];
  if (headerValue) {
    try {
      candidates.push(JSON.parse(b64decode(headerValue)));
    } catch {
      /* not a challenge header — fall through to the body */
    }
  }
  candidates.push(body);
  for (const c of candidates) {
    const accepts = (c as { accepts?: unknown })?.accepts;
    if (!Array.isArray(accepts)) continue;
    const hit = accepts.find(
      (a) => (a as EscrowAccept)?.scheme === "escrow" && typeof (a as EscrowAccept)?.extra?.message === "string" && typeof (a as EscrowAccept)?.payTo === "string",
    ) as EscrowAccept | undefined;
    if (hit) {
      const assets = accepts.map((a) => (a as EscrowAccept)?.asset).filter((x): x is string => typeof x === "string");
      return { escrow: hit, assets };
    }
  }
  return null;
}

interface ParsedTemplate {
  payTo: string;
  network: string;
  amountUusdc: string;
  resource: string;
}

/** The escrow message must have the documented layout, or it is refused.
 * A trailing newline (or blank lines) at the end of a live template is
 * tolerated — it is not a mismatch, only sloppy framing. */
export function parseTemplate(template: string): ParsedTemplate {
  const lines = template.trimEnd().split("\n");
  if (lines[0] !== TEMPLATE_HEADER || lines[1] !== "" || lines.length !== 2 + TEMPLATE_KEYS.length) {
    throw new ChallengeMismatchError("escrow template does not have the documented layout");
  }
  const values: Record<string, string> = {};
  TEMPLATE_KEYS.forEach((key, i) => {
    const line = lines[2 + i];
    const prefix = `${key}: `;
    if (!line.startsWith(prefix)) throw new ChallengeMismatchError(`escrow template line ${3 + i} should be "${key}: …"`);
    values[key] = line.slice(prefix.length);
  });
  for (const [key, ph] of Object.entries(PLACEHOLDERS)) {
    if (values[key] !== ph) throw new ChallengeMismatchError(`escrow template ${key} must be ${ph}`);
  }
  const fixed = TEMPLATE_KEYS.filter((k) => !(k in PLACEHOLDERS)).map((k) => values[k]);
  if (fixed.some((v) => /[{}]/.test(v))) throw new ChallengeMismatchError("escrow template has an unexpected placeholder");
  const amount = /^(\d{1,12}) uUSDC$/.exec(values.Amount);
  if (!amount) throw new ChallengeMismatchError('escrow template Amount is not "N uUSDC"');
  if (!/^\/v1\/ask(\/[\w.-]+)?$/.test(values.Resource)) throw new ChallengeMismatchError(`escrow template Resource ${values.Resource} is not an ask`);
  return { payTo: values["Pay To"], network: values.Network, amountUusdc: amount[1], resource: values.Resource };
}

export interface Authorization {
  from: string;
  to: string;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: string;
}

function buildAuthorization(args: { from: string; to: string; value: string; nowSec: number; nonce: string }): Authorization {
  return {
    from: args.from.toLowerCase(), // the node lowercases the wallet before checking the signature
    to: args.to,
    value: args.value,
    validAfter: String(args.nowSec - WINDOW_BEFORE_SEC),
    validBefore: String(args.nowSec + WINDOW_AFTER_SEC),
    nonce: args.nonce,
  };
}

function fillTemplate(template: string, auth: Authorization): string {
  return template
    .split("{from}").join(auth.from)
    .split("{nonce}").join(auth.nonce)
    .split("{validAfter}").join(auth.validAfter)
    .split("{validBefore}").join(auth.validBefore);
}

/**
 * Validate a 402 escrow challenge against the pinned network, sign the
 * payment message, and return the X-PAYMENT header value. Throws
 * ChallengeMismatchError on anything unexpected — never sign blind.
 */
export async function signEscrowPayment(args: {
  accept: EscrowAccept;
  assets?: string[];
  signer: MessageSigner;
  expected: { caip2: string; payee: string; usdc?: string; maxUusdc: number; resource?: string };
  nowSec: number;
  nonce: string;
}): Promise<{ header: string; authorization: Authorization; amountUusdc: number }> {
  const { accept, expected } = args;
  const t = parseTemplate(accept.extra!.message!);
  const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
  if (accept.network !== expected.caip2 || t.network !== expected.caip2) {
    throw new ChallengeMismatchError(`challenge network ${accept.network} / template ${t.network}, expected ${expected.caip2}`);
  }
  // The payee must be the configured escrow payee (default: the Diamond)
  // AND internally consistent between the accept and its own template.
  // If the live node names a different payee (observed: 0x72a7… on a generic
  // GET 402 — see config.ts), set it explicitly via TELEGRAPH_ESCROW_PAYEE
  // after verifying it; never sign a challenge that pays an unknown address.
  if (!same(accept.payTo, t.payTo)) {
    throw new ChallengeMismatchError(`challenge payTo ${accept.payTo} disagrees with its template ${t.payTo}`);
  }
  if (!same(accept.payTo, expected.payee)) {
    throw new ChallengeMismatchError(`challenge pays ${accept.payTo}, expected escrow payee ${expected.payee} (set TELEGRAPH_ESCROW_PAYEE only after verifying the address)`);
  }
  if (accept.amount !== undefined && accept.amount !== t.amountUusdc) {
    throw new ChallengeMismatchError(`challenge amount ${accept.amount} disagrees with the template's ${t.amountUusdc}`);
  }
  if (accept.extra?.resource !== undefined && accept.extra.resource !== t.resource) {
    throw new ChallengeMismatchError(`challenge resource ${accept.extra.resource} disagrees with the template's ${t.resource}`);
  }
  if (expected.resource !== undefined && t.resource !== expected.resource) {
    throw new ChallengeMismatchError(`template resource ${t.resource}, expected ${expected.resource}`);
  }
  if (expected.usdc) {
    const wrong = (args.assets ?? []).find((a) => !same(a, expected.usdc!));
    if (wrong) throw new ChallengeMismatchError(`challenge names asset ${wrong}, expected USDC ${expected.usdc}`);
  }
  const amountUusdc = Number(t.amountUusdc);
  if (!(Number.isSafeInteger(amountUusdc) && amountUusdc <= expected.maxUusdc)) {
    throw new ChallengeMismatchError(`challenge asks ${t.amountUusdc} uUSDC, cap ${expected.maxUusdc}`);
  }
  const authorization = buildAuthorization({ from: args.signer.address, to: expected.payee, value: t.amountUusdc, nowSec: args.nowSec, nonce: args.nonce });
  const signature = await args.signer.signMessage(fillTemplate(accept.extra!.message!, authorization));
  const header = b64encode(JSON.stringify({ x402Version: 2, scheme: "escrow", network: accept.network, payload: { signature, authorization } }));
  return { header, authorization, amountUusdc };
}

export function decodeReceipt(headerValue: string | null): Receipt | null {
  if (!headerValue) return null;
  try {
    const r = JSON.parse(b64decode(headerValue)) as Receipt;
    return typeof r?.receipt_hash === "string" ? r : null;
  } catch {
    return null;
  }
}

/** Cross-check a receipt against what was actually signed. */
export function receiptProblems(r: Receipt | null, signed: { payer: string; amountUusdc: number; minerId?: string }): string[] {
  if (!r) return ["no receipt"];
  const out: string[] = [];
  if (!/^0x[0-9a-fA-F]{64}$/.test(r.receipt_hash)) out.push("receipt_hash is not 32 bytes of hex");
  if (r.rail !== "escrow") out.push(`receipt rail ${r.rail}, expected escrow`);
  if (typeof r.payer !== "string" || r.payer.toLowerCase() !== signed.payer.toLowerCase()) out.push(`receipt payer ${r.payer}, expected ${signed.payer}`);
  if (String(r.amount_uusdc) !== String(signed.amountUusdc)) out.push(`receipt amount ${r.amount_uusdc}, signed ${signed.amountUusdc}`);
  if (signed.minerId && r.miner !== undefined && String(r.miner) !== signed.minerId) out.push(`receipt miner ${r.miner}, pinned ${signed.minerId}`);
  return out;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export interface ClientOptions {
  network: NetworkConfig;
  signer?: MessageSigner;
  fetch?: typeof fetch;
  /** Hard cap on what one call may cost, in micro-USDC. */
  maxUusdcPerCall: number;
  now?: () => number;
  nonce?: () => string;
  /** Allow paid calls before the season opens (pre-season smoke tests only). */
  allowPreSeason?: boolean;
}

/**
 * Retryable failure kinds — failures BEFORE any payment was sent. A failure
 * AFTER X-PAYMENT was sent is never retried: the node may have billed it.
 * "refused" is deliberately NOT here: it only ever happens after payment
 * (a paid request answered 402), and retrying it would sign and pay twice.
 * Its billing is "unknown" (see fail() — paidUusdc > 0), so ask() also
 * returns it immediately on that ground; the set is the second line of
 * defence. */
const RETRYABLE = new Set(["timeout", "network", "server_error"]);

export class TelegraphClient {
  private readonly fetchFn: typeof fetch;
  private readonly now: () => number;
  private readonly nonce: () => string;

  constructor(private readonly opts: ClientOptions) {
    this.fetchFn = opts.fetch ?? globalThis.fetch;
    this.now = opts.now ?? Date.now;
    this.nonce = opts.nonce ?? (() => crypto.randomUUID());
  }

  private url(path: string): string {
    return `${this.opts.network.nodeUrl.replace(/\/$/, "")}${path}`;
  }

  /** One request with a referenced timer that also covers reading the body. */
  private async send(path: string, init: RequestInit, timeoutMs: number): Promise<{ status: number; headers: Headers; text: string } | "timeout" | "network"> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(new DOMException("upstream timed out", "TimeoutError")), timeoutMs);
    try {
      const res = await this.fetchFn(this.url(path), { ...init, signal: ctl.signal });
      const text = (await res.text()).slice(0, 1_000_000);
      return { status: res.status, headers: res.headers, text };
    } catch (e) {
      const err = e as Error;
      return err.name === "TimeoutError" || err.name === "AbortError" ? "timeout" : "network";
    } finally {
      clearTimeout(timer);
    }
  }

  private async getJson(path: string): Promise<Record<string, unknown>> {
    const r = await this.send(path, { method: "GET" }, 15_000);
    if (typeof r === "string") throw new Error(`GET ${path}: ${r}`);
    if (r.status < 200 || r.status >= 300) throw new Error(`GET ${path}: HTTP ${r.status}`);
    return JSON.parse(r.text) as Record<string, unknown>;
  }

  async getIntents(): Promise<{ count: number; intents: { intent_id: string; miner_count: number; canonical: boolean }[] }> {
    return this.getJson("/engine/v1/intents") as Promise<{ count: number; intents: { intent_id: string; miner_count: number; canonical: boolean }[] }>;
  }

  async getIntent(intent: string): Promise<Record<string, unknown>> {
    return this.getJson(`/engine/v1/intents/${encodeURIComponent(intent)}`);
  }

  async listMiners(q: { intent?: string; status?: string; limit?: number } = {}): Promise<MinerRecord[]> {
    const p = new URLSearchParams();
    if (q.intent) p.set("intent", q.intent);
    if (q.status) p.set("status", q.status);
    if (q.limit) p.set("limit", String(q.limit));
    const d = await this.getJson(`/api/miners${p.size ? `?${p}` : ""}`);
    return (d.miners ?? d) as MinerRecord[];
  }

  async getSignal(signalHash: string): Promise<Record<string, unknown>> {
    return this.getJson(`/engine/v1/signal/${encodeURIComponent(signalHash)}`);
  }

  /**
   * Looks a paid answer's signal_hash up on the node — the network's own
   * record of it. "verified": the node has the signal (and, when it says
   * which miner, that miner is the one paid). "missing": no such signal.
   * "mismatch": it exists, from another miner. "unchecked": node silent.
   */
  async verifySignal(signalHash: string | undefined, expect: { minerId?: string } = {}): Promise<SignalStatus> {
    if (!signalHash || !/^0x[0-9a-fA-F]{64}$/.test(signalHash)) return "missing";
    const r = await this.send(`/engine/v1/signal/${encodeURIComponent(signalHash)}`, { method: "GET" }, 10_000);
    if (typeof r === "string" || r.status >= 500) return "unchecked";
    if (r.status === 404) return "missing";
    if (r.status < 200 || r.status >= 300) return "unchecked";
    const body = parseJson(r.text) as Record<string, unknown> | null;
    const miner = body?.miner_id ?? body?.minerId;
    if (expect.minerId && miner !== undefined && miner !== null && String(miner) !== expect.minerId) return "mismatch";
    return "verified";
  }

  /**
   * Buys one answer on the escrow rail. Failures before payment are retried
   * once with a fresh challenge and nonce: nothing was billed. A failure
   * after X-PAYMENT was sent — including a 402 refusal — is never retried
   * and is reported with billing "unknown" and the paid amount attached.
   */
  async ask(req: AskRequest, opts: { minerId?: string; timeoutMs: number; maxUusdc?: number }): Promise<AskOutcome> {
    const started = this.now();
    let last: AskOutcome | null = null;
    for (let attempt = 1; attempt <= 2; attempt++) {
      const out = await this.attempt(req, opts, started, attempt);
      if (out.ok || out.billing === "unknown" || !RETRYABLE.has(out.kind)) return out;
      last = out;
    }
    return last!;
  }

  private async attempt(req: AskRequest, opts: { minerId?: string; timeoutMs: number; maxUusdc?: number }, started: number, attempts: number): Promise<AskOutcome> {
    const path = opts.minerId ? `/engine/v1/ask/${encodeURIComponent(opts.minerId)}` : "/engine/v1/ask";
    const body = JSON.stringify(req);
    const fail = (kind: AskFailureKind, error: string, httpStatus?: number, paidUusdc = 0): AskOutcome => ({
      ok: false,
      kind,
      error,
      durationMs: this.now() - started,
      attempts,
      paidUusdc,
      billing: paidUusdc > 0 ? "unknown" : "none",
      ...(httpStatus !== undefined ? { httpStatus } : {}),
    });
    const post = (headers: Record<string, string>) =>
      this.send(path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body }, opts.timeoutMs);

    // 1. Unpaid probe — the node must answer 402 with an escrow challenge.
    const challenge = await post({});
    if (typeof challenge === "string") return fail(challenge, `unpaid request: ${challenge}`);
    if (challenge.status !== 402) {
      const msg = challenge.text.slice(0, 2000);
      let err: string | undefined;
      try {
        err = (JSON.parse(msg) as { error?: string }).error;
      } catch { /* not JSON */ }
      const kind: AskFailureKind =
        challenge.status < 300 || err === "no_compatible_miner" || err === "invalid_params" || err === "no_input_schema" || err === "intent_required"
          ? "incompatible"
          : challenge.status >= 500
            ? "server_error"
            : "client_error";
      return fail(kind, `expected 402, got ${challenge.status}: ${msg}`, challenge.status);
    }
    const parsed = readChallenge(challenge.headers.get("payment-required"), parseJson(challenge.text));
    if (!parsed) return fail("mismatch", "the node offered no escrow scheme", 402);
    if (!this.opts.allowPreSeason && this.now() < SEASON_START) {
      return fail("preseason", "paid calls are refused before the season opens (Nov 1 UTC)");
    }
    if (!this.opts.signer) return fail("mismatch", "no signer configured");
    const maxUusdc = Math.min(this.opts.maxUusdcPerCall, opts.maxUusdc ?? Infinity);
    let signed: Awaited<ReturnType<typeof signEscrowPayment>>;
    try {
      signed = await signEscrowPayment({
        accept: parsed.escrow,
        assets: parsed.assets,
        signer: this.opts.signer,
        expected: {
          caip2: this.opts.network.caip2,
          payee: process.env.TELEGRAPH_ESCROW_PAYEE ?? this.opts.network.payee,
          usdc: this.opts.network.usdc,
          maxUusdc,
          ...(opts.minerId ? { resource: `/v1/ask/${opts.minerId}` } : {}),
        },
        nowSec: Math.floor(this.now() / 1000),
        nonce: this.nonce(),
      });
    } catch (e) {
      if (e instanceof ChallengeMismatchError) return fail("mismatch", e.message, 402);
      throw e;
    }

    // 2. Paid request. Never retried after this point.
    const paid = await post({ "X-PAYMENT": signed.header });
    const sent = signed.amountUusdc;
    if (typeof paid === "string") return fail(paid, `paid request: ${paid}`, undefined, sent);
    if (paid.status === 402) {
      const reason = parseJson(paid.text) as { reason?: string; error?: string } | null;
      // Post-payment 402: the authorisation may already have been billed,
      // so the paid amount is passed through (billing "unknown") and the
      // caller must count it against the ledger and never retry it.
      return fail("refused", `payment refused: ${reason?.reason ?? reason?.error ?? "no reason given"}`, 402, sent);
    }
    if (paid.status < 200 || paid.status >= 300) {
      return fail(paid.status >= 500 ? "server_error" : "client_error", `HTTP ${paid.status}: ${paid.text.slice(0, 2000)}`, paid.status, sent);
    }
    const response = parseJson(paid.text) as AskResponse | null;
    if (!response || typeof response !== "object") return fail("server_error", "200 with a body that is not JSON", paid.status, sent);
    const receipt = decodeReceipt(paid.headers.get("x-payment-response"));
    const problems = receiptProblems(receipt, { payer: signed.authorization.from, amountUusdc: sent, minerId: opts.minerId });
    if (opts.minerId) {
      for (const [what, id] of [["receipt miner", receipt?.miner], ["answered by miner", response.miner_id]] as const) {
        if (id === undefined || id === null || String(id) === opts.minerId) continue;
        problems.push(`${what} ${id}, pinned ${opts.minerId} (registration lookup unavailable — treat as unverified, not as proof of mismatch)`);
      }
    }
    return { ok: true, response, receipt, receiptProblems: problems, httpStatus: paid.status, amountUusdc: sent, durationMs: this.now() - started, attempts };
  }
}
