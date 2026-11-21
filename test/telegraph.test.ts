import { describe, expect, it } from "vitest";
import { ChallengeMismatchError, decodeReceipt, parseTemplate, readChallenge, receiptProblems, signEscrowPayment, TelegraphClient, TESTNET, type MessageSigner } from "../src/telegraph.js";
import { SPEND } from "../src/config.js";

const DIAMOND = "0x3624EB012B5E998BB57B6bE6C9Cfc9c4bc5eb99b";
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

const fakeSigner: MessageSigner = {
  address: "0x1111111111111111111111111111111111111111",
  signMessage: async (m: string) => `signed:${m.slice(0, 12)}`,
};

function accept(payTo = DIAMOND, amount = "10000 uUSDC") {
  return {
    scheme: "escrow",
    network: "eip155:11155111",
    payTo,
    extra: { message: TEMPLATE.replace(DIAMOND, payTo).replace("10000 uUSDC", amount), resource: "/v1/ask" },
  };
}

describe("parseTemplate", () => {
  it("accepts the documented layout", () => {
    const t = parseTemplate(TEMPLATE);
    expect(t.payTo).toBe(DIAMOND);
    expect(t.amountUusdc).toBe("10000");
    expect(t.resource).toBe("/v1/ask");
  });
  it("rejects a tampered header", () => {
    expect(() => parseTemplate(TEMPLATE.replace("Telegraph Escrow Payment", "Telegraph Payment"))).toThrow(ChallengeMismatchError);
  });
  it("rejects a non-uUSDC amount", () => {
    expect(() => parseTemplate(TEMPLATE.replace("10000 uUSDC", "10 USDC"))).toThrow(ChallengeMismatchError);
  });
  it("tolerates a trailing newline (M8)", () => {
    const t = parseTemplate(TEMPLATE + "\n");
    expect(t.payTo).toBe(DIAMOND);
    expect(t.amountUusdc).toBe("10000");
  });
  it("tolerates several trailing blank lines (M8)", () => {
    expect(parseTemplate(TEMPLATE + "\n\n\n").resource).toBe("/v1/ask");
  });
});

describe("readChallenge", () => {
  it("finds the escrow accept in the body", () => {
    const c = readChallenge(null, { error: "payment required", accepts: [accept()] });
    expect(c?.escrow.payTo).toBe(DIAMOND);
  });
  it("returns null when there is no escrow scheme", () => {
    expect(readChallenge(null, { accepts: [{ scheme: "exact", payTo: "0xabc" }] })).toBeNull();
  });
});

describe("signEscrowPayment", () => {
  const base = { signer: fakeSigner, nowSec: 1_800_000_000, nonce: "test-nonce-1" };
  it("signs a valid challenge under the cap", async () => {
    const { header, amountUusdc, authorization } = await signEscrowPayment({
      ...base,
      accept: accept(),
      expected: { caip2: "eip155:11155111", payee: DIAMOND, maxUusdc: 50_000 },
    });
    expect(amountUusdc).toBe(10_000);
    expect(authorization.from).toBe(fakeSigner.address.toLowerCase());
    expect(authorization.to).toBe(DIAMOND);
    expect(authorization.nonce).toBe("test-nonce-1");
    const decoded = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
    expect(decoded.scheme).toBe("escrow");
    expect(decoded.payload.authorization.value).toBe("10000");
  });
  it("refuses a challenge above the cap", async () => {
    await expect(
      signEscrowPayment({ ...base, accept: accept(DIAMOND, "60000 uUSDC"), expected: { caip2: "eip155:11155111", payee: DIAMOND, maxUusdc: 50_000 } }),
    ).rejects.toThrow(ChallengeMismatchError);
  });
  it("refuses a challenge paying an unknown address", async () => {
    const other = "0x72a70e949362670bf8bcead24efc5b8f950aa08b";
    await expect(
      signEscrowPayment({ ...base, accept: accept(other), expected: { caip2: "eip155:11155111", payee: DIAMOND, maxUusdc: 50_000 } }),
    ).rejects.toThrow(/expected escrow payee/);
  });
  it("accepts the observed live payee only when explicitly configured", async () => {
    const other = "0x72a70e949362670bf8bcead24efc5b8f950aa08b";
    const tpl = TEMPLATE.replace(DIAMOND, other);
    const { authorization } = await signEscrowPayment({
      ...base,
      accept: { scheme: "escrow", network: "eip155:11155111", payTo: other, extra: { message: tpl, resource: "/v1/ask" } },
      expected: { caip2: "eip155:11155111", payee: other, maxUusdc: 50_000 },
    });
    expect(authorization.to).toBe(other);
  });
  it("refuses a wrong network", async () => {
    await expect(
      signEscrowPayment({ ...base, accept: { ...accept(), network: "eip155:1" }, expected: { caip2: "eip155:11155111", payee: DIAMOND, maxUusdc: 50_000 } }),
    ).rejects.toThrow(ChallengeMismatchError);
  });
});

describe("receipts", () => {
  it("decodeReceipt parses the x-payment-response header", () => {
    const r = { receipt_hash: "0x" + "ab".repeat(32), rail: "escrow", payer: fakeSigner.address, miner: "200001", amount_uusdc: "10000", timestamp: 1 };
    const h = Buffer.from(JSON.stringify(r)).toString("base64");
    expect(decodeReceipt(h)?.receipt_hash).toBe(r.receipt_hash);
    expect(decodeReceipt("not-base64!!!")).toBeNull();
  });
  it("receiptProblems flags payer/amount mismatches", () => {
    const good = { receipt_hash: "0x" + "ab".repeat(32), rail: "escrow", payer: fakeSigner.address, miner: "200001", amount_uusdc: "10000", timestamp: 1 };
    expect(receiptProblems(good, { payer: fakeSigner.address, amountUusdc: 10_000 })).toEqual([]);
    expect(receiptProblems(good, { payer: fakeSigner.address, amountUusdc: 20_000 }).length).toBeGreaterThan(0);
    expect(receiptProblems(null, { payer: fakeSigner.address, amountUusdc: 10_000 })).toEqual(["no receipt"]);
  });
});

describe("TelegraphClient.ask (mock fetch)", () => {
  const USDC = "0xcc194e1a843B658526D0D5C431f670028582Ae17";
  const NOW = Date.parse("2026-11-22T02:00:00Z");

  function challengeResponse(resource = "/v1/ask"): Response {
    const tpl = TEMPLATE.replace("Resource: /v1/ask", `Resource: ${resource}`);
    const body = JSON.stringify({
      error: "payment required",
      accepts: [{ scheme: "escrow", network: "eip155:11155111", payTo: DIAMOND, amount: "10000", asset: USDC, extra: { message: tpl, resource } }],
    });
    return new Response(body, { status: 402, headers: { "content-type": "application/json" } });
  }

  function paidResponse(result: string, minerId = "200001"): Response {
    const receipt = { receipt_hash: "0x" + "ab".repeat(32), rail: "escrow", payer: fakeSigner.address, miner: minerId, amount_uusdc: "10000", timestamp: 1 };
    const body = JSON.stringify({ miner_id: minerId, miner_name: "Mock Miner", result, signal_hash: "0x" + "cd".repeat(32) });
    return new Response(body, {
      status: 200,
      headers: { "content-type": "application/json", "x-payment-response": Buffer.from(JSON.stringify(receipt)).toString("base64") },
    });
  }

  /** A fetch mock that plays a fixed script of responses, one per call. */
  function scriptedFetch(script: Response[]): { fetch: typeof fetch; callCount: () => number } {
    let calls = 0;
    const fetchFn = (async () => script[calls++] ?? new Response("script exhausted", { status: 500 })) as unknown as typeof fetch;
    return { fetch: fetchFn, callCount: () => calls };
  }

  function client(mock: { fetch: typeof fetch }): TelegraphClient {
    return new TelegraphClient({
      network: TESTNET,
      signer: fakeSigner,
      fetch: mock.fetch,
      maxUusdcPerCall: SPEND.maxUusdcPerAsk,
      now: () => NOW,
      nonce: () => "test-nonce-1",
    });
  }

  const req = { intent: "SMART_CONTRACT_AUDIT_GENERAL", query: "Audit 0x4200000000000000000000000000000000000006", params: { contract_address: "0x4200000000000000000000000000000000000006", chain_id: 8453 } };

  it("end-to-end: 402 challenge → sign → paid 200 with a clean receipt", async () => {
    const mock = scriptedFetch([challengeResponse(), paidResponse("Audit complete. No issues found, no vulnerabilities, contract is safe. Severity: none.")]);
    const out = await client(mock).ask(req, { timeoutMs: 5_000 });
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.amountUusdc).toBe(10_000);
    expect(out.attempts).toBe(1);
    expect(out.receiptProblems).toEqual([]);
    expect(out.receipt?.payer).toBe(fakeSigner.address);
    expect(mock.callCount()).toBe(2);
  });

  it("H2: a 402 AFTER payment is counted as paid and NEVER retried", async () => {
    const refused = new Response(JSON.stringify({ reason: "settlement failed" }), { status: 402, headers: { "content-type": "application/json" } });
    const mock = scriptedFetch([challengeResponse(), refused]);
    const out = await client(mock).ask(req, { timeoutMs: 5_000 });
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.kind).toBe("refused");
    expect(out.httpStatus).toBe(402);
    // The money may already have been billed: it must be reported as paid.
    expect(out.paidUusdc).toBe(10_000);
    expect(out.billing).toBe("unknown");
    expect(out.attempts).toBe(1);
    // No retry: exactly 2 HTTP calls (unpaid probe + paid request).
    expect(mock.callCount()).toBe(2);
  });

  it("retries ONCE on a pre-payment failure (500 on the unpaid probe)", async () => {
    const boom = new Response(JSON.stringify({ error: "boom" }), { status: 500, headers: { "content-type": "application/json" } });
    const mock = scriptedFetch([boom, challengeResponse(), paidResponse("Audit complete. No issues found. Severity: none.")]);
    const out = await client(mock).ask(req, { timeoutMs: 5_000 });
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.attempts).toBe(2);
    expect(mock.callCount()).toBe(3);
  });
});
