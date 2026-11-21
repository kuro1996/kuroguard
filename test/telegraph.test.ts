import { describe, expect, it } from "vitest";
import { ChallengeMismatchError, decodeReceipt, parseTemplate, readChallenge, receiptProblems, signEscrowPayment, type MessageSigner } from "../src/telegraph.js";

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
