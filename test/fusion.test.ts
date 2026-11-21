import { describe, expect, it } from "vitest";
import { errorFinding, fuse, parseFinding, type Finding } from "../src/fusion.js";

function finding(check: Finding["check"], patch: Partial<Finding> = {}): Finding {
  return { check, status: "PASS", severity: "none", riskScore: 0, notes: ["clean"], costUusdc: 10_000, durationMs: 100, receiptProblems: [], ...patch };
}

describe("parseFinding", () => {
  it("parses a clean audit answer as PASS", () => {
    const f = parseFinding("contract_audit", "Audit complete. No issues found, no vulnerabilities, contract is safe. Severity: none.");
    expect(f.status).toBe("PASS");
    expect(f.severity).toBe("none");
  });
  it("parses a honeypot answer as critical FAIL", () => {
    const f = parseFinding("contract_audit", "CRITICAL finding: honeypot pattern — sells are blocked for non-owner wallets. Owner can drain funds.");
    expect(f.status).toBe("FAIL");
    expect(f.severity).toBe("critical");
    expect(f.riskScore).toBeGreaterThanOrEqual(95);
  });
  it("parses a sanctions match as critical FAIL", () => {
    const f = parseFinding("sanctions", "Match found on the OFAC SDN list for this address.");
    expect(f.status).toBe("FAIL");
    expect(f.severity).toBe("critical");
  });
  it("parses wash-trading evidence as critical FAIL", () => {
    const f = parseFinding("wash_trading", "Wash trading detected: circular transfers between affiliated wallets.");
    expect(f.status).toBe("FAIL");
  });
  it("treats a vague answer as low-severity WARN, not a pass", () => {
    const f = parseFinding("wash_trading", "The data is inconclusive and more context would help.");
    expect(f.status).toBe("WARN");
  });
});

describe("fuse", () => {
  it("GO when all three checks are clean", () => {
    const d = fuse([finding("contract_audit"), finding("wash_trading"), finding("sanctions")]);
    expect(d.verdict).toBe("GO");
    expect(d.score).toBeGreaterThanOrEqual(80);
    expect(d.coverage).toBe(1);
    expect(d.verdictHash).toMatch(/^0x[0-9a-f]{64}$/);
  });
  it("BLOCK on a critical audit finding even if the other two pass", () => {
    const bad = parseFinding("contract_audit", "CRITICAL: honeypot — sells blocked, owner can drain.");
    const d = fuse([bad, finding("wash_trading"), finding("sanctions")]);
    expect(d.verdict).toBe("BLOCK");
    expect(d.score).toBeLessThan(50);
  });
  it("BLOCK on a sanctions match", () => {
    const bad = parseFinding("sanctions", "Sanctions match: address appears on the OFAC SDN list.");
    const d = fuse([finding("contract_audit"), finding("wash_trading"), bad]);
    expect(d.verdict).toBe("BLOCK");
  });
  it("ABSTAIN — never GO — when a required check errors", () => {
    const d = fuse([finding("contract_audit"), errorFinding("wash_trading", "timeout"), finding("sanctions")]);
    expect(d.verdict).toBe("ABSTAIN");
    expect(d.reasons.some((r) => r.code === "MISSING_REQUIRED_CHECK")).toBe(true);
  });
  it("HOLD on mixed high-severity evidence", () => {
    const warn = parseFinding("contract_audit", "High severity finding: owner can pause transfers; contract source unverified.");
    const d = fuse([warn, finding("wash_trading"), finding("sanctions")]);
    expect(d.verdict).toBe("HOLD");
  });
  it("flags conflicts when one check fails and another passes", () => {
    const bad = parseFinding("wash_trading", "Wash trading detected: circular transfers.");
    const d = fuse([finding("contract_audit"), bad, finding("sanctions")]);
    expect(d.conflicts.length).toBeGreaterThan(0);
  });
});
