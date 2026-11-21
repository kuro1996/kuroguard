/**
 * KuroGuard configuration — all network facts verified live 2026-11-22.
 *
 * Telegraph testnet (Ethereum Sepolia, chain 11155111):
 *  - dev node: https://devnode.telegraphprotocol.com
 *  - test USDC (mintable by anyone): 0xcc194e1a843B658526D0D5C431f670028582Ae17
 *  - escrow Diamond: 0x3624EB012B5E998BB57B6bE6C9Cfc9c4bc5eb99b
 *  - one ask ≈ $0.01 test USDC (10_000 uUSDC), charged to escrow balance.
 *
 * Spend caps (hard, enforced before any signature):
 *  - MAX_UUSDC_PER_ASK = 50_000  ($0.05 per ask)
 *  - MAX_UUSDC_TOTAL   = 1_000_000 ($1.00 total across the ledger lifetime)
 * A guard run buys 3 asks ≈ $0.03, so the total cap allows ~33 full runs.
 */

export const TELEGRAPH = {
  nodeUrl: "https://devnode.telegraphprotocol.com",
  caip2: "eip155:11155111",
  chainId: 11155111,
  diamond: "0x3624EB012B5E998BB57B6bE6C9Cfc9c4bc5eb99b",
  usdc: "0xcc194e1a843B658526D0D5C431f670028582Ae17",
  rpcUrl: "https://ethereum-sepolia-rpc.publicnode.com",
  /**
   * Who an escrow payment authorisation pays. Default = the escrow Diamond
   * (per the Telegraph docs / SDK pattern). OPEN ITEM (2026-11-22): a GET
   * probe of /engine/v1/ask returned a generic 402 whose escrow accept
   * names payee 0x72a70e949362670bf8bcead24efc5b8f950aa08b (a live contract
   * on Sepolia) instead of the Diamond. The POST ask challenge may differ
   * from that generic 402 — the unpaid-POST probe needs operator approval
   * and is still pending. If the live POST challenge names 0x72a7…,
   * set TELEGRAPH_ESCROW_PAYEE=0x72a70e949362670bf8bcead24efc5b8f950aa08b
   * after verifying that address is Telegraph's settler; never set an
   * unverified payee. See FINDINGS.md.
   */
  payee: "0x3624EB012B5E998BB57B6bE6C9Cfc9c4bc5eb99b",
} as const;

/** The three checks KuroGuard buys for every planned transaction. */
export const CHECKS = [
  {
    id: "contract_audit",
    intent: "SMART_CONTRACT_AUDIT_GENERAL",
    // Intent lifecycle (live 2026-11-22): "registered" — it has no response
    // format of its own, so canonical routing is weaker here than for the
    // other two intents. Fallback miners below are the mitigation.
    weight: 45,
    required: true,
  },
  {
    id: "wash_trading",
    intent: "WASH_TRADING_DETECTION_GENERAL",
    weight: 30,
    required: true,
  },
  {
    id: "sanctions",
    intent: "SANCTIONS_SCREENING_MATCH_GENERAL",
    weight: 25,
    required: true,
  },
] as const;

export type CheckId = (typeof CHECKS)[number]["id"];

/**
 * Direct-ask fallback miners, taken from the live intent miner lists
 * (GET /engine/v1/intents/<intent>, 2026-11-22). Used only when a canonical
 * ask comes back irrelevant, incompatible, or empty — the known routing
 * weakness documented in FINDINGS.md.
 *
 * CORRECTION (2026-11-22): the research note named miner 5530 "Telegraph
 * Verity" as a fallback. Live lookup shows 5530 is slug `carr-faa` and serves
 * only CARRIER_SERVICEABILITY_GENERAL. Do not use it. The miners below are
 * the ones actually registered for each intent.
 */
export const FALLBACK_MINERS: Record<CheckId, { id: string; name: string }[]> = {
  contract_audit: [
    { id: "200001", name: "GoPlus Security" },
    { id: "200002", name: "Sourcify Verified Contracts" },
    { id: "501", name: "Telegraph Sentinel Risk Intelligence" },
  ],
  wash_trading: [
    { id: "73181", name: "ZK Wash Trading Evidence" },
    { id: "7378", name: "VerifyWire Wash Trading Detection" },
    { id: "9002", name: "TxLens" },
  ],
  sanctions: [
    { id: "78004", name: "OpenSanctions US OFAC Index" },
    { id: "78003", name: "OFAC SDN XML" },
    { id: "731149", name: "ZK Official Sanctions Match" },
  ],
};

/** Hard spend caps, in micro-USDC (1 USDC = 1_000_000 uUSDC). */
export const SPEND = {
  maxUusdcPerAsk: 50_000, // $0.05 per ask
  maxUusdcTotal: 1_000_000, // $1.00 total, ledger lifetime
  askPriceUusdc: 10_000, // $0.01 — the price the node quotes per ask
} as const;

/** Guard policy: pre-flight gate for agent-wallet transactions. */
export const POLICY = {
  id: "preflight-gate",
  version: "0.1.0",
  /** Verdict thresholds on the fused 0–100 safety score. */
  goAt: 80,
  holdAt: 50,
  /** Fail closed: a missing required check forces ABSTAIN, never GO. */
  abstainOnMissingRequired: true,
  /** Ask timeouts. */
  askTimeoutMs: 60_000,
  signalVerifyTimeoutMs: 10_000,
} as const;

/** Known-bad contract used by the BLOCK test case (see test/guard.test.ts). */
export const KNOWN_BAD = {
  // Backdoor Pass — owner can seize any minted NFT via ambil().
  // Documented in the operator's own records; used only as a test fixture.
  address: "0x9c6a008f73a1d1941f4763b88c6ee8c8e4ef8b0a",
  reason: "owner-controlled seizure function ambil()",
} as const;

export function env(name: string, fallback = ""): string {
  return process.env[name] ?? fallback;
}
