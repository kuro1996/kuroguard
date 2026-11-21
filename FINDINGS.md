# KuroGuard — Findings (live, 2026-11-22)

Things found while building that change the plan, the code, or what a
reviewer should check. Each item names its evidence.

## 1. Miner 5530 is NOT "Telegraph Verity" (research-note correction)

- **Claim in the research note:** fallback via `telegraph_ask_miner` to
  "5530 Telegraph Verity".
- **Live check:** `GET /api/miners/5530` →
  `{"miner":{"registration_id":5530,"slug":"carr-faa",
  "supported_intents":["CARRIER_SERVICEABILITY_GENERAL"],…}}`.
  Miner 5530 serves only carrier serviceability. It cannot answer any of
  KuroGuard's three checks.
- **Action:** fallback miners in `src/config.ts` were taken from the live
  intent lists (`GET /engine/v1/intents/<intent>`, 22 Nov):
  - audit: 200001 GoPlus Security, 200002 Sourcify Verified Contracts,
    501 Telegraph Sentinel Risk Intelligence
  - wash: 73181 ZK Wash Trading Evidence, 7378 VerifyWire, 9002 TxLens
  - sanctions: 78004 OpenSanctions US OFAC Index, 78003 OFAC SDN XML,
    731149 ZK Official Sanctions Match
- **Note:** `/api/miners/{id}` returns "miner registration not found" for
  some ids that *do* appear in intent lists (501, 200001). The registration
  lookup is unreliable; KuroGuard treats an unresolvable miner id as
  "unverified", not as proof of mismatch.

## 2. SMART_CONTRACT_AUDIT_GENERAL is "registered", not "active"

- **Live check:** `GET /engine/v1/intents` → audit intent
  `lifecycle_state: "registered"`, reasons: "output schema: it has no
  response format, its own or its family's" / "input schema: no response
  format declares inputs".
- Wash (`active`) and sanctions (`active`) have adapters/evaluators; the
  audit intent does not. Canonical routing for the audit check is therefore
  weaker, and its answers arrive as free text with no response format —
  which is why `src/fusion.ts` parses answers with a negation-aware
  keyword heuristic instead of trusting a schema.
- **Mitigation:** same as finding 1 — one direct fallback ask to a
  verified audit miner when the canonical answer is unusable; ABSTAIN if
  it still fails.

## 3. Escrow payee discrepancy — OPEN, must resolve before the first paid ask

- **Evidence:** `GET /engine/v1/ask` returns 402 with an escrow accept
  whose `payTo` **and** message-template "Pay To" are
  `0x72a70e949362670bf8bcead24efc5b8f950aa08b`, not the escrow Diamond
  `0x3624EB012B5E998BB57B6bE6C9Cfc9c4bc5eb99b`.
- **On-chain check (read-only RPC, 22 Nov):** `0x72a7…` has bytecode (a
  live contract) and a small ETH balance; the Diamond also has bytecode.
  `0x72a7…` is plausibly Telegraph's settler/ledger contract.
- **Why it matters:** the signed EIP-191 authorisation pays `to` — if the
  client signs for the wrong payee, settlement fails (or worse, pays an
  address the operator never verified).
- **Status (updated 2026-11-22 evening):** an unpaid `POST /engine/v1/ask`
  probe — the call that would show which payee the *live ask* challenge
  uses (the GET 402 may be a generic gateway response, not the ask-specific
  challenge) — required operator approval and the approval timed out
  unanswered. **Not retried.** A second attempt on 2026-11-22 ~19:06 WIB
  also timed out (15 s, 0 bytes, approval unanswered) and was NOT retried
  again, per the standing order. The probe is still pending.
- **On-chain verification (read-only, 2026-11-22, $0) — 0x72a7… checks out
  as a live Telegraph Diamond:**
  - Etherscan Sepolia: contract named **"Diamond"**, compiler v0.8.30,
    verified source, ETH balance ~0.2, 985 transactions, active minutes
    before the check (latest block 12183696).
  - Sourcify v2: `runtimeMatch: "match"` (verified 2026-11-17).
  - Recent methods: `Deposit USDC` (from several distinct users — the
    escrow deposit entry point), `Register Miner`, `Update Miner`,
    `Register Wasm`, `Activate Entitlement`, `Publish Entitlement`,
    `Submit Epoch`, `Set Intent Volume`; internal transfers to
    `0x71cA4dF7a1931609C9060058B899fFdF79F384d0` (tiny ETH amounts).
  - Same Diamond proxy bytecode family as `0x3624…` (identical proxy
    prefix `6080604052361560e757…`, "Diamond: Function does not exist"
    fallback). `0x3624…`: 13,193 txns, 0 ETH, created 28 days ago via
    factory `0x329b9872ae2171bB9E0DA7556494d895D9f32d9e`; its latest 25
    txns show miner-registry calls but no `Deposit USDC`, while `0x72a7…`
    is the Diamond currently receiving deposits.
  - NOT established: the deployer/creation tx of `0x72a7…` (Etherscan's
    ContractCreator section did not render in the crawl), and the
    settlement-facet functions (Diamond facets are delegate-called and
    are not in the proxy ABI; the Sourcify file-tree endpoint 404'd).
    No public Telegraph doc names the settler address.
  - **Conclusion:** `0x72a7…` is very likely the live escrow Diamond and
    the correct `TELEGRAPH_ESCROW_PAYEE` — but the decisive evidence (the
    ask-specific POST challenge) is still missing, so the env var is
    **still NOT set**. The client keeps failing closed on mismatch.
- **Code response:** the client validates the payee against a configured
  value (default: the Diamond) and refuses anything else, with an error
  that names the observed address. `TELEGRAPH_ESCROW_PAYEE` overrides it
  only after the operator verifies the address is Telegraph's settler.
  Do not set an unverified payee.

## 4. PoW faucet needs a captcha to start a session

- **Evidence:** `GET /api/getFaucetConfig` →
  `modules.captcha: {provider: "custom", requiredForStart: true,
  requiredForClaim: false}`; PoW params `{a: "cryptonight", difficulty:
  11, powHashrateLimit: 1000}`; faucet wallet holds ~6.65 Sepolia ETH.
- A `POST /api/startSession` attempt from the VM also required operator
  approval, which timed out unanswered. **Not retried.**
- **Consequence:** Sepolia ETH for the burner cannot be obtained from the
  VM unattended. Paths that need a human/browser: solve the PoW faucet
  captcha in a browser and mine briefly, or claim via the Google Cloud
  Web3 faucet (Google sign-in). Both are documented in README § Funding.
- **No Sepolia ETH has been spent or received by the burner yet.**
  Burner `0x15007e68334A4E2ad66e126D5c6bDB9e90CED708`, balance 0.

## 5. What is verified live (22 Nov, no payment)

- Dev node `https://devnode.telegraphprotocol.com/engine/v1/intents` →
  HTTP 200, 136 canonical intents; all three KuroGuard intents present
  with live miners (audit 19, wash 17, sanctions 29).
- Test USDC `0xcc19…2Ae17` has bytecode with `ERC20: mint to the zero
  address` revert + EIP-3009 strings (mintable, x402-ready).
- Escrow Diamond `0x3624…b99b` has bytecode.
- `GET /engine/v1/signal/0x00…00` → `{"error":"signal not found"}`
  (endpoint live; unknown hashes 404 cleanly).
- Free quote path works end-to-end against the live node:
  `kuroguard quote 8453 0x4200…0006` → `ok: true`, 3 checks × $0.01.
- Demo gate: clean contract → **GO 100/100**; honeypot fixture →
  **BLOCK 29/100** (see `evidence/verdicts/demo/`).
- 51/51 unit tests pass; `tsc --noEmit` clean (verified independently
  2026-11-22 after the Milestone 1.1 fixes — the builder's earlier 29/29
  claim is now superseded by the 51-test suite, run in this session).

## 7. Payee verification, second pass (2026-11-22 evening, read-only, $0)

See §3 for the full evidence. Summary: `0x72a7…` verified as a live,
verified-source Telegraph Diamond actively receiving `Deposit USDC`;
the unpaid-POST probe timed out twice (approval unanswered, not retried);
deployer + settlement facets not enumerated. `TELEGRAPH_ESCROW_PAYEE`
still NOT set. Next step is a single unpaid-POST probe with operator
approval present — or the first live paid ask failing closed on the
mismatch, which is the safe default.

## 8. Independent-review fixes applied — Milestone 1.1 (2026-11-22)

Review `REVIEW-20261122.md` (2 HIGH + 8 MEDIUM + 7 LOW). Fixed in this
tree, with a test for each:

- **H1** — demo/live namespaces: demo seals to `evidence/verdicts/demo/`,
  live to `evidence/verdicts/`; replay requires the stored `simulated`
  flag to match the run mode, and legacy files without the flag replay
  for nobody. The two pre-existing demo verdicts were moved into `demo/`.
  CLI renders `[SIMULATED …]` / `[REPLAYED …]` on the first line.
  Test: demo-then-live same contract → live does NOT replay.
- **H2** — post-payment 402 passes the paid amount through
  (`billing: "unknown"`, counted in the ledger) and `"refused"` left
  `RETRYABLE`, so a paid-but-refused ask is never signed twice.
  Test: mock-fetch post-payment 402 → 2 HTTP calls, no retry.
- **M1** — fallback is exactly ONE ask (first verified miner only), the
  fallback answer must pass `answerUsable()`, a discarded canonical ask
  is still counted, and `quote()` budgets the worst case ($0.06/run)
  against the total cap. Test: mock-node end-to-end, 3 paid fallbacks,
  $0.06 total, no 2nd/3rd fallback miner ever called.
- **M2** — receipt problems or signal `missing`/`mismatch` cap the
  verdict at HOLD (score ≤ 79) with `RECEIPT_UNVERIFIED` /
  `SIGNAL_UNVERIFIED` reasons; a GO needs verified payment evidence.
- **M3** — idempotency key now hashes calldata and includes the label.
- **M4** — a quote-failure ABSTAIN is returned unsealed
  (`cacheable: false`); nothing is written, the next run retries.
- **M5** — CLEAN patterns are tested on negation-stripped text (plus
  raw-text checks only for patterns that ARE negations), and an explicit
  `not/never safe|clean` guard blocks negated passes.
  Tests: `"not safe"`, `"not clean"`, `"never safe"` → not PASS.
- **M6** — ledger writes are atomic (temp file + rename); a corrupt
  ledger throws `LedgerCorruptError` (fail closed) instead of resetting
  the cap to $0.
- **M7** — `recordSpend()` enforces the total cap at record time
  (`SpendCapError`, ledger untouched); the quote already checks the
  worst-case cost.
- **M8** — `parseTemplate()` trims trailing blank lines before parsing.
- **L1** — server binds `127.0.0.1` only; `/api/guard` requires
  `x-kuroguard-token` when `KUROGUARD_API_TOKEN` is set (warns on
  startup when it is not).
- **L2** — `quote()` returns `priceAssumption` labelling the $0.01/ask
  figure as an assumption from a constant, plus `maxPriceUusdc` /
  `fallbackBudgetUusdc`.
- **L3** — every ledger entry gets a unique key (hash of
  check/intent/receipt/signal/amount/timestamp), never `"ask"` /
  `"paid-failure"`.
- **L7** (bonus) — a replay returns the ORIGINAL events, not `[]`;
  the `"done"` event is now emitted before sealing so the sealed log is
  complete.
- L4–L6 were NOT changed (fail-closed asset check, UNKNOWN-never-
  produced, fund.ts receipt checks — documented limitations, no live
  impact before the first paid run).

Verification in this session: `npm test` **51/51 pass** (was 29),
`tsc --noEmit` clean, `npm run demo` still GO 100 / BLOCK 29 with the
SIMULATED banner. No payment was made, no env payee was set, nothing
was submitted.

## 9. What is NOT yet verified (needs the funded burner)

- A real paid ask end-to-end: 402 → sign → X-PAYMENT → receipt →
  `signal_hash` → `GET /engine/v1/signal/<hash>` = verified.
- The exact live ask-challenge payee (finding 3).
- Miner answer quality on real contracts (clean vs honeypot) — the fusion
  parser is tuned on the miners' documented behaviour, not on live
  answers yet; expect a tuning pass after the first live runs.
- Indonesia payout eligibility (hackathon rules: cash prizes subject to
  "published country eligibility, identity, and tax checks" — no
  Indonesia confirmation found in the rules page). Build risk only, not
  a build blocker.
