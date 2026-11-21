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
- **Status:** an unpaid `POST /engine/v1/ask` probe — the call that would
  show which payee the *live ask* challenge uses (the GET 402 may be a
  generic gateway response, not the ask-specific challenge) — required
  operator approval and the approval timed out unanswered. **Not retried.**
  The probe is pending.
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
  **BLOCK 29/100** (see `evidence/verdicts/`).
- 29/29 unit tests pass; `tsc --noEmit` clean.

## 6. What is NOT yet verified (needs the funded burner)

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
