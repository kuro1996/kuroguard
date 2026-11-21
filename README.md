# KuroGuard — Pre-Flight Safety Gate for Agent Wallets

**Telegraph Hackathon Season II · Mission 14 (Web3 Native & DeFi) + 01 · Track: Apps & Agents**

Before an agent wallet executes *any* transaction, KuroGuard buys three
independent checks on the Telegraph network and decides **GO / HOLD / BLOCK**
under a published rubric — turning the operator's manual rules (a 100-point
project rubric + "confirm any suspicious transaction first") into an
autonomous machine that buys its own intelligence.

## Why this is not another listing gate

- **Skein** gates *listings* (is this token safe to list?).
  **KuroGuard gates *execution*** (is this transaction safe for *my* wallet
  to sign?). Different subject, different moment, different failure cost:
  a bad listing embarrasses an exchange; a bad signature drains a wallet.
- The gate runs **pre-flight**, on the exact tx the agent is about to send
  (chain, contract, value, calldata) — not on a token in the abstract.
- It fuses three *independent* miners, fails closed (**ABSTAIN** on any
  missing required check — never "assume safe"), and seals every decision
  with a recomputable verdict hash plus the Telegraph receipt and signal
  hash of each purchase, so a reviewer can re-verify every input at
  `GET /engine/v1/signal/<signal_hash>`.

## The three checks (one paid ask each, ≈ $0.01 test USDC)

| Check | Telegraph intent | What it answers |
|---|---|---|
| `contract_audit` | `SMART_CONTRACT_AUDIT_GENERAL` | Honeypot / drain / seizure powers, reentrancy, backdoor, proxy risk |
| `wash_trading` | `WASH_TRADING_DETECTION_GENERAL` | Circular transfers, self-dealing loops, artificial volume |
| `sanctions` | `SANCTIONS_SCREENING_MATCH_GENERAL` | OFAC SDN / EU / UN list match for the address |

## Verdicts

| Verdict | Meaning | Rule |
|---|---|---|
| **GO** | Execute | Score ≥ 80, all required checks answered, no blocker |
| **HOLD** | Human reviews | Score 50–79, or mixed/conflicting evidence |
| **BLOCK** | Do not sign | Score < 50, or any blocker (sanctions match, honeypot/drain/seizure, critical audit finding) |
| **ABSTAIN** | Retry later, never execute | A required check is missing/errored. Charged at upstream cost only. |

Score is a weighted 0–100 fusion (audit 45 / wash 30 / sanctions 25).
`riskBps`, `confidenceBps` and `coverage` qualify every verdict.

## Spend caps (hard, enforced before any signature)

- **$0.05 per ask** (`maxUusdcPerAsk`) — the Telegraph client refuses any
  402 challenge above it, and validates the challenge (chain, payee,
  amount, resource) before signing.
- **$1.00 total** across the ledger lifetime (`evidence/ledger.json`),
  enforced at quote time (against the worst-case run cost) AND at record
  time (a spend that would cross the cap is refused and left unrecorded).
- One idempotency key per gated tx per day — re-running the same gate
  replays the stored verdict instead of buying the checks again. The key
  covers chain + contract + value + recipient + calldata hash + label.
- A paid-but-failed ask is counted against the ledger and **never retried** —
  including a 402 that arrives *after* payment was sent.
- **Run budget:** a run costs ≈ $0.03 happy-path (3 asks × $0.01) and at
  most **$0.06 worst-case** (3 canonical + at most one $0.01 fallback ask
  per check). The quote states both numbers; prices are *assumed* $0.01/ask
  from a constant, not read from a live price catalogue — the real charge
  is validated against the per-ask cap at signing time.
- **Demo vs live are separate namespaces:** demo ($0, simulated) verdicts
  seal under `evidence/verdicts/demo/`; live (paid) verdicts under
  `evidence/verdicts/`. A demo verdict can never be replayed by a live
  run, and the CLI labels simulated/replayed verdicts on the first line.
  A quote-failure ABSTAIN is never cached — the next run retries.
- **Unverifiable payment evidence caps the verdict at HOLD:** a GO needs
  receipts and signals the node itself confirms (no receipt problems,
  signal `verified`).

## Quickstart

```bash
npm install
npm test                    # 51 unit tests (fusion, escrow challenge, ask flow, ledger, guard)
npm run demo                # $0 demo: clean contract → GO, honeypot → BLOCK
npm run new-burner          # fresh Sepolia burner → .env (mode 600, never committed)
# get Sepolia ETH for gas (PoW faucet or Google Cloud faucet — see below)
npm run fund                # mint 10 test USDC → approve → deposit 5 into escrow
npm run cli -- guard 56 0x...            # live paid gate
npm run cli -- guard 56 0x... --demo honeypot   # $0 simulated gate
npm run dev                 # demo panel on http://localhost:3000
```

## Funding the burner (testnet, $0 real money)

1. Fresh burner: `npm run new-burner` (key in `.env`, mode 600).
2. Sepolia ETH for gas — any public Sepolia faucet. The PoW faucet
   (`sepolia-faucet.pk910.de`) needs no login but requires a browser
   captcha + mining; the Google Cloud Web3 faucet needs a Google sign-in.
   Do **not** use the Alchemy faucet (needs ≥ 0.001 mainnet ETH).
3. `npm run fund` — mints 10 test USDC (`0xcc19…2Ae17`, mintable by
   anyone), approves the escrow Diamond (`0x3624…b99b`), deposits 5 USDC,
   and prints `effectiveBalance`. One full gate run costs ≈ $0.03
   (worst case $0.06 with fallbacks), so 5 USDC covers ~80–160 runs.

## How the Telegraph client works (own implementation)

Written from the public protocol behaviour, not a fork of any SDK:

1. `POST /engine/v1/ask {intent, query, params}` with no payment →
   the node answers **402** with an `accepts[]` list.
2. The client takes the `scheme: "escrow"` accept and **validates** it
   against pinned config (Sepolia `eip155:11155111`, payee, `N uUSDC`
   amount, resource `/v1/ask[/minerId]`, per-call cap). Anything that
   disagrees is refused — a challenge is untrusted input.
3. It fills the escrow message template, signs it with EIP-191
   (`personal_sign`), and re-POSTs with
   `X-PAYMENT: base64({x402Version: 2, scheme: "escrow", network,
   payload: {signature, authorization}})`.
4. The answer carries the receipt in the `x-payment-response` header
   (`receipt_hash`, `rail`, `payer`, `miner`, `amount_uusdc`) and a
   `signal_hash` in the body; the client cross-checks the receipt against
   what was signed and re-checks the signal with
   `GET /engine/v1/signal/<signal_hash>`.
5. Failures **after** `X-PAYMENT` is sent are never retried (the node may
   have billed them) — including a 402 refusal after payment, which is
   reported with the paid amount attached (`billing: "unknown"`) and
   counted against the ledger. Failures before payment are retried once.

## Known findings (see FINDINGS.md)

- **Routing weakness (documented, mitigated):** some intents route badly
  without an evaluator (e.g. issue #187: `SECURITY_REVIEW_GENERAL` always
  went to a miner that ignored the target). KuroGuard detects an
  unusable/irrelevant answer and retries **once** as a direct ask
  (`/engine/v1/ask/{minerId}`) to the first verified miner for that intent.
  The fallback answer must also be usable, or the check ABSTAINs.
  **Correction:** the research note named miner 5530 "Telegraph Verity"
  as a fallback — live lookup shows 5530 is `carr-faa`, serving only
  `CARRIER_SERVICEABILITY_GENERAL`. The fallback list in `src/config.ts`
  was built from the live intent miner lists instead.
- **Open item — escrow payee:** a generic GET 402 names payee
  `0x72a70e…` (a live Sepolia contract) rather than the Diamond.
  Verification 2026-11-22 (read-only): `0x72a7…` IS a live Telegraph
  Diamond (verified source, actively receiving `Deposit USDC`) — very
  likely the live escrow Diamond. But the unpaid-POST probe that would
  settle which payee the *live ask* challenge uses timed out unanswered
  and was not retried, so `TELEGRAPH_ESCROW_PAYEE` is still NOT set; the
  client fails closed on a payee mismatch. See FINDINGS.md §3/§7.
- **Review fixes (Milestone 1.1, 2026-11-22):** independent review
  `REVIEW-20261122.md` found 2 HIGH + 8 MEDIUM + 7 LOW issues; all H/M
  and L1–L3 are fixed in this tree (demo/live namespaces, post-payment
  402, single fallback + worst-case quote, HOLD on unverified receipts /
  signals, calldata in the idempotency key, no caching of quote ABSTAINs,
  negation-aware CLEAN parsing, atomic + fail-closed ledger, cap enforced
  at record time, trailing-newline-tolerant template, loopback-only
  server + `/api/guard` token, quote labelled as an assumption, unique
  ledger keys per ask). Tests grew 29 → 51, all passing; `tsc --noEmit`
  clean. See FINDINGS.md §8.

## Layout

```
src/
  telegraph.ts   own Telegraph client (x402 escrow, ask, signal verify)
  guard.ts       plan → quote → buy (3 parallel) → fuse → seal
  fusion.ts      findings → rubric score → GO/HOLD/BLOCK/ABSTAIN
  ledger.ts      spend caps + idempotency keys
  config.ts      network facts, intents, fallback miners, caps
  server.ts      demo panel API  ·  cli.ts  CLI
scripts/
  new-burner.ts  fresh burner → .env (600)
  fund.ts        mint → approve → deposit → effectiveBalance
  demo.ts        $0 two-case demo
test/            vitest: fusion, escrow challenge, ledger, guard (demo)
evidence/        verdict JSONs + ledger (local; verdicts contain no keys)
```

## Submission

- Hackathon: Telegraph Season II, deadline **1 Dec 2026 23:59 UTC**
  (= 2 Dec 06:59 WIB). 100% online, solo.
- Requires: GitHub user `kuro1996` to star
  `github.com/telegraphprotocol/bounties`, submit via the official H2
  site, demo video 2–5 min.
- Repo: `github.com/kuro1996/kuroguard` (MIT).

## Safety

Testnet only. The burner holds test USDC / Sepolia test ETH — never real
funds, never the operator's real wallet, never a seed phrase. No key is
committed (`.gitignore` blocks `.env`); the ledger and verdicts contain
no secrets.
