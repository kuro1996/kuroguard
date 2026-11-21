# KuroGuard — Submission Checklist (Telegraph Hackathon Season II)

Deadline: **1 Dec 2026 23:59 UTC = 2 Dec 06:59 WIB** · Track: Apps & Agents
($3,000) · Mission 14 (utama) + 01 · 100% online, solo.

## Build status (22 Nov 2026 ~01:50 WIB)

- [x] Repo scaffolded, TypeScript + Node 20+, own Telegraph client
- [x] Guard engine: 3 parallel asks, fusion rubric, GO/HOLD/BLOCK/ABSTAIN
- [x] Spend caps ($0.05/ask, $1.00 total), idempotency, ledger
- [x] Demo mode ($0): clean → GO 100/100, honeypot → BLOCK 29/100
- [x] 29/29 unit tests pass, `tsc` clean
- [x] Free live quote verified against the dev node (3 × $0.01)
- [x] Burner wallet generated (`.env` mode 600, never committed)
- [ ] **BLOCKED: Sepolia ETH for the burner (balance 0)** — needs Bos in a
      browser: PoW faucet (captcha + mining) or Google Cloud Web3 faucet
- [ ] **PENDING APPROVAL: unpaid POST /engine/v1/ask probe** (settles the
      escrow-payee question in FINDINGS.md §3) — approval timed out, not
      retried
- [ ] First live paid ask (3 receipts + signal verification) — after funding
- [ ] 2-case live verification (clean GO vs honeypot BLOCK) + evidence pack
- [ ] Demo video 2–5 min
- [ ] 3 public updates on different dates (X @KhurotaS, tag @Telegraphprotoc)
      + evidence an independent developer tried it (20 pts organic growth)
- [ ] Star `github.com/telegraphprotocol/bounties` as **kuro1996** (Bos)
- [ ] Submit via the official H2 site (Bos / per auto-submit authority)

## Scoring target (≥70/100, technical ≥24/35)

- Technical 35: own x402-escrow client, fail-closed fusion, caps,
  idempotency, verifiable receipts/signals, tests.
- Commercial 25: prevents wallet drains pre-signature — the costliest
  failure mode for agent wallets; every agent wallet is a user.
- Reproducibility 5: one-command demo, evidence JSONs, published verdict
  hashes.
- Integration 5: 3 canonical intents, escrow rail, signal verification.
- Organic growth 20: partial at best for a solo entry — 3 public updates
  + independent trial is the plan.

## Evidence to collect before submit

- `evidence/verdicts/*.json` — live GO + live BLOCK runs
- `evidence/ledger.json` — every paid ask + receipt hash
- `GET /engine/v1/signal/<hash>` outputs for all 6+ signals
- Escrow funding tx hashes (mint / approve / deposit)
- Demo video link (2–5 min: input → 3 purchases → verdict → proof)
