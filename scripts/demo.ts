#!/usr/bin/env node
/**
 * demo — the 2–5 minute hackathon demo, $0, no wallet needed.
 * Runs the gate twice (clean contract → GO, honeypot → BLOCK) with
 * simulated miner answers, and prints the verdicts + evidence paths.
 */
import { KuroGuard, renderVerdict } from "../src/guard.js";
import { TelegraphClient, TESTNET } from "../src/telegraph.js";
import { SPEND } from "../src/config.js";

const client = new TelegraphClient({ network: TESTNET, maxUusdcPerCall: SPEND.maxUusdcPerAsk });
const guard = new KuroGuard({ client, demo: true, demoScenario: "clean" });

console.log("=== KuroGuard demo — case 1: clean contract (WETH on Base) ===");
const clean = await guard.guard({ chainId: 8453, chainName: "base", contract: "0x4200000000000000000000000000000000000006", value: "0", label: "WETH" });
console.log(renderVerdict(clean));

const guard2 = new KuroGuard({ client, demo: true, demoScenario: "honeypot" });
console.log("\n=== case 2: honeypot / drainer ===");
const bad = await guard2.guard({ chainId: 56, chainName: "bsc", contract: "0x9c6a008f73a1d1941f4763b88c6ee8c8e4ef8b0a", value: "0", label: "Backdoor Pass (known-bad fixture)" });
console.log(renderVerdict(bad));
console.log("\nDemo verdicts saved under evidence/verdicts/. Live (paid) runs: fund the burner, then `npm run cli -- guard <chainId> <contract>`.");
