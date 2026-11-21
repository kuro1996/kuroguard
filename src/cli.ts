#!/usr/bin/env node
/**
 * kuroguard CLI — pre-flight safety gate for agent-wallet transactions.
 *
 *   kuroguard guard <chainId> <contract> [--value 0] [--to 0x..] [--label x] [--demo clean|honeypot]
 *   kuroguard quote <chainId> <contract>
 *   kuroguard balance
 *   kuroguard verify <signal_hash>
 *   kuroguard spend
 *
 * Paid runs need a funded burner: KUROGUARD_PRIVATE_KEY in .env (mode 600).
 * --demo runs the whole gate with simulated miner answers and spends $0.
 * Exit code: 0 GO · 1 BLOCK · 2 HOLD · 3 ABSTAIN · 4 usage/config error.
 */
import { config as loadEnv } from "dotenv";
import { readFileSync } from "node:fs";
import { join } from "node:path";

process.chdir(new URL("..", import.meta.url).pathname);
loadEnv({ path: join(process.cwd(), ".env") });

import { SPEND, TELEGRAPH } from "./config.js";
import { KuroGuard, renderVerdict, type TxPlan } from "./guard.js";
import { loadLedger, usdc } from "./ledger.js";
import { TelegraphClient, TESTNET, viemSigner } from "./telegraph.js";

const CHAIN_NAMES: Record<number, string> = { 1: "ethereum", 56: "bsc", 8453: "base", 11155111: "sepolia" };

function usage(): never {
  console.error(`usage:
  kuroguard guard <chainId> <contract> [--value 0] [--to 0x..] [--label text] [--demo clean|honeypot]
  kuroguard quote <chainId> <contract>
  kuroguard balance
  kuroguard verify <signal_hash>
  kuroguard spend`);
  process.exit(4);
}

function parseArgs(argv: string[]): { cmd: string; positional: string[]; flags: Record<string, string> } {
  const [cmd, ...rest] = argv;
  const positional: string[] = [];
  const flags: Record<string, string> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = rest[i + 1];
      if (next && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else flags[key] = "true";
    } else positional.push(a);
  }
  return { cmd, positional, flags };
}

function makeClient(demo: boolean): TelegraphClient {
  const key = process.env.KUROGUARD_PRIVATE_KEY;
  if (!key && !demo) {
    console.error("KUROGUARD_PRIVATE_KEY is not set (.env). Run `npm run new-burner` then `npm run fund`, or use --demo for a $0 simulated run.");
    process.exit(4);
  }
  return new TelegraphClient({
    network: TESTNET,
    signer: key ? viemSigner(key as `0x${string}`) : undefined,
    maxUusdcPerCall: SPEND.maxUusdcPerAsk,
  });
}

function txFrom(positional: string[], flags: Record<string, string>): TxPlan {
  const chainId = Number(positional[0]);
  const contract = positional[1];
  if (!Number.isInteger(chainId) || !/^0x[0-9a-fA-F]{40}$/.test(contract ?? "")) usage();
  return {
    chainId,
    chainName: CHAIN_NAMES[chainId] ?? `chain-${chainId}`,
    contract: contract.toLowerCase(),
    to: flags.to,
    value: flags.value ?? "0",
    label: flags.label,
  };
}

async function main(): Promise<void> {
  const { cmd, positional, flags } = parseArgs(process.argv.slice(2));
  if (!cmd) usage();

  if (cmd === "balance") {
    const key = process.env.KUROGUARD_PRIVATE_KEY;
    if (!key) {
      console.error("KUROGUARD_PRIVATE_KEY is not set.");
      process.exit(4);
    }
    const { createPublicClient, http, formatEther, formatUnits } = await import("viem");
    const { sepolia } = await import("viem/chains");
    const { erc20Abi } = await import("viem");
    const client = createPublicClient({ chain: sepolia, transport: http(TELEGRAPH.rpcUrl) });
    const account = viemSigner(key as `0x${string}`);
    const [eth, usdcBal, escrow] = await Promise.all([
      client.getBalance({ address: account.address as `0x${string}` }),
      client.readContract({ address: TELEGRAPH.usdc as `0x${string}`, abi: erc20Abi, functionName: "balanceOf", args: [account.address as `0x${string}`] }),
      client.readContract({
        address: TELEGRAPH.diamond as `0x${string}`,
        abi: [{ name: "effectiveBalance", type: "function", stateMutability: "view", inputs: [{ name: "account", type: "address" }], outputs: [{ type: "int256" }] }] as const,
        functionName: "effectiveBalance",
        args: [account.address as `0x${string}`],
      }),
    ]);
    console.log(`burner: ${account.address}`);
    console.log(`Sepolia ETH: ${formatEther(eth)}`);
    console.log(`test USDC balance: ${formatUnits(usdcBal as bigint, 6)}`);
    console.log(`escrow effectiveBalance: ${formatUnits(BigInt(escrow as unknown as bigint), 6)} USDC`);
    return;
  }

  if (cmd === "spend") {
    const ledger = loadLedger();
    console.log(`spent: ${usdc(ledger.totalUusdc)} (${ledger.totalUusdc} uUSDC) across ${ledger.entries.length} paid asks`);
    console.log(`remaining: ${usdc(SPEND.maxUusdcTotal - ledger.totalUusdc)} of ${usdc(SPEND.maxUusdcTotal)} total cap`);
    return;
  }

  if (cmd === "verify") {
    const hash = positional[0];
    if (!/^0x[0-9a-fA-F]{64}$/.test(hash ?? "")) usage();
    const client = makeClient(true);
    const status = await client.verifySignal(hash);
    const signal = status === "verified" ? await client.getSignal(hash) : null;
    console.log(`signal ${hash}: ${status}`);
    if (signal) console.log(JSON.stringify(signal, null, 2).slice(0, 2000));
    process.exit(status === "verified" ? 0 : 1);
  }

  if (cmd === "quote") {
    const tx = txFrom(positional, flags);
    const client = makeClient(true);
    const guard = new KuroGuard({ client });
    const q = await guard.quote(tx);
    console.log(JSON.stringify(q, null, 2));
    process.exit(q.ok ? 0 : 1);
  }

  if (cmd === "guard") {
    const tx = txFrom(positional, flags);
    const demo = flags.demo;
    if (demo && demo !== "clean" && demo !== "honeypot") usage();
    const client = makeClient(!!demo);
    const guard = new KuroGuard({
      client,
      demo: !!demo,
      demoScenario: (demo as "clean" | "honeypot") || "clean",
      onEvent: (e) => {
        if (e.type === "purchase") console.log(`  paid ${(e.data as { check: string }).check} — see evidence/`);
        if (e.type === "fallback") console.log(`  fallback: ${(e.data as { check: string }).check} → miner ${(e.data as { miner: string }).miner}`);
      },
    });
    console.log(`KuroGuard pre-flight gate — ${tx.chainName} (${tx.chainId}) ${tx.contract}${demo ? ` [DEMO ${demo} — simulated answers, $0 spent]` : ""}`);
    const run = await guard.guard(tx);
    console.log(renderVerdict(run));
    console.log(`evidence: evidence/verdicts/${run.idempotencyKey}.json`);
    process.exit(run.decision.verdict === "GO" ? 0 : run.decision.verdict === "BLOCK" ? 1 : run.decision.verdict === "HOLD" ? 2 : 3);
  }

  usage();
}

main().catch((e) => {
  console.error("kuroguard failed:", e instanceof Error ? e.message : e);
  process.exit(4);
});
