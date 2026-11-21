#!/usr/bin/env node
/**
 * fund — mint 10 test USDC, approve the escrow, deposit 5 USDC, verify.
 * (Same steps as the Telegraph tutorial's "Fund a burner", via viem.)
 *
 * Needs: KUROGUARD_PRIVATE_KEY in .env + Sepolia ETH for gas (~3 tx).
 * Test USDC is mintable by anyone; the escrow only accepts Telegraph's
 * own test USDC (0xcc19…2Ae17) — do NOT substitute Circle's faucet USDC.
 */
import { config as loadEnv } from "dotenv";
import { join } from "node:path";
loadEnv({ path: join(process.cwd(), ".env") });

import { createPublicClient, createWalletClient, formatUnits, http } from "viem";
import { sepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { TELEGRAPH } from "../src/config.js";

const USDC_ABI = [
  { name: "mint", type: "function", stateMutability: "nonpayable", inputs: [{ name: "to", type: "address" }, { name: "amount", type: "uint256" }], outputs: [] },
  { name: "approve", type: "function", stateMutability: "nonpayable", inputs: [{ name: "spender", type: "address" }, { name: "amount", type: "uint256" }], outputs: [{ type: "bool" }] },
  { name: "balanceOf", type: "function", stateMutability: "view", inputs: [{ name: "account", type: "address" }], outputs: [{ type: "uint256" }] },
] as const;

const DIAMOND_ABI = [
  { name: "depositUSDC", type: "function", stateMutability: "nonpayable", inputs: [{ name: "amount", type: "uint256" }], outputs: [] },
  { name: "effectiveBalance", type: "function", stateMutability: "view", inputs: [{ name: "account", type: "address" }], outputs: [{ type: "int256" }] },
] as const;

const MINT = 10_000_000n; // 10 test USDC (6 decimals)
const DEPOSIT = 5_000_000n; // 5 test USDC into escrow

async function main(): Promise<void> {
  const key = process.env.KUROGUARD_PRIVATE_KEY as `0x${string}` | undefined;
  if (!key) throw new Error("KUROGUARD_PRIVATE_KEY is not set — run `npm run new-burner` first.");
  const account = privateKeyToAccount(key);
  const pub = createPublicClient({ chain: sepolia, transport: http(TELEGRAPH.rpcUrl) });
  const wallet = createWalletClient({ account, chain: sepolia, transport: http(TELEGRAPH.rpcUrl) });
  console.log(`burner: ${account.address}`);

  const eth = await pub.getBalance({ address: account.address });
  console.log(`Sepolia ETH: ${formatUnits(eth, 18)}`);
  if (eth === 0n) throw new Error("No Sepolia ETH for gas. Claim some first: PoW faucet (no login) or Google Cloud Web3 faucet, then re-run.");

  const usdc = TELEGRAPH.usdc as `0x${string}`;
  const diamond = TELEGRAPH.diamond as `0x${string}`;

  const balBefore = (await pub.readContract({ address: usdc, abi: USDC_ABI, functionName: "balanceOf", args: [account.address] })) as bigint;
  if (balBefore < MINT) {
    const h1 = await wallet.writeContract({ address: usdc, abi: USDC_ABI, functionName: "mint", args: [account.address, MINT] });
    await pub.waitForTransactionReceipt({ hash: h1 });
    console.log(`minted 10 test USDC — ${h1}`);
  } else console.log(`already holds ${formatUnits(balBefore, 6)} test USDC — skipping mint`);

  const h2 = await wallet.writeContract({ address: usdc, abi: USDC_ABI, functionName: "approve", args: [diamond, DEPOSIT] });
  await pub.waitForTransactionReceipt({ hash: h2 });
  console.log(`approved escrow 5 USDC — ${h2}`);

  const h3 = await wallet.writeContract({ address: diamond, abi: DIAMOND_ABI, functionName: "depositUSDC", args: [DEPOSIT] });
  const rc = await pub.waitForTransactionReceipt({ hash: h3 });
  console.log(`deposited 5 USDC into escrow — ${h3} (status ${rc.status})`);

  const eff = (await pub.readContract({ address: diamond, abi: DIAMOND_ABI, functionName: "effectiveBalance", args: [account.address] })) as bigint;
  console.log(`escrow effectiveBalance: ${formatUnits(BigInt(eff), 6)} USDC`);
  if (eff < 1_000_000n) throw new Error("effectiveBalance below 1 USDC — deposit did not land.");
  console.log("Funded. A full guard run costs ~$0.03 test USDC — this balance covers ~160 runs.");
}

main().catch((e) => {
  console.error("fund failed:", e instanceof Error ? e.message : e);
  process.exit(1);
});
