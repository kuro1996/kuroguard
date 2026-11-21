#!/usr/bin/env node
/**
 * new-burner — generate a FRESH burner wallet for KuroGuard's Telegraph
 * escrow payments and write it to .env (mode 600).
 *
 * The burner holds ONLY test USDC / Sepolia test ETH. It is never the
 * operator's real wallet, never holds real funds, and its key is never
 * committed (see .gitignore) and never printed in full.
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { chmodSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const envPath = join(process.cwd(), ".env");
if (existsSync(envPath)) {
  console.error(".env already exists — refusing to overwrite. Delete it first if you really want a new burner.");
  process.exit(1);
}
const key = generatePrivateKey();
const account = privateKeyToAccount(key);
writeFileSync(envPath, `# KuroGuard burner — TESTNET ONLY (Sepolia). Never put a real wallet key here.\nKUROGUARD_PRIVATE_KEY=${key}\nKUROGUARD_ADDRESS=${account.address}\n`, "utf8");
chmodSync(envPath, 0o600);
console.log(`burner address: ${account.address}`);
console.log(".env written (mode 600). Next: get Sepolia ETH for gas (PoW faucet or Google Cloud faucet), then run: npm run fund");
