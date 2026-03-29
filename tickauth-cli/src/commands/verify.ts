import { type TickAuthMode, type TickAuthProof, verifyProof } from "@nextera.one/tickauth-sdk";
import { Command } from "commander";
import chalk from "chalk";

import { readJsonFile } from "./fsutil";

type ReplayScope = "nonce" | "challenge" | "proof";

const validReplayScopes: ReplayScope[] = ["nonce", "challenge", "proof"];
const validModes: TickAuthMode[] = [
  "PASSKEY",
  "ATTESTED",
  "PRESENCE",
  "OFFLINE",
  "AGENT",
];

export const verifyCommand = new Command("verify")
  .description("Verify a TickAuth proof")
  .requiredOption("-p, --proof <path>", "Path to proof JSON file")
  .option(
    "--pubkey <hex>",
    "Public key to verify against (if different from proof)",
  )
  .option(
    "--allow-embedded-key",
    "Allow using proof-embedded public key when no trusted --pubkey is provided",
  )
  .option(
    "--expected-action <action>",
    "Require proof.challenge.action to match this action",
  )
  .option(
    "--expected-mode <mode>",
    "Require proof.challenge.mode to match this mode",
  )
  .option(
    "--replay-scope <scope>",
    "Replay uniqueness scope: nonce|challenge|proof",
    "proof",
  )
  .option("--skip-replay", "Skip replay check (not recommended)")
  .action(async (options: Record<string, unknown>) => {
    try {
      const proof = readJsonFile<TickAuthProof>(String(options.proof));
      const expectedMode = options.expectedMode
        ? (String(options.expectedMode).toUpperCase() as TickAuthMode)
        : undefined;
      const replayScope = String(options.replayScope) as ReplayScope;

      if (expectedMode && !validModes.includes(expectedMode)) {
        console.error(chalk.red(`Invalid expected mode: ${expectedMode}`));
        console.error(`Valid modes: ${validModes.join(", ")}`);
        process.exit(1);
      }

      if (!validReplayScopes.includes(replayScope)) {
        console.error(chalk.red(`Invalid replay scope: ${replayScope}`));
        console.error(`Valid replay scopes: ${validReplayScopes.join(", ")}`);
        process.exit(1);
      }

      const verifyOptions: Record<string, unknown> = {
        publicKeyHex: options.pubkey ? String(options.pubkey) : undefined,
        requireTrustedKey: !Boolean(options.allowEmbeddedKey),
        expectedAction: options.expectedAction
          ? String(options.expectedAction)
          : undefined,
        expectedMode,
        replayScope,
        skipReplayCheck: Boolean(options.skipReplay),
      };

      const result = await verifyProof(
        proof,
        verifyOptions as Parameters<typeof verifyProof>[1],
      );

      if (result.ok) {
        console.log(chalk.green("✅ Proof verified successfully"));
        if (result.capsule_id) {
          console.log(chalk.bold("Capsule ID:"), chalk.cyan(result.capsule_id));
        }
        console.log(
          chalk.dim("Action:  "),
          result.clearance?.action ?? result.capsule?.intent.action,
        );
        console.log(
          chalk.dim("Mode:    "),
          result.clearance?.mode ?? result.capsule?.mode,
        );
        console.log(
          chalk.dim("Status:  "),
          chalk.green(result.capsule?.verification.status ?? "approved"),
        );
        if (result.clearance?.expiresAt) {
          console.log(chalk.dim("Expires: "), result.clearance.expiresAt);
        }
      } else {
        console.log(chalk.red("❌ Verification failed"));
        if (result.capsule_id) {
          console.log(
            chalk.bold("Capsule ID:"),
            chalk.yellow(result.capsule_id),
          );
        }
        console.log(
          chalk.dim("Status:  "),
          chalk.red(result.capsule?.verification.status ?? "denied"),
        );
        console.log(chalk.dim("Error:   "), result.error);
        console.log(chalk.dim("Message: "), result.message);
        process.exit(1);
      }
    } catch (err) {
      console.error(
        chalk.red("Error verifying proof:"),
        (err as Error).message,
      );
      process.exit(1);
    }
  });
