import { Command } from 'commander';
import chalk from 'chalk';

import { verifyProof, type TickAuthProof } from '@nextera.one/tickauth-sdk';
import { readJsonFile } from './fsutil';

export const verifyCommand = new Command('verify')
  .description('Verify a TickAuth proof')
  .requiredOption('-p, --proof <path>', 'Path to proof JSON file')
  .option('--pubkey <hex>', 'Public key to verify against (if different from proof)')
  .option('--skip-replay', 'Skip replay check (not recommended)')
  .action(async (options) => {
    try {
      const proof = readJsonFile<TickAuthProof>(String(options.proof));

      const result = await verifyProof(proof, {
        publicKeyHex: options.pubkey ? String(options.pubkey) : undefined,
        skipReplayCheck: Boolean(options.skipReplay),
      });

      if (result.ok) {
        console.log(chalk.green('✅ Proof verified successfully'));
        if (result.capsule_id) {
          console.log(chalk.bold('Capsule ID:'), chalk.cyan(result.capsule_id));
        }
        console.log(chalk.dim('Action:  '), result.clearance?.action ?? result.capsule?.intent.action);
        console.log(chalk.dim('Mode:    '), result.clearance?.mode ?? result.capsule?.mode);
        console.log(chalk.dim('Status:  '), chalk.green(result.capsule?.verification.status ?? 'approved'));
        if (result.clearance?.expiresAt) {
          console.log(chalk.dim('Expires: '), result.clearance.expiresAt);
        }
      } else {
        console.log(chalk.red('❌ Verification failed'));
        if (result.capsule_id) {
          console.log(chalk.bold('Capsule ID:'), chalk.yellow(result.capsule_id));
        }
        console.log(chalk.dim('Status:  '), chalk.red(result.capsule?.verification.status ?? 'denied'));
        console.log(chalk.dim('Error:   '), result.error);
        console.log(chalk.dim('Message: '), result.message);
        process.exit(1);
      }
    } catch (err) {
      console.error(chalk.red('Error verifying proof:'), (err as Error).message);
      process.exit(1);
    }
  });
