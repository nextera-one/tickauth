import { Command } from 'commander';
import chalk from 'chalk';

import { createChallenge, type TickAuthMode } from '@nextera.one/tickauth-sdk';
import { writeJsonFile } from './fsutil';

const validModes: TickAuthMode[] = ['PASSKEY', 'ATTESTED', 'PRESENCE', 'OFFLINE', 'AGENT'];

export const challengeCommand = new Command('challenge')
  .description('Create a temporal authorization challenge')
  .requiredOption('-a, --action <action>', 'Action to authorize (e.g., funds.transfer)')
  .option('-m, --mode <mode>', 'TickAuth mode', 'PRESENCE')
  .option('-w, --window <ms>', 'Window duration in milliseconds', '30000')
  .option('-r, --rp <rp>', 'Relying party identifier')
  .option('-s, --sub <sub>', 'Subject identifier')
  .option('-o, --out <path>', 'Output file (default: stdout)')
  .action((options) => {
    const mode = String(options.mode).toUpperCase() as TickAuthMode;
    if (!validModes.includes(mode)) {
      console.error(chalk.red(`Invalid mode: ${mode}`));
      console.error(`Valid modes: ${validModes.join(', ')}`);
      process.exit(1);
    }

    const challenge = createChallenge({
      action: String(options.action),
      mode,
      windowMs: parseInt(options.window, 10),
      rp: options.rp ? String(options.rp) : undefined,
      sub: options.sub ? String(options.sub) : undefined,
    });

    if (options.out) {
      writeJsonFile(String(options.out), challenge);
      console.log(chalk.green('✅ Challenge created'));
      console.log(`Wrote: ${options.out}`);
    } else {
      console.log(JSON.stringify(challenge, null, 2));
    }
  });
