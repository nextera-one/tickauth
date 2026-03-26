import { Command } from 'commander';
import chalk from 'chalk';

import { signChallenge, type TickAuthChallenge, type TickAuthIdentity } from '@nextera.one/tickauth-sdk';
import { readJsonFile, writeJsonFile } from './fsutil';

export const signCommand = new Command('sign')
  .description('Sign a challenge with an identity to create a proof')
  .requiredOption('-c, --challenge <path>', 'Path to challenge JSON file')
  .option(
    '-i, --identity <path>',
    'Path to identity JSON file',
    './.tickauth/identity.json',
  )
  .option('-o, --out <path>', 'Output file (default: stdout)')
  .action(async (options) => {
    try {
      const challenge = readJsonFile<TickAuthChallenge>(String(options.challenge));
      const identity = readJsonFile<TickAuthIdentity>(String(options.identity));

      const proof = await signChallenge(challenge, identity);

      if (options.out) {
        writeJsonFile(String(options.out), proof);
        console.log(chalk.green('✅ Proof created'));
        console.log(`Wrote: ${options.out}`);
      } else {
        console.log(JSON.stringify(proof, null, 2));
      }
    } catch (err) {
      console.error(chalk.red('Error signing challenge:'), (err as Error).message);
      process.exit(1);
    }
  });
