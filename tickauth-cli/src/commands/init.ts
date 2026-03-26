import { Command } from 'commander';
import chalk from 'chalk';

import { generateEd25519Keypair, bytesToHex } from '@nextera.one/tickauth-sdk';
import { writeJsonFile } from './fsutil';

export const initCommand = new Command('init')
  .description('Create a TickAuth identity keypair (ed25519)')
  .option(
    '-o, --out <path>',
    'Output path for identity JSON',
    './.tickauth/identity.json',
  )
  .option('--kid <kid>', 'Key id to embed in signatures', 'kid:local')
  .action(async (options) => {
    const { privateKey, publicKey } = await generateEd25519Keypair();

    const identity = {
      alg: 'ed25519',
      kid: String(options.kid),
      privateKeyHex: bytesToHex(privateKey),
      publicKeyHex: bytesToHex(publicKey),
      createdAt: new Date().toISOString(),
    };

    writeJsonFile(String(options.out), identity);

    console.log(chalk.green('✅ TickAuth identity created'));
    console.log(`Wrote: ${options.out}`);
    console.log(chalk.dim(`Public key: ${identity.publicKeyHex.slice(0, 16)}...`));
  });
