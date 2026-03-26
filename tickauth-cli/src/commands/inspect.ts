import { Command } from 'commander';
import chalk from 'chalk';
import { readJsonFile } from './fsutil';

export const inspectCommand = new Command('inspect')
  .description('Inspect and decode a TickAuth proof or challenge file')
  .argument('<file>', 'Path to JSON file')
  .action((file) => {
    try {
      const data = readJsonFile(file) as any;
      
      console.log(chalk.bold(`\nInspecting: ${file}\n`));

      // Identify type
      if (data.v === 1 && data.sig && data.challenge) {
        console.log(chalk.bgGreen.black(' TYPE: PROOF '));
        console.log(chalk.dim('Signed TickAuth Proof\n'));
        
        console.log(`${chalk.bold('Tick')}:      ${chalk.yellow(data.tick)}`);
        console.log(`${chalk.bold('Signed At')}: ${data.signedAt}`);
        console.log(`${chalk.bold('Signer')}:    ${chalk.cyan(data.sig.publicKeyHex.slice(0, 16) + '...')}`);
        
        console.log(chalk.gray('\n--- Challenge ---'));
        console.log(`${chalk.bold('ID')}:        ${data.challenge.id}`);
        console.log(`${chalk.bold('Action')}:    ${data.challenge.action}`);
        console.log(`${chalk.bold('Mode')}:      ${chalk.magenta(data.challenge.mode)}`);
        
      } else if (data.v === 1 && data.window && data.nonce) {
        console.log(chalk.bgBlue.black(' TYPE: CHALLENGE '));
        console.log(chalk.dim('Unsigned TickAuth Challenge\n'));
        
        console.log(`${chalk.bold('ID')}:        ${data.id}`);
        console.log(`${chalk.bold('Action')}:    ${data.action}`);
        console.log(`${chalk.bold('Mode')}:      ${chalk.magenta(data.mode)}`);
        console.log(`${chalk.bold('Window')}:    ${data.window.tickStart} -> ${data.window.tickEnd}`);
      } else if (data.capsule_id && data.capsule_type === 'tickauth.authorization') {
        console.log(chalk.bgMagenta.white(' TYPE: CAPSULE '));
        console.log(chalk.dim('TickAuth Evidence Capsule\n'));

        const statusColor =
          data.verification?.status === 'approved' ? chalk.green : chalk.red;
        console.log(`${chalk.bold('Capsule ID')}: ${chalk.cyan(data.capsule_id)}`);
        console.log(`${chalk.bold('Version')}:    ${data.capsule_version}`);
        console.log(`${chalk.bold('Status')}:     ${statusColor(data.verification?.status ?? '?')}`);
        if (data.verification?.reason) {
          console.log(`${chalk.bold('Reason')}:     ${data.verification.reason}`);
        }
        console.log(`${chalk.bold('Action')}:     ${data.intent?.action}`);
        console.log(`${chalk.bold('Mode')}:       ${chalk.magenta(data.mode)}`);
        console.log(`${chalk.bold('Challenge')}: ${data.challenge_id}`);
        console.log(`${chalk.bold('Issued At')}: ${data.issued_at}`);
        if (data.subject) console.log(`${chalk.bold('Subject')}:    ${data.subject}`);
        if (data.issuer)  console.log(`${chalk.bold('Issuer')}:     ${data.issuer}`);
        if (data.parents?.length) {
          console.log(`${chalk.bold('Parents')}:    ${data.parents.join(', ')}`);
        }
      } else {
        console.log(chalk.bgRed.white(' UNKNOWN TYPE '));
        console.log(chalk.red('File does not appear to be a valid TickAuth challenge, proof, or capsule.'));
      }
      
      console.log('');
      
    } catch (err: any) {
      console.error(chalk.red(`Error reading file: ${err.message}`));
      process.exit(1);
    }
  });
