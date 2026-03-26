import { Command } from 'commander';
import chalk from 'chalk';
import { verifyCapsuleIntegrity, type TickAuthCapsule } from '@nextera.one/tickauth-sdk';
import { readJsonFile } from './fsutil';

export const capsuleCommand = new Command('capsule')
  .description('Inspect and verify a TickAuth Capsule evidence artifact')
  .argument('<file>', 'Path to capsule JSON file')
  .option('--check-integrity', 'Verify capsule_id matches content hash')
  .action((file, options) => {
    try {
      const capsule = readJsonFile<TickAuthCapsule>(file);

      if (!capsule.capsule_id || capsule.capsule_type !== 'tickauth.authorization') {
        console.error(chalk.red('Error: File does not appear to be a valid TickAuth Capsule.'));
        process.exit(1);
      }

      console.log(chalk.bold('\nTickAuth Capsule\n'));

      const statusColor =
        capsule.verification.status === 'approved' ? chalk.green : chalk.red;

      console.log(`${chalk.bold('Capsule ID')}: ${chalk.cyan(capsule.capsule_id)}`);
      console.log(`${chalk.bold('Status')}:     ${statusColor(capsule.verification.status)}`);
      if (capsule.verification.reason) {
        console.log(`${chalk.bold('Reason')}:     ${chalk.dim(capsule.verification.reason)}`);
      }
      console.log(`${chalk.bold('Action')}:     ${capsule.intent.action}`);
      console.log(`${chalk.bold('Mode')}:       ${chalk.magenta(capsule.mode)}`);
      if (capsule.subject) {
        console.log(`${chalk.bold('Subject')}:    ${capsule.subject}`);
      }
      console.log(`${chalk.bold('Tick')}:       ${capsule.tick_index}`);
      if (capsule.tick_tps) {
        console.log(`${chalk.bold('TPS Tick')}:   ${capsule.tick_tps}`);
      }
      console.log(`${chalk.bold('Challenge')}: ${capsule.challenge_id}`);
      console.log(`${chalk.bold('Issued At')}: ${capsule.issued_at}`);
      if (capsule.issuer) {
        console.log(`${chalk.bold('Issuer')}:     ${capsule.issuer}`);
      }
      if (capsule.parents?.length) {
        console.log(`${chalk.bold('Parents')}:    ${capsule.parents.join(', ')}`);
      }

      if (options.checkIntegrity) {
        const valid = verifyCapsuleIntegrity(capsule);
        console.log('');
        if (valid) {
          console.log(chalk.green('✅ Capsule integrity verified — content hash matches ID'));
        } else {
          console.log(chalk.red('❌ Capsule integrity FAILED — content hash does not match ID'));
          process.exit(1);
        }
      }

      console.log('');
    } catch (err) {
      console.error(chalk.red('Error reading capsule:'), (err as Error).message);
      process.exit(1);
    }
  });
