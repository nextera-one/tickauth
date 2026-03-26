#!/usr/bin/env node
import { Command } from 'commander';

import { initCommand } from './commands/init';
import { challengeCommand } from './commands/challenge';
import { signCommand } from './commands/sign';
import { verifyCommand } from './commands/verify';
import { modesCommand } from './commands/modes';
import { inspectCommand } from './commands/inspect';
import { capsuleCommand } from './commands/capsule';

const program = new Command();

program
  .name('tickauth')
  .description('TickAuth CLI - Temporal Authorization Protocol')
  .version('1.0.0');

program.addCommand(initCommand);
program.addCommand(challengeCommand);
program.addCommand(signCommand);
program.addCommand(verifyCommand);
program.addCommand(modesCommand);
program.addCommand(inspectCommand);
program.addCommand(capsuleCommand);

program.parse(process.argv);

if (!process.argv.slice(2).length) {
  program.outputHelp();
}
