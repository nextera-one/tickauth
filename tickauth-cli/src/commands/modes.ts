import { Command } from 'commander';
import chalk from 'chalk';
import { TickAuthMode } from '@nextera.one/tickauth-sdk';

export const modesCommand = new Command('modes')
  .description('List available TickAuth verification modes')
  .action(() => {
    console.log(chalk.bold('\nTickAuth Verification Modes:\n'));
    
    const modes: { mode: TickAuthMode; desc: string }[] = [
      { mode: 'PASSKEY', desc: 'Browser Passkey Mode (WebAuthn-compatible)' },
      { mode: 'ATTESTED', desc: 'Device Attestation (Hardware-bound)' },
      { mode: 'PRESENCE', desc: 'Continuous/Step-up Presence' },
      { mode: 'OFFLINE', desc: 'Offline / Airgap Mode' },
      { mode: 'AGENT', desc: 'Service / Agent Mode (Non-human)' },
    ];

    modes.forEach(({ mode, desc }) => {
      console.log(`  ${chalk.cyan(mode.padEnd(12))} ${chalk.dim(desc)}`);
    });
    console.log('');
  });
