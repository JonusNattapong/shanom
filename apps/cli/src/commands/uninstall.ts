/**
 * `shn uninstall` command — remove ~/.shanom/ after confirmation (npx only).
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as p from '@clack/prompts';
import { stopInfra, stopWorkers } from '../docker.js';

const SHANOM_HOME = path.join(os.homedir(), '.shanom');

export async function uninstall(): Promise<void> {
  p.intro('Shanom Uninstall');

  if (!fs.existsSync(SHANOM_HOME)) {
    p.log.info('Nothing to remove. Shanom is not configured on this machine.');
    p.outro('Done.');
    return;
  }

  const confirmed = await p.confirm({
    message: 'This will permanently remove all past scan data, saved configurations, and API keys. Continue?',
  });
  if (p.isCancel(confirmed) || !confirmed) {
    p.cancel('Aborted.');
    process.exit(0);
  }

  // Stop any running containers first
  stopWorkers();
  stopInfra(false);

  fs.rmSync(SHANOM_HOME, { recursive: true, force: true });
  p.log.success('All Shanom data has been removed.');
  p.outro('Shanom has been uninstalled. Run `npx shanom setup` to start fresh.');
}
