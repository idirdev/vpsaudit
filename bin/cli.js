#!/usr/bin/env node
'use strict';

/**
 * @file vpsaudit CLI
 * @description VPS security audit command-line interface.
 * @author idirdev
 */

const { runAudit, CHECKS } = require('../src/index.js');

const args = process.argv.slice(2);
const help = args.includes('--help') || args.includes('-h');
const json = args.includes('--json');
const verbose = args.includes('--verbose') || args.includes('-v');

if (help) {
  console.log(`
Usage: vpsaudit [options]

Options:
  --checks <list>  Comma-separated checks to run: ${CHECKS.map(c => c.name).join(',')}
  --json           Output JSON
  --verbose        Include detailed check output
  -h, --help       Show help

Examples:
  vpsaudit
  vpsaudit --checks ssh,firewall,disk
  vpsaudit --json --verbose
`);
  process.exit(0);
}

const checksArg = args.find(a => a.startsWith('--checks=') || args[args.indexOf('--checks') + 1]);
let checksFilter = [];
if (args.includes('--checks')) {
  const idx = args.indexOf('--checks');
  if (args[idx + 1] && !args[idx + 1].startsWith('--')) {
    checksFilter = args[idx + 1].split(',').map(s => s.trim());
  }
} else {
  const eq = args.find(a => a.startsWith('--checks='));
  if (eq) checksFilter = eq.split('=')[1].split(',').map(s => s.trim());
}

const result = runAudit({ checks: checksFilter, verbose });

if (json) {
  console.log(JSON.stringify(result, null, 2));
} else {
  console.log(result.report);
}
