#!/usr/bin/env node
// Validate an audit's findings.json before a report is written from it.
//
//   node validate-findings.mjs <findings.json> [--target <project-dir>]
//
// With --target, every cited file and line number is checked against the
// audited project, which catches invented or stale locations.
// Exit code: 0 valid (warnings allowed), 1 invalid, 2 usage error.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateFindings } from './lib/contract.mjs';

function main() {
  const argv = process.argv.slice(2);
  let file = null;
  let targetDir = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--target') targetDir = argv[++i];
    else if (!file) file = argv[i];
  }
  if (!file) {
    process.stderr.write('Usage: node validate-findings.mjs <findings.json> [--target <project-dir>]\n');
    process.exit(2);
  }
  if (targetDir && !fs.existsSync(targetDir)) {
    process.stderr.write(`validate-findings: target directory not found: ${targetDir}\n`);
    process.exit(2);
  }

  let rawText;
  let doc;
  try {
    rawText = fs.readFileSync(file, 'utf8');
    doc = JSON.parse(rawText);
  } catch (err) {
    process.stderr.write(`validate-findings: cannot read ${file} as JSON: ${err.message}\n`);
    process.exit(1);
  }

  const { errors, warnings } = validateFindings(doc, { targetDir: targetDir && path.resolve(targetDir), rawText });
  for (const w of warnings) process.stdout.write(`warning: ${w}\n`);
  for (const e of errors) process.stdout.write(`error: ${e}\n`);
  if (errors.length) {
    process.stdout.write(`\nINVALID: ${errors.length} error(s). Fix findings.json and run again.\n`);
    process.exit(1);
  }
  const counts = { confirmed: 0, needs_validation: 0, rejected: 0 };
  for (const f of doc.findings) counts[f.verdict]++;
  process.stdout.write(
    `VALID: ${counts.confirmed} confirmed, ${counts.needs_validation} needs validation, ${counts.rejected} rejected, ${(doc.hardening || []).length} hardening note(s)` +
      `${warnings.length ? `, ${warnings.length} warning(s) to review` : ''}.` +
      `${targetDir ? '' : ' Locations were not checked against the project (no --target).'}\n`,
  );
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) main();
