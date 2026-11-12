#!/usr/bin/env node
// Render REPORT.md from a validated findings.json.
//
//   node render-report.mjs <findings.json> [--target <project-dir>] [--out REPORT.md]
//
// The report is derived from the records, so the prose can never disagree with
// the data. Refuses to render an invalid file. Without --out, prints to stdout.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateFindings, DOMAINS, SEVERITIES } from './lib/contract.mjs';

const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const ATTACKER_LABEL = {
  'binary-holder': 'Anyone with the app binary',
  'remote-content': 'Remote content (link, web page, push, WebView page)',
  'local-app': 'Another app on the device',
  network: 'Network attacker on the path',
  'device-access': 'Someone with the device or its backups',
  'compromised-device': 'Rooted / instrumented device (including its owner)',
  'backend-peer': 'Another user of the backend',
  'supply-chain': 'Supply chain or repository reader',
};
const STATUS_LABEL = { reviewed: 'Reviewed', not_applicable: 'Not applicable', not_reviewed: 'NOT REVIEWED' };

const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\s*\n\s*/g, ' ');
const loc = (l) => `\`${l.file}${l.line ? `:${l.line}` : ''}\`${l.note ? ` — ${l.note}` : ''}`;

export function renderReport(doc) {
  const out = [];
  const run = doc.run;
  const confirmed = doc.findings
    .filter((f) => f.verdict === 'confirmed')
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.id.localeCompare(b.id));
  const needs = doc.findings.filter((f) => f.verdict === 'needs_validation');
  const rejected = doc.findings.filter((f) => f.verdict === 'rejected');
  const hardening = doc.hardening || [];
  const notReviewed = doc.coverage.filter((c) => c.status === 'not_reviewed');

  out.push(`# Security audit: ${run.target}`, '');
  out.push(`| | |`, `|---|---|`);
  out.push(`| Date | ${cell(run.date)} |`);
  out.push(`| Source | ${cell(run.source_ref || 'not recorded')} |`);
  out.push(`| Scope | ${run.mode === 'scoped' ? `Scoped: ${cell((run.scope || []).join(', '))}` : 'Full repository'} |`);
  if (run.profile && typeof run.profile === 'object') {
    out.push(`| Project | ${cell(Object.entries(run.profile).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join('; '))} |`);
  }
  out.push(`| Method | Static review of source and build configuration. No live systems were probed and no discovered credential was used. |`);
  out.push('');

  if (run.mode === 'scoped' || notReviewed.length) {
    out.push(`> **Partial coverage.** ${run.mode === 'scoped' ? 'This was a scoped review. ' : ''}${notReviewed.length ? `Not reviewed: ${notReviewed.map((c) => c.domain).join(', ')}. ` : ''}Absence of findings outside the reviewed area means nothing.`, '');
  }

  out.push('## Summary', '', doc.summary.trim(), '');
  const counts = SEVERITIES.map((s) => [s, confirmed.filter((f) => f.severity === s).length]).filter(([, n]) => n);
  out.push(
    `**${confirmed.length} confirmed** finding${confirmed.length === 1 ? '' : 's'}` +
      `${counts.length ? ` (${counts.map(([s, n]) => `${n} ${s}`).join(', ')})` : ''}, ` +
      `**${needs.length}** needing validation, **${hardening.length}** hardening note${hardening.length === 1 ? '' : 's'}.`,
    '',
  );

  out.push('## Confirmed findings', '');
  if (!confirmed.length) {
    out.push('None. No issue met the bar of a source-visible path from a realistic attacker to a concrete effect in the release app. See coverage and limits below for what that statement does and does not cover.', '');
  } else {
    out.push('| ID | Severity | Finding | Attacker | MASVS |', '|---|---|---|---|---|');
    for (const f of confirmed) out.push(`| ${f.id} | ${SEVERITY_LABEL[f.severity]} | ${cell(f.title)} | ${cell(ATTACKER_LABEL[f.attacker])} | ${f.masvs.join(', ')} |`);
    out.push('');
    for (const f of confirmed) {
      out.push(`### ${f.id} · ${SEVERITY_LABEL[f.severity]} · ${f.title}`, '');
      out.push(f.description.trim(), '');
      out.push(`- **Attacker:** ${ATTACKER_LABEL[f.attacker]}`);
      if (f.preconditions?.length) {
        out.push('- **Preconditions:**');
        for (const p of f.preconditions) out.push(`  - ${p}`);
      }
      out.push(`- **Impact:** ${f.impact.trim()}`);
      out.push(`- **Why ${f.severity}:** ${f.severity_rationale.trim()}`);
      out.push(`- **Evidence:** ${f.evidence.trim()}`);
      out.push(`- **Where:**`);
      for (const l of f.locations) out.push(`  - ${loc(l)}`);
      out.push(`- **MASVS:** ${f.masvs.join(', ')}`);
      out.push('', `**Fix.** ${f.fix.trim()}`, '');
    }
  }

  out.push('## Needs validation', '');
  if (!needs.length) out.push('None.', '');
  else {
    out.push('These are source-grounded leads that depend on a fact outside the repository. They are not rated and are not confirmed vulnerabilities.', '');
    for (const f of needs) {
      out.push(`### ${f.id} · ${f.title}`, '');
      out.push(f.description.trim(), '');
      out.push(`- **Attacker if real:** ${ATTACKER_LABEL[f.attacker]}`);
      out.push(`- **What is unknown:** ${f.blocker.trim()}`);
      out.push(`- **How to settle it:** ${f.validation_plan.trim()}`);
      if (f.fix) out.push(`- **If it holds, fix:** ${f.fix.trim()}`);
      out.push(`- **Where:**`);
      for (const l of f.locations) out.push(`  - ${loc(l)}`);
      out.push('');
    }
  }

  out.push('## Hardening notes', '');
  if (!hardening.length) out.push('None.', '');
  else {
    out.push('Defence-in-depth improvements. None of these is a vulnerability on its own.', '');
    for (const h of hardening) {
      const where = h.locations?.length ? ` (${h.locations.map((l) => `\`${l.file}${l.line ? `:${l.line}` : ''}\``).join(', ')})` : '';
      out.push(`- **${h.title}**${h.masvs?.length ? ` [${h.masvs.join(', ')}]` : ''}: ${h.note.trim()}${where}`);
    }
    out.push('');
  }

  out.push('## Coverage', '', '| Domain | Status | Note |', '|---|---|---|');
  for (const d of DOMAINS) {
    const c = doc.coverage.find((x) => x.domain === d);
    out.push(`| ${d} | ${STATUS_LABEL[c.status]} | ${cell(c.note || '')} |`);
  }
  out.push('');

  if (rejected.length) {
    out.push('## Checked and dismissed', '', 'Leads that were investigated and did not hold, recorded so they are not re-reported.', '');
    for (const f of rejected) out.push(`- **${f.id} ${f.title}** (${f.locations.map((l) => `\`${l.file}${l.line ? `:${l.line}` : ''}\``).join(', ')}): ${f.reason.trim()}`);
    out.push('');
  }

  out.push('## Limits of this audit', '');
  for (const l of run.limitations || []) out.push(`- ${l}`);
  out.push('- Static source review cannot observe server-side authorization, provider-console settings (API key restrictions, backend rules actually deployed), or the final signed binary.');
  out.push('- One pass does not exhaust a codebase. Re-run after significant changes and before each release.');
  out.push('');
  return out.join('\n');
}

function main() {
  const argv = process.argv.slice(2);
  let file = null;
  let outPath = null;
  let targetDir = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--out') outPath = argv[++i];
    else if (argv[i] === '--target') targetDir = argv[++i];
    else if (!file) file = argv[i];
  }
  if (!file) {
    process.stderr.write('Usage: node render-report.mjs <findings.json> [--target <project-dir>] [--out REPORT.md]\n');
    process.exit(2);
  }
  let rawText;
  let doc;
  try {
    rawText = fs.readFileSync(file, 'utf8');
    doc = JSON.parse(rawText);
  } catch (err) {
    process.stderr.write(`render-report: cannot read ${file} as JSON: ${err.message}\n`);
    process.exit(1);
  }
  const { errors } = validateFindings(doc, { targetDir: targetDir && path.resolve(targetDir), rawText });
  if (errors.length) {
    for (const e of errors) process.stderr.write(`error: ${e}\n`);
    process.stderr.write('render-report: findings.json is invalid; nothing was written.\n');
    process.exit(1);
  }
  const md = renderReport(doc);
  if (outPath) {
    fs.writeFileSync(outPath, md);
    process.stdout.write(`Wrote ${outPath}\n`);
  } else {
    process.stdout.write(md);
  }
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) main();
