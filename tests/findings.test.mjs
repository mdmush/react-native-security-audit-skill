import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const skillDir = path.join(repo, 'skills/react-native-security-audit');
const { validateFindings, DOMAINS } = await import(path.join(skillDir, 'scripts/lib/contract.mjs'));
const { renderReport } = await import(path.join(skillDir, 'scripts/render-report.mjs'));
const examplePath = path.join(skillDir, 'assets/findings.example.json');
const example = () => JSON.parse(fs.readFileSync(examplePath, 'utf8'));
const fixture = path.join(repo, 'evals/full-audit-pre-release/files');
const errorsOf = (doc, opts) => validateFindings(doc, opts).errors;

test('the bundled example is valid', () => {
  const { errors, warnings } = validateFindings(example());
  assert.deepEqual(errors, []);
  assert.deepEqual(warnings, []);
});

test('the example and the JSON schema agree on the enums', () => {
  const schema = JSON.parse(fs.readFileSync(path.join(skillDir, 'assets/findings.schema.json'), 'utf8'));
  assert.deepEqual(schema.$defs.domain.enum, DOMAINS);
  assert.equal(schema.properties.schema.const, example().schema);
});

test('severity is only allowed on confirmed findings', () => {
  const doc = example();
  doc.findings.find((f) => f.verdict === 'needs_validation').severity = 'high';
  assert.ok(errorsOf(doc).some((e) => /must not carry "severity"/.test(e)));
});

test('each verdict needs its own fields', () => {
  const a = example();
  delete a.findings[0].fix;
  assert.ok(errorsOf(a).some((e) => /RN-001.*"fix"/.test(e)));

  const b = example();
  delete b.findings.find((f) => f.verdict === 'needs_validation').blocker;
  assert.ok(errorsOf(b).some((e) => /"blocker"/.test(e)));

  const c = example();
  delete c.findings.find((f) => f.verdict === 'rejected').reason;
  assert.ok(errorsOf(c).some((e) => /"reason"/.test(e)));
});

test('every domain must be accounted for in coverage', () => {
  const doc = example();
  doc.coverage = doc.coverage.filter((c) => c.domain !== 'privacy');
  assert.ok(errorsOf(doc).some((e) => /missing the "privacy" domain/.test(e)));

  const doc2 = example();
  delete doc2.coverage.find((c) => c.status === 'not_reviewed').note;
  assert.ok(errorsOf(doc2).some((e) => /needs a note/.test(e)));
});

test('unknown enums, ids and MASVS controls are rejected', () => {
  const doc = example();
  doc.findings[0].attacker = 'hacker';
  doc.findings[1].masvs = ['MSTG-STORAGE-1'];
  doc.findings[2].id = 'RN-001';
  const errs = errorsOf(doc).join('\n');
  assert.match(errs, /attacker must be one of/);
  assert.match(errs, /not a MASVS v2 control id/);
  assert.match(errs, /duplicate id/);
});

test('absolute and escaping paths are rejected', () => {
  const doc = example();
  doc.findings[0].locations[0].file = '/Users/someone/app/src/config/env.ts';
  doc.findings[1].locations[0].file = '../other/secret.ts';
  assert.equal(errorsOf(doc).filter((e) => /relative to the audited project/.test(e)).length, 2);
});

test('with a target, invented files and out-of-range lines are caught', () => {
  const doc = example();
  doc.findings = [
    {
      ...doc.findings[0],
      locations: [
        { file: 'src/config/keys.ts', line: 12 },
        { file: 'src/config/keys.ts', line: 9999 },
        { file: 'src/does/not/exist.ts', line: 1 },
      ],
    },
  ];
  doc.hardening = [];
  const errs = errorsOf(doc, { targetDir: fixture });
  assert.equal(errs.length, 2);
  assert.ok(errs.some((e) => /past the end/.test(e)));
  assert.ok(errs.some((e) => /does not exist in the target/.test(e)));
});

test('an unredacted credential in the file is an error', () => {
  const doc = example();
  doc.findings[0].description += ` The key is ${'sk_' + 'live_'}${'a1B2c3D4'.repeat(3)}.`;
  assert.ok(errorsOf(doc).some((e) => /Unredacted secret/.test(e)));
});

test('calibration warnings fire for device-owner and resilience over-rating', () => {
  const doc = example();
  doc.findings[2].attacker = 'compromised-device';
  doc.findings[2].severity = 'high';
  const { errors, warnings } = validateFindings(doc);
  assert.deepEqual(errors, []);
  assert.ok(warnings.some((w) => /rooted\/instrumented device/.test(w)));
});

test('hardening notes cannot carry a severity', () => {
  const doc = example();
  doc.hardening[0].severity = 'low';
  assert.ok(errorsOf(doc).some((e) => /hardening notes are not rated/.test(e)));
});

test('a scoped run must say what its scope was', () => {
  const doc = example();
  doc.run.mode = 'scoped';
  assert.ok(errorsOf(doc).some((e) => /run\.scope/.test(e)));
});

test('report renders every section from the records', () => {
  const md = renderReport(example());
  assert.match(md, /^# Security audit: example-app/);
  assert.match(md, /\*\*3 confirmed\*\* findings \(1 critical, 1 high, 1 medium\)/);
  assert.ok(md.indexOf('RN-001 · Critical') < md.indexOf('RN-002 · High'), 'confirmed findings are ordered by severity');
  assert.match(md, /## Needs validation[\s\S]*RN-004/);
  assert.match(md, /## Hardening notes[\s\S]*Sign over-the-air updates/);
  assert.match(md, /## Checked and dismissed[\s\S]*RN-005/);
  assert.match(md, /\| resilience \| NOT REVIEWED \|/);
  assert.match(md, /Partial coverage/);
  const needsSection = md.slice(md.indexOf('## Needs validation'), md.indexOf('## Hardening notes'));
  assert.ok(!/Critical|High|Medium/.test(needsSection), 'unconfirmed leads are never shown with a severity');
});

test('an empty audit renders an honest clean result', () => {
  const doc = example();
  doc.findings = [];
  doc.hardening = [];
  doc.coverage.forEach((c) => {
    c.status = 'reviewed';
  });
  const md = renderReport(doc);
  assert.match(md, /\*\*0 confirmed\*\* findings/);
  assert.match(md, /No issue met the bar/);
  assert.ok(!/Partial coverage/.test(md));
});

test('CLI: validate then render, and refuse to render an invalid file', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rn-findings-'));
  const ok = execFileSync('node', [path.join(skillDir, 'scripts/validate-findings.mjs'), examplePath], { encoding: 'utf8' });
  assert.match(ok, /^VALID: 3 confirmed, 1 needs validation, 1 rejected, 2 hardening note\(s\)/m);

  const report = path.join(dir, 'REPORT.md');
  execFileSync('node', [path.join(skillDir, 'scripts/render-report.mjs'), examplePath, '--out', report]);
  assert.match(fs.readFileSync(report, 'utf8'), /## Confirmed findings/);

  const bad = example();
  delete bad.summary;
  const badPath = path.join(dir, 'bad.json');
  fs.writeFileSync(badPath, JSON.stringify(bad));
  const v = spawnSync('node', [path.join(skillDir, 'scripts/validate-findings.mjs'), badPath], { encoding: 'utf8' });
  assert.equal(v.status, 1);
  assert.match(v.stdout, /INVALID/);
  const badReport = path.join(dir, 'BAD.md');
  const r = spawnSync('node', [path.join(skillDir, 'scripts/render-report.mjs'), badPath, '--out', badReport], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.ok(!fs.existsSync(badReport));
});

test('a rejected record needs only id, title, domain, locations and a reason', () => {
  const doc = example();
  const rejected = doc.findings.find((f) => f.verdict === 'rejected');
  assert.equal(rejected.attacker, undefined, 'the example shows the minimal rejected form');
  delete rejected.description;
  assert.deepEqual(errorsOf(doc), []);
  delete doc.findings[0].attacker;
  assert.ok(errorsOf(doc).some((e) => /RN-001: missing "attacker"/.test(e)), 'confirmed findings still need an attacker');
});

test('preconditions render as a list', () => {
  const doc = example();
  doc.findings[0].preconditions = ['Has the app; nothing else', 'Key still valid'];
  const md = renderReport(doc);
  assert.match(md, /- \*\*Preconditions:\*\*\n  - Has the app; nothing else\n  - Key still valid/);
});
