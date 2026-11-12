// The findings.json contract: enums, and the checks that keep an audit honest.
// assets/findings.schema.json describes the same shape for editors and other
// tools; this file is what the validator actually enforces.

import fs from 'node:fs';
import path from 'node:path';
import { findUnredactedSecrets } from './secret-patterns.mjs';

export const SCHEMA_ID = 'rn-security-audit/1';

export const DOMAINS = ['secrets', 'storage', 'crypto', 'auth', 'network', 'platform', 'supply-chain', 'privacy', 'resilience'];
export const VERDICTS = ['confirmed', 'needs_validation', 'rejected'];
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const COVERAGE_STATUSES = ['reviewed', 'not_applicable', 'not_reviewed'];
export const ATTACKERS = [
  'binary-holder', // anyone who downloads the app and unpacks it
  'remote-content', // a link, web page, QR code, push payload or page inside a WebView
  'local-app', // another app installed on the same device
  'network', // on-path between the device and the server
  'device-access', // has the device or its backups, not root
  'compromised-device', // root/jailbreak or instrumentation; includes the device owner
  'backend-peer', // another authenticated user of the same backend
  'supply-chain', // a dependency, build step, OTA channel or repository reader
];
export const MASVS = [
  'MASVS-STORAGE-1', 'MASVS-STORAGE-2',
  'MASVS-CRYPTO-1', 'MASVS-CRYPTO-2',
  'MASVS-AUTH-1', 'MASVS-AUTH-2', 'MASVS-AUTH-3',
  'MASVS-NETWORK-1', 'MASVS-NETWORK-2',
  'MASVS-PLATFORM-1', 'MASVS-PLATFORM-2', 'MASVS-PLATFORM-3',
  'MASVS-CODE-1', 'MASVS-CODE-2', 'MASVS-CODE-3', 'MASVS-CODE-4',
  'MASVS-RESILIENCE-1', 'MASVS-RESILIENCE-2', 'MASVS-RESILIENCE-3', 'MASVS-RESILIENCE-4',
  'MASVS-PRIVACY-1', 'MASVS-PRIVACY-2', 'MASVS-PRIVACY-3', 'MASVS-PRIVACY-4',
];

const FIELDS_BY_VERDICT = {
  confirmed: { required: ['impact', 'severity', 'severity_rationale', 'evidence', 'fix'], forbidden: ['blocker', 'validation_plan', 'reason'] },
  needs_validation: { required: ['blocker', 'validation_plan'], forbidden: ['severity', 'severity_rationale', 'reason'] },
  rejected: { required: ['reason'], forbidden: ['severity', 'severity_rationale', 'fix', 'blocker', 'validation_plan'] },
};
const COMMON_REQUIRED = ['id', 'title', 'verdict', 'domain', 'masvs', 'attacker', 'locations', 'description'];
const KNOWN_FINDING_FIELDS = new Set([
  ...COMMON_REQUIRED, 'preconditions', 'impact', 'severity', 'severity_rationale', 'evidence', 'fix', 'blocker', 'validation_plan', 'reason',
]);
const MIN_PROSE = 20;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isText = (v, min = 1) => typeof v === 'string' && v.trim().length >= min;

function checkLocations(locs, where, targetDir, errors, lineCache) {
  if (!Array.isArray(locs)) {
    errors.push(`${where}.locations must be an array.`);
    return;
  }
  locs.forEach((loc, i) => {
    const at = `${where}.locations[${i}]`;
    if (!isObj(loc) || !isText(loc.file)) {
      errors.push(`${at} needs a "file".`);
      return;
    }
    if (path.isAbsolute(loc.file) || loc.file.split(/[\\/]/).includes('..')) {
      errors.push(`${at}.file must be a path relative to the audited project (got "${loc.file}").`);
      return;
    }
    if (loc.line !== undefined && (!Number.isInteger(loc.line) || loc.line < 1)) {
      errors.push(`${at}.line must be a positive integer.`);
    }
    if (!targetDir) return;
    const abs = path.join(targetDir, loc.file);
    if (!fs.existsSync(abs)) {
      errors.push(`${at}: "${loc.file}" does not exist in the target. A finding must cite a real file.`);
      return;
    }
    if (Number.isInteger(loc.line) && fs.statSync(abs).isFile()) {
      if (!lineCache.has(abs)) lineCache.set(abs, fs.readFileSync(abs, 'utf8').split('\n').length);
      if (loc.line > lineCache.get(abs)) {
        errors.push(`${at}: line ${loc.line} is past the end of "${loc.file}" (${lineCache.get(abs)} lines).`);
      }
    }
  });
}

function checkMasvs(list, where, errors) {
  if (!Array.isArray(list)) {
    errors.push(`${where}.masvs must be an array of MASVS control ids.`);
    return;
  }
  for (const id of list) {
    if (!MASVS.includes(id)) errors.push(`${where}.masvs: "${id}" is not a MASVS v2 control id (expected e.g. MASVS-STORAGE-1).`);
  }
}

// Returns { errors, warnings }. Errors mean the file must be fixed before a
// report is rendered; warnings are calibration prompts worth a second look.
export function validateFindings(doc, { targetDir = null, rawText = null } = {}) {
  const errors = [];
  const warnings = [];
  const lineCache = new Map();

  if (!isObj(doc)) return { errors: ['Top level must be a JSON object.'], warnings };
  if (doc.schema !== SCHEMA_ID) errors.push(`"schema" must be "${SCHEMA_ID}".`);

  // run
  if (!isObj(doc.run)) errors.push('"run" object is required.');
  else {
    for (const k of ['target', 'date', 'mode']) if (!isText(doc.run[k])) errors.push(`run.${k} is required.`);
    if (isText(doc.run.target) && path.isAbsolute(doc.run.target)) errors.push('run.target should be the project name, not an absolute path from this machine.');
    if (isText(doc.run.mode) && !['full', 'scoped'].includes(doc.run.mode)) errors.push('run.mode must be "full" or "scoped".');
    if (doc.run.mode === 'scoped' && !(Array.isArray(doc.run.scope) && doc.run.scope.length)) errors.push('A scoped run must list run.scope so readers know what was not looked at.');
    if (doc.run.limitations !== undefined && !Array.isArray(doc.run.limitations)) errors.push('run.limitations must be an array of strings.');
  }

  if (!isText(doc.summary, MIN_PROSE)) errors.push('"summary" is required: a short, plain statement of the security posture.');

  // coverage: every domain accounted for, so silence is never read as "fine".
  if (!Array.isArray(doc.coverage)) errors.push('"coverage" array is required.');
  else {
    const seen = new Map();
    doc.coverage.forEach((c, i) => {
      const at = `coverage[${i}]`;
      if (!isObj(c) || !DOMAINS.includes(c.domain)) {
        errors.push(`${at}.domain must be one of: ${DOMAINS.join(', ')}.`);
        return;
      }
      if (seen.has(c.domain)) errors.push(`${at}: domain "${c.domain}" is listed twice.`);
      seen.set(c.domain, c.status);
      if (!COVERAGE_STATUSES.includes(c.status)) errors.push(`${at}.status must be one of: ${COVERAGE_STATUSES.join(', ')}.`);
      if (c.status !== 'reviewed' && !isText(c.note)) errors.push(`${at}: status "${c.status}" needs a note saying why.`);
    });
    for (const d of DOMAINS) if (!seen.has(d)) errors.push(`coverage is missing the "${d}" domain. Mark it not_applicable or not_reviewed with a note if it was not looked at.`);
  }

  // findings
  if (!Array.isArray(doc.findings)) errors.push('"findings" array is required (it may be empty).');
  else {
    const ids = new Set();
    doc.findings.forEach((f, i) => {
      const at = isObj(f) && isText(f.id) ? f.id : `findings[${i}]`;
      if (!isObj(f)) {
        errors.push(`${at} must be an object.`);
        return;
      }
      // A dismissed lead has no real attacker or control to name, so those are optional there.
      const optionalHere = f.verdict === 'rejected' ? ['masvs', 'attacker', 'description'] : [];
      for (const k of COMMON_REQUIRED) if (f[k] === undefined && !optionalHere.includes(k)) errors.push(`${at}: missing "${k}".`);
      for (const k of Object.keys(f)) if (!KNOWN_FINDING_FIELDS.has(k)) errors.push(`${at}: unknown field "${k}".`);
      if (isText(f.id)) {
        if (!/^RN-\d{3}$/.test(f.id)) errors.push(`${at}: id must look like RN-001.`);
        if (ids.has(f.id)) errors.push(`${at}: duplicate id.`);
        ids.add(f.id);
      }
      if (f.title !== undefined && !isText(f.title, 8)) errors.push(`${at}: title is too short to be useful.`);
      if (f.description !== undefined && !isText(f.description, MIN_PROSE)) errors.push(`${at}: description is too short.`);
      if (f.domain !== undefined && !DOMAINS.includes(f.domain)) errors.push(`${at}: domain must be one of: ${DOMAINS.join(', ')}.`);
      if (f.attacker !== undefined && !ATTACKERS.includes(f.attacker)) errors.push(`${at}: attacker must be one of: ${ATTACKERS.join(', ')}.`);
      if (f.masvs !== undefined) checkMasvs(f.masvs, at, errors);
      if (f.preconditions !== undefined && !(Array.isArray(f.preconditions) && f.preconditions.every((p) => isText(p)))) errors.push(`${at}: preconditions must be an array of strings.`);
      if (f.locations !== undefined) {
        checkLocations(f.locations, at, targetDir, errors, lineCache);
        if (Array.isArray(f.locations) && f.locations.length === 0) errors.push(`${at}: at least one source location is required.`);
      }

      if (!VERDICTS.includes(f.verdict)) {
        if (f.verdict !== undefined) errors.push(`${at}: verdict must be one of: ${VERDICTS.join(', ')}.`);
        return;
      }
      const rules = FIELDS_BY_VERDICT[f.verdict];
      for (const k of rules.required) {
        if (k === 'severity') continue;
        if (!isText(f[k], MIN_PROSE)) errors.push(`${at}: a ${f.verdict} record needs a substantive "${k}".`);
      }
      for (const k of rules.forbidden) {
        if (f[k] !== undefined) errors.push(`${at}: a ${f.verdict} record must not carry "${k}"${k.startsWith('severity') ? ' (only confirmed findings are rated)' : ''}.`);
      }
      if (f.verdict === 'confirmed') {
        if (!SEVERITIES.includes(f.severity)) errors.push(`${at}: severity must be one of: ${SEVERITIES.join(', ')}.`);
        if (Array.isArray(f.masvs) && f.masvs.length === 0) errors.push(`${at}: a confirmed finding maps to at least one MASVS control.`);
        if (['critical', 'high'].includes(f.severity) && f.attacker === 'compromised-device') {
          warnings.push(`${at}: rated ${f.severity} but the attacker needs a rooted/instrumented device. That is usually low or medium unless the app's whole purpose is resisting the device owner.`);
        }
        if (['critical', 'high'].includes(f.severity) && f.domain === 'resilience') {
          warnings.push(`${at}: resilience controls (root detection, obfuscation, pinning) are defence in depth. A ${f.severity} rating needs an impact that does not depend on another flaw.`);
        }
        if (f.severity === 'critical' && !['binary-holder', 'remote-content', 'network', 'supply-chain', 'backend-peer'].includes(f.attacker)) {
          warnings.push(`${at}: critical is reserved for attackers who need no access to the victim's device. Re-check the attacker class or the rating.`);
        }
      }
    });
  }

  // hardening notes
  if (doc.hardening !== undefined) {
    if (!Array.isArray(doc.hardening)) errors.push('"hardening" must be an array.');
    else {
      doc.hardening.forEach((h, i) => {
        const at = `hardening[${i}]`;
        if (!isObj(h) || !isText(h.title) || !isText(h.note)) {
          errors.push(`${at} needs "title" and "note".`);
          return;
        }
        if (h.severity !== undefined) errors.push(`${at}: hardening notes are not rated. If it deserves a severity it is a finding.`);
        if (h.masvs !== undefined) checkMasvs(h.masvs, at, errors);
        if (h.locations !== undefined) checkLocations(h.locations, at, targetDir, errors, lineCache);
      });
    }
  }

  // No usable credential may be copied into an audit artifact.
  const text = rawText ?? JSON.stringify(doc);
  for (const hit of findUnredactedSecrets(text)) {
    errors.push(`Unredacted secret in the file (${hit.label}: ${hit.preview}). Quote secrets as their first 4 characters plus length, never in full.`);
  }

  return { errors, warnings };
}
