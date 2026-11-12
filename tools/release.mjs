#!/usr/bin/env node
// Decide whether the commits since the last release tag warrant a new release,
// and if so bump the version everywhere it is recorded.
//
//   node tools/release.mjs [--dry-run] [--notes <file>]
//
// The size of the bump comes from Conventional Commit messages:
//   feat!: / fix!: / "BREAKING CHANGE:" in the body  -> major
//   feat:                                             -> minor
//   anything else that touches shipped files          -> patch
//
// Only commits that touch what users install (skills/, .claude-plugin/) count.
// Changes to the README, tests, evals or CI alone do not produce a release.
//
// With no release tag yet, the current version is released as it stands.
// Run from the repository root. Writes `release`, `version` and `bump` to
// $GITHUB_OUTPUT when that is set. Zero dependencies.

import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const SHIPPED_PATHS = ['skills', '.claude-plugin'];
export const VERSION_FILES = {
  package: 'package.json',
  plugin: '.claude-plugin/plugin.json',
  skill: 'skills/react-native-security-audit/SKILL.md',
};

const BREAKING_SUBJECT = /^[a-z]+(\([^)]*\))?!:/i;
const BREAKING_BODY = /^BREAKING[ -]CHANGE:/m;
const FEATURE = /^feat(\([^)]*\))?:/i;
const FIX = /^(fix|perf)(\([^)]*\))?:/i;

export function classify(commit) {
  if (BREAKING_SUBJECT.test(commit.subject) || BREAKING_BODY.test(commit.body || '')) return 'major';
  if (FEATURE.test(commit.subject)) return 'minor';
  return 'patch';
}

export function bumpFor(commits) {
  if (!commits.length) return null;
  const kinds = commits.map(classify);
  return kinds.includes('major') ? 'major' : kinds.includes('minor') ? 'minor' : 'patch';
}

export function nextVersion(current, bump) {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(current);
  if (!m) throw new Error(`Version "${current}" is not MAJOR.MINOR.PATCH`);
  const [major, minor, patch] = m.slice(1).map(Number);
  if (bump === 'major') return `${major + 1}.0.0`;
  if (bump === 'minor') return `${major}.${minor + 1}.0`;
  return `${major}.${minor}.${patch + 1}`;
}

export function releaseNotes(version, commits, { first = false } = {}) {
  const groups = { 'Breaking changes': [], Features: [], Fixes: [], 'Other changes': [] };
  for (const c of commits) {
    const kind = classify(c);
    const title = kind === 'major' ? 'Breaking changes' : kind === 'minor' ? 'Features' : FIX.test(c.subject) ? 'Fixes' : 'Other changes';
    groups[title].push(`- ${c.subject} (${c.hash.slice(0, 7)})`);
  }
  const out = [`## v${version}`, ''];
  if (first) out.push('First release.', '');
  for (const [title, lines] of Object.entries(groups)) {
    if (lines.length) out.push(`### ${title}`, '', ...lines, '');
  }
  return out.join('\n');
}

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
}

function lastReleaseTag() {
  try {
    return git(['describe', '--tags', '--abbrev=0', '--match', 'v[0-9]*']);
  } catch {
    return null;
  }
}

function commitsSince(tag, paths) {
  const range = tag ? [`${tag}..HEAD`] : ['HEAD'];
  const raw = git(['log', ...range, '--format=%H%x1f%s%x1f%b%x1e', '--', ...paths]);
  return raw
    .split('\x1e')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [hash, subject, body] = entry.split('\x1f');
      return { hash, subject, body: body || '' };
    })
    .filter((c) => !/^chore\(release\):/.test(c.subject));
}

function writeVersion(version) {
  for (const file of [VERSION_FILES.package, VERSION_FILES.plugin]) {
    const json = JSON.parse(fs.readFileSync(file, 'utf8'));
    json.version = version;
    fs.writeFileSync(file, `${JSON.stringify(json, null, 2)}\n`);
  }
  const skill = fs.readFileSync(VERSION_FILES.skill, 'utf8');
  const end = skill.indexOf('\n---', 3);
  const frontmatter = skill.slice(0, end);
  const updated = frontmatter.replace(/^(\s+version:\s*")[^"]*(")/m, `$1${version}$2`);
  if (updated === frontmatter && !frontmatter.includes(`version: "${version}"`)) {
    throw new Error(`No metadata.version line found in ${VERSION_FILES.skill}`);
  }
  fs.writeFileSync(VERSION_FILES.skill, updated + skill.slice(end));
}

function setOutput(values) {
  if (!process.env.GITHUB_OUTPUT) return;
  fs.appendFileSync(process.env.GITHUB_OUTPUT, Object.entries(values).map(([k, v]) => `${k}=${v}\n`).join(''));
}

function main() {
  const argv = process.argv.slice(2);
  const dryRun = argv.includes('--dry-run');
  const notesAt = argv.indexOf('--notes');
  const notesFile = notesAt >= 0 ? argv[notesAt + 1] : null;

  const current = JSON.parse(fs.readFileSync(VERSION_FILES.package, 'utf8')).version;
  const tag = lastReleaseTag();

  let version;
  let bump;
  let commits;
  if (!tag) {
    version = current;
    bump = 'initial';
    commits = commitsSince(null, ['.']);
  } else {
    commits = commitsSince(tag, SHIPPED_PATHS);
    bump = bumpFor(commits);
    if (!bump) {
      console.log(`No change to ${SHIPPED_PATHS.join(' or ')} since ${tag}. Nothing to release.`);
      setOutput({ release: 'false' });
      return;
    }
    version = nextVersion(current, bump);
  }

  const notes = releaseNotes(version, commits, { first: !tag });
  console.log(`${tag ? `${tag} -> ` : ''}v${version} (${bump}, ${commits.length} commit${commits.length === 1 ? '' : 's'})${dryRun ? ' [dry run, nothing written]' : ''}\n`);
  console.log(notes);
  if (dryRun) return;

  if (tag) writeVersion(version);
  if (notesFile) fs.writeFileSync(notesFile, notes);
  setOutput({ release: 'true', version, bump });
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) main();
