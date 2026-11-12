import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tool = path.join(repo, 'tools/release.mjs');
const { classify, bumpFor, nextVersion, releaseNotes, VERSION_FILES } = await import(tool);
const c = (subject, body = '') => ({ hash: 'abcdef1234567', subject, body });

test('commit messages map to bump sizes', () => {
  assert.equal(classify(c('feat: add push-payload rule')), 'minor');
  assert.equal(classify(c('feat(scanner): add rule')), 'minor');
  assert.equal(classify(c('fix: mask env values')), 'patch');
  assert.equal(classify(c('docs: clarify pinning')), 'patch');
  assert.equal(classify(c('Tidy wording')), 'patch', 'unconventional messages still release as a patch');
  assert.equal(classify(c('feat!: rename findings fields')), 'major');
  assert.equal(classify(c('refactor(contract)!: drop field')), 'major');
  assert.equal(classify(c('fix: x', 'BREAKING CHANGE: schema id changed')), 'major');
});

test('the largest change in a batch decides the bump', () => {
  assert.equal(bumpFor([]), null);
  assert.equal(bumpFor([c('fix: a'), c('docs: b')]), 'patch');
  assert.equal(bumpFor([c('fix: a'), c('feat: b')]), 'minor');
  assert.equal(bumpFor([c('feat: a'), c('fix!: b')]), 'major');
});

test('version arithmetic', () => {
  assert.equal(nextVersion('1.2.3', 'patch'), '1.2.4');
  assert.equal(nextVersion('1.2.3', 'minor'), '1.3.0');
  assert.equal(nextVersion('1.2.3', 'major'), '2.0.0');
  assert.throws(() => nextVersion('1.2', 'patch'));
});

test('release notes group commits by kind', () => {
  const notes = releaseNotes('1.3.0', [c('feat: add rule'), c('fix: mask'), c('Tidy wording'), c('feat!: rename')]);
  assert.match(notes, /^## v1\.3\.0/);
  assert.match(notes, /### Breaking changes\n\n- feat!: rename \(abcdef1\)/);
  assert.match(notes, /### Features\n\n- feat: add rule/);
  assert.match(notes, /### Fixes\n\n- fix: mask/);
  assert.match(notes, /### Other changes\n\n- Tidy wording/);
});

// End to end in a throwaway repository shaped like this one.
function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rn-release-'));
  const git = (...args) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false', ...args], { cwd: dir, encoding: 'utf8' });
  const write = (rel, text) => {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), text);
  };
  const commit = (msg) => {
    git('add', '-A');
    git('commit', '-q', '-m', msg);
  };
  const run = (...args) => {
    const out = path.join(dir, '.out');
    fs.writeFileSync(out, '');
    const stdout = execFileSync('node', [tool, ...args], { cwd: dir, encoding: 'utf8', env: { ...process.env, GITHUB_OUTPUT: out } });
    const outputs = Object.fromEntries(fs.readFileSync(out, 'utf8').trim().split('\n').filter(Boolean).map((l) => l.split('=')));
    fs.rmSync(out);
    return { stdout, outputs };
  };
  const versions = () => ({
    package: JSON.parse(fs.readFileSync(path.join(dir, VERSION_FILES.package), 'utf8')).version,
    plugin: JSON.parse(fs.readFileSync(path.join(dir, VERSION_FILES.plugin), 'utf8')).version,
    skill: fs.readFileSync(path.join(dir, VERSION_FILES.skill), 'utf8').match(/version: "([^"]+)"/)[1],
  });
  git('init', '-q', '-b', 'main');
  write(VERSION_FILES.package, JSON.stringify({ name: 'x', version: '1.0.0' }, null, 2));
  write(VERSION_FILES.plugin, JSON.stringify({ name: 'x', version: '1.0.0' }, null, 2));
  write(VERSION_FILES.skill, '---\nname: x\ndescription: y\nmetadata:\n  author: a\n  version: "1.0.0"\n---\n\n# X\n\nBody mentions version: "9.9.9" and must not change.\n');
  write('README.md', 'readme\n');
  commit('Initial commit');
  return { dir, git, write, commit, run, versions };
}

test('first run with no tag releases the current version unchanged', () => {
  const s = sandbox();
  const { outputs, stdout } = s.run();
  assert.deepEqual(outputs, { release: 'true', version: '1.0.0', bump: 'initial' });
  assert.match(stdout, /First release\./);
  assert.deepEqual(s.versions(), { package: '1.0.0', plugin: '1.0.0', skill: '1.0.0' });
  assert.equal(s.git('status', '--porcelain').trim(), '', 'no files are modified for the first release');
});

test('changes outside shipped paths do not release', () => {
  const s = sandbox();
  s.git('tag', 'v1.0.0');
  s.write('README.md', 'better readme\n');
  s.commit('feat: rewrite readme');
  const { outputs } = s.run();
  assert.deepEqual(outputs, { release: 'false' });
});

test('a feature in the skill bumps minor in all three files', () => {
  const s = sandbox();
  s.git('tag', 'v1.0.0');
  s.write('skills/react-native-security-audit/references/new.md', 'new\n');
  s.commit('feat: add reference');
  s.write('README.md', 'x\n');
  s.commit('docs: readme');
  const notes = path.join(s.dir, 'notes.md');
  const { outputs } = s.run('--notes', notes);
  assert.deepEqual(outputs, { release: 'true', version: '1.1.0', bump: 'minor' });
  assert.deepEqual(s.versions(), { package: '1.1.0', plugin: '1.1.0', skill: '1.1.0' });
  const skill = fs.readFileSync(path.join(s.dir, VERSION_FILES.skill), 'utf8');
  assert.match(skill, /Body mentions version: "9\.9\.9"/, 'only the frontmatter version is touched');
  const text = fs.readFileSync(notes, 'utf8');
  assert.match(text, /feat: add reference/);
  assert.ok(!/docs: readme/.test(text), 'notes list only commits that touched shipped files');
});

test('after a release commit and tag, the next run sees only newer commits', () => {
  const s = sandbox();
  s.git('tag', 'v1.0.0');
  s.write('.claude-plugin/plugin.json', JSON.stringify({ name: 'x', version: '1.0.0', description: 'd' }, null, 2));
  s.commit('Reword plugin description');
  assert.equal(s.run().outputs.version, '1.0.1');
  s.commit('chore(release): v1.0.1');
  s.git('tag', 'v1.0.1');
  assert.deepEqual(s.run().outputs, { release: 'false' });
  s.write('skills/react-native-security-audit/SKILL.md', fs.readFileSync(path.join(s.dir, VERSION_FILES.skill), 'utf8') + '\nmore\n');
  s.commit('feat!: change record format');
  assert.equal(s.run().outputs.version, '2.0.0');
});

test('dry run writes nothing', () => {
  const s = sandbox();
  s.git('tag', 'v1.0.0');
  s.write('skills/react-native-security-audit/x.md', 'x\n');
  s.commit('fix: wording');
  const { stdout, outputs } = s.run('--dry-run');
  assert.match(stdout, /v1\.0\.0 -> v1\.0\.1 \(patch, 1 commit\) \[dry run/);
  assert.deepEqual(outputs, {});
  assert.equal(s.versions().package, '1.0.0');
});
