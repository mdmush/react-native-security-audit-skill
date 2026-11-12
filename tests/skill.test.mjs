// Structural checks on the skill itself: the things the Agent Skills
// specification requires, and the things that silently break a skill when
// someone edits it (dead links, an over-long description, a bloated SKILL.md).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const skillName = 'react-native-security-audit';
const skillDir = path.join(repo, 'skills', skillName);
const skillMd = fs.readFileSync(path.join(skillDir, 'SKILL.md'), 'utf8');

function frontmatter(text) {
  const m = text.match(/^---\n([\s\S]*?)\n---\n/);
  assert.ok(m, 'SKILL.md must start with YAML frontmatter');
  const fields = {};
  for (const line of m[1].split('\n')) {
    const kv = line.match(/^([a-z-]+):\s*(.*)$/);
    if (kv) fields[kv[1]] = kv[2];
  }
  return { fields, body: text.slice(m[0].length) };
}

const { fields, body } = frontmatter(skillMd);

test('frontmatter name follows the spec and matches the directory', () => {
  assert.equal(fields.name, skillName);
  assert.match(fields.name, /^[a-z0-9]+(-[a-z0-9]+)*$/);
  assert.ok(fields.name.length <= 64);
});

test('description is a single plain line within the spec limit', () => {
  const d = fields.description;
  assert.ok(d && d.length >= 100, 'description should say what the skill does and when to use it');
  assert.ok(d.length <= 1024, `description is ${d.length} chars; the spec limit is 1024`);
  assert.ok(!/: /.test(d), 'a ": " inside an unquoted YAML scalar breaks strict parsers');
  assert.ok(!/ #/.test(d), 'a " #" inside an unquoted YAML scalar starts a comment');
  assert.match(d, /React Native/);
  assert.match(d, /Expo/);
  assert.match(d, /Use whenever/);
});

test('compatibility stays within the spec limit', () => {
  assert.ok(fields.compatibility.length <= 500);
});

test('only spec-defined frontmatter fields are used, so every agent accepts the file', () => {
  const allowed = new Set(['name', 'description', 'license', 'compatibility', 'metadata', 'allowed-tools']);
  for (const key of Object.keys(fields)) assert.ok(allowed.has(key), `unexpected frontmatter field "${key}"`);
});

test('SKILL.md stays under 500 lines', () => {
  const lines = skillMd.split('\n').length;
  assert.ok(lines < 500, `SKILL.md is ${lines} lines`);
});

function relativeLinks(markdown) {
  return [...markdown.matchAll(/\]\(([^)#\s]+)(?:#[^)]*)?\)/g)].map((m) => m[1]).filter((l) => !/^[a-z]+:/i.test(l));
}

test('every relative link in SKILL.md resolves', () => {
  const links = relativeLinks(body);
  assert.ok(links.length >= 10, 'SKILL.md should point at its references');
  for (const link of links) assert.ok(fs.existsSync(path.join(skillDir, link)), `broken link in SKILL.md: ${link}`);
});

test('every reference file is linked from SKILL.md and its own links resolve', () => {
  const refDir = path.join(skillDir, 'references');
  for (const file of fs.readdirSync(refDir)) {
    assert.ok(body.includes(`references/${file}`), `references/${file} is not reachable from SKILL.md`);
    const text = fs.readFileSync(path.join(refDir, file), 'utf8');
    for (const link of relativeLinks(text)) {
      assert.ok(fs.existsSync(path.join(refDir, link)), `broken link in references/${file}: ${link}`);
    }
  }
});

test('long reference files open with a table of contents', () => {
  const refDir = path.join(skillDir, 'references');
  for (const file of fs.readdirSync(refDir)) {
    const text = fs.readFileSync(path.join(refDir, file), 'utf8');
    if (text.split('\n').length > 120) assert.match(text, /^## Contents$/m, `references/${file} is long and needs a "## Contents" section`);
  }
});

test('scripts named in SKILL.md exist', () => {
  for (const m of body.matchAll(/scripts\/([a-z-]+\.mjs)/g)) {
    assert.ok(fs.existsSync(path.join(skillDir, 'scripts', m[1])), `missing script ${m[1]}`);
  }
});

test('the skill does not ship real-looking credentials', async () => {
  const { findUnredactedSecrets } = await import(path.join(skillDir, 'scripts/lib/secret-patterns.mjs'));
  const walk = (dir) =>
    fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));
  for (const file of [...walk(skillDir), ...walk(path.join(repo, 'evals'))]) {
    const hits = findUnredactedSecrets(fs.readFileSync(file, 'utf8'));
    assert.deepEqual(hits, [], `${path.relative(repo, file)} contains a provider-format secret`);
  }
});

test('Claude Code plugin and marketplace manifests are consistent', () => {
  const plugin = JSON.parse(fs.readFileSync(path.join(repo, '.claude-plugin/plugin.json'), 'utf8'));
  const market = JSON.parse(fs.readFileSync(path.join(repo, '.claude-plugin/marketplace.json'), 'utf8'));
  assert.match(plugin.name, /^[a-z0-9]+(-[a-z0-9]+)*$/);
  assert.equal(market.plugins.length, 1);
  assert.equal(market.plugins[0].name, plugin.name, 'marketplace entry name must equal the plugin manifest name');
  assert.equal(market.plugins[0].source, './');
  assert.ok(market.owner?.name);
  const meta = skillMd.match(/version: "([^"]+)"/);
  assert.equal(meta?.[1], plugin.version, 'skill metadata.version and plugin version should move together');
});
