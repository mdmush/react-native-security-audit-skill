import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scripts = path.join(repo, 'skills/react-native-security-audit/scripts');
const { scan, renderSummary } = await import(path.join(scripts, 'scan.mjs'));
const fixture = path.join(repo, 'evals/full-audit-pre-release/files');

// Build a throwaway project. Secret-shaped values are assembled at runtime so
// no provider-format credential is ever stored in this repository.
function project(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rn-scan-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return dir;
}
const pkg = (deps = {}) => JSON.stringify({ name: 'demo', dependencies: { 'react-native': '0.76.0', ...deps } });
const rulesHit = (result) => new Set(result.leads.map((l) => l.rule));
const lead = (result, rule, file) => result.leads.find((l) => l.rule === rule && (!file || l.file === file));

test('fixture app: the planted issues are surfaced as leads', () => {
  const r = scan(fixture);
  const hit = rulesHit(r);
  for (const rule of [
    'SEC-GENERIC-ASSIGNMENT', // payments secret in src/config/keys.ts
    'SEC-OAUTH-CLIENT-SECRET',
    'SEC-GRADLE-SIGNING-PASSWORD',
    'STO-PERSISTED-STATE',
    'STO-SENSITIVE-LOGGING',
    'AUTH-OAUTH-WEAK-FLOW',
    'AUTH-CLIENT-SIDE-AUTHZ',
    'NET-CUSTOM-TRUST-ANDROID',
    'PLT-NAVIGATION-LINKING-CONFIG',
    'PLT-WEBVIEW',
    'PLT-WEBVIEW-ANY-ORIGIN',
    'PLT-WEBVIEW-BRIDGE',
    'PLT-ANDROID-BACKUP-ENABLED',
  ]) {
    assert.ok(hit.has(rule), `expected a ${rule} lead`);
  }
  assert.equal(lead(r, 'SEC-GENERIC-ASSIGNMENT').file, 'src/config/keys.ts');
});

test('fixture app: profile reads the project correctly', () => {
  const { profile } = scan(fixture);
  assert.equal(profile.framework, 'bare-react-native');
  assert.equal(profile.reactNative, '0.76.5');
  assert.equal(profile.hermes, 'enabled');
  assert.deepEqual(profile.entryPoints.androidSchemes, ['shopmate']);
  assert.deepEqual(profile.entryPoints.iosSchemes, ['shopmate']);
  assert.ok(profile.libraries.webview.includes('react-native-webview'));
  assert.ok(profile.libraries.plainStorage.includes('redux-persist'));
});

test('fixture app: decoys are tagged or left alone', () => {
  const r = scan(fixture);
  const cleartext = lead(r, 'PLT-ANDROID-CLEARTEXT-ALLOWED');
  assert.equal(cleartext.variant, 'debug', 'the debug manifest must be tagged as the debug variant');
  assert.equal(lead(r, 'STO-ASYNCSTORAGE-SENSITIVE', 'src/__tests__/auth.test.ts').context, 'test');
  assert.ok(!rulesHit(r).has('CRY-MATH-RANDOM-SECURITY'), 'Math.random for UI jitter is not a lead');
  assert.ok(!rulesHit(r).has('PLT-IOS-ATS-DISABLED'), 'NSAllowsLocalNetworking alone is not a lead');
  assert.ok(!r.leads.some((l) => l.file === '.env.example'), 'placeholder values in example env files are ignored');
  assert.ok(!r.leads.some((l) => l.excerpt.includes('storePassword')), 'Gradle variable references are not passwords');
});

test('no secret value survives into scanner output', () => {
  const r = scan(fixture);
  const all = JSON.stringify(r) + renderSummary(r, 50);
  for (const secret of ['pay_live_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c', 'smc_2b7e151628aed2a6abf7158809cf4f3c', 'Tr0ub4dor-Upload-2024']) {
    assert.ok(!all.includes(secret), 'a secret value leaked into scanner output');
  }
  assert.match(all, /pay_…\[redacted:41 chars\]/);
});

test('provider-format secrets are detected and masked', () => {
  const aws = 'AKIA' + 'Q7ZK4T2MXW9PL3VB';
  const stripe = 'sk_' + 'live_' + '4eC39HqLyjWDarjtT1zdp7dc';
  const llm = 'sk-' + 'ant-' + 'api03-' + 'x'.repeat(40);
  const dir = project({
    'package.json': pkg(),
    'src/keys.ts': `export const a = "${aws}";\nexport const b = "${stripe}";\nconst c = "${llm}";\n`,
  });
  const r = scan(dir);
  const hit = rulesHit(r);
  assert.ok(hit.has('SEC-AWS-ACCESS-KEY') && hit.has('SEC-STRIPE-SECRET') && hit.has('SEC-LLM-API-KEY'));
  const out = JSON.stringify(r);
  for (const s of [aws, stripe, llm]) assert.ok(!out.includes(s));
});

test('JWT claims are decoded so an anon key can be told from a service_role key', () => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const jwt = (role) => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', role, exp: 2000000000 })}.${'s'.repeat(43)}`;
  const dir = project({
    'package.json': pkg(),
    'src/supabase.ts': `const anon = "${jwt('anon')}";\nconst admin = "${jwt('service_role')}";\n`,
  });
  const jwts = scan(dir).leads.filter((l) => l.rule === 'SEC-JWT');
  assert.equal(jwts.length, 2);
  assert.match(jwts[0].excerpt, /role=anon/);
  assert.match(jwts[1].excerpt, /role=service_role/);
});

test('Expo project: bundled env names, config and workflow are reported', () => {
  const dir = project({
    'package.json': pkg({ expo: '~52.0.0', 'expo-router': '4.0.0', 'expo-secure-store': '14.0.0' }),
    'app.json': JSON.stringify({
      expo: {
        scheme: 'demo',
        extra: { apiUrl: 'https://api.example.com', eas: { projectId: 'x' } },
        updates: { url: 'https://u.expo.dev/x' },
        ios: { infoPlist: { NSAppTransportSecurity: { NSAllowsArbitraryLoads: true } } },
      },
    }),
    '.env': 'EXPO_PUBLIC_API_URL=https://api.example.com\nEXPO_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=svc_4f9a8b7c6d5e4f3a2b1c\n',
    'app/item/[id].tsx': 'import { useLocalSearchParams } from "expo-router";\nexport default function S() { const { id } = useLocalSearchParams<{ id: string }>(); return null; }\n',
  });
  const r = scan(dir);
  assert.match(r.profile.framework, /expo-managed/);
  assert.equal(r.profile.entryPoints.expoScheme, 'demo');
  assert.equal(r.profile.expo.updates.codeSigning, false);
  assert.deepEqual(r.profile.expo.extraKeys, ['apiUrl', 'eas']);
  const hit = rulesHit(r);
  assert.ok(hit.has('SEC-PUBLIC-ENV-SECRET-NAME'));
  assert.ok(hit.has('PLT-ROUTE-PARAMS'));
  assert.ok(hit.has('PLT-IOS-ATS-DISABLED'));
  assert.ok(r.sensitiveFiles.some((f) => f.file === '.env' && f.kind === 'env-file'));
  assert.ok(!JSON.stringify(r).includes('svc_4f9a8b7c6d5e4f3a2b1c'));
});

test('labels, i18n keys and placeholders are not mistaken for secrets', () => {
  const dir = project({
    'package.json': pkg(),
    'src/form.ts': [
      'const labels = { password: "Password", apiKey: "your_api_key_here" };',
      'const t = { passwordHint: "auth.password.hint" };',
      'const cfg = { secretKey: process.env.SECRET_KEY, apiKey: "" };',
      'const accessToken = "xxxxxxxxxxxxxxxx";',
    ].join('\n'),
  });
  assert.equal(scan(dir).leads.filter((l) => l.domain === 'secrets').length, 0);
});

test('node_modules and build output are never scanned', () => {
  const dir = project({
    'package.json': pkg(),
    'node_modules/evil/index.js': 'const apiSecret = "abcd1234efgh5678ijkl";',
    'android/app/build/generated/x.js': 'const apiSecret = "abcd1234efgh5678ijkl";',
    'ios/Pods/x.m': 'allowsAnyHTTPSCertificate',
  });
  assert.equal(scan(dir).leads.filter((l) => l.domain !== 'supply-chain').length, 0);
});

test('missing allowBackup attribute is reported as the default-true case', () => {
  const dir = project({
    'package.json': pkg(),
    'android/app/src/main/AndroidManifest.xml': '<manifest>\n  <application\n    android:name=".MainApplication">\n  </application>\n</manifest>\n',
  });
  const l = lead(scan(dir), 'PLT-ANDROID-BACKUP-ENABLED');
  assert.ok(l && /defaults to true/.test(l.excerpt));
  assert.equal(l.line, 2);
});

test('CLI runs through a symlinked install and writes JSON', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rn-scan-cli-'));
  const link = path.join(dir, 'skill-link');
  fs.symlinkSync(path.join(repo, 'skills/react-native-security-audit'), link);
  const out = path.join(dir, 'out/leads.json');
  const stdout = execFileSync('node', [path.join(link, 'scripts/scan.mjs'), fixture, '--out', out], { encoding: 'utf8' });
  assert.match(stdout, /## Project profile/);
  assert.match(stdout, /These are leads to read and judge, not findings/);
  const json = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(json.schema, 'rn-audit-scan/1');
  assert.ok(json.leads.length > 10);
});

test('CLI rejects a missing target with a usage error', () => {
  assert.throws(() => execFileSync('node', [path.join(scripts, 'scan.mjs'), '/nonexistent/dir'], { stdio: 'pipe' }), (e) => e.status === 2);
});

test('direct calls to secret-key APIs, the password grant and iCloud keychain sync are leads', () => {
  const dir = project({
    'package.json': pkg(),
    'src/ai.ts': "export const ask = (k: string) => fetch('https://api.anthropic.com/v1/messages', { headers: { 'x-api-key': k } });\n",
    'src/login.ts': "const body = new URLSearchParams({ grant_type: 'password', username, password });\n",
    'src/vault.ts': "await Keychain.setGenericPassword('u', token, { cloudSync: true });\n",
  });
  const hit = rulesHit(scan(dir));
  assert.ok(hit.has('SEC-SECRET-KEY-API-CALLED-FROM-CLIENT'));
  assert.ok(hit.has('AUTH-OAUTH-WEAK-FLOW'));
  assert.ok(hit.has('STO-KEYCHAIN-CLOUD-SYNC'));
});

test('an env line with a bundled-prefix secret name is reported once', () => {
  const dir = project({ 'package.json': pkg(), '.env': 'EXPO_PUBLIC_MAILER_SECRET_KEY=mlr_9c2f7a1e5b8d4063a7f1\nBACKEND_API_TOKEN=tok_7a1e5b8d40639c2f\n' });
  const leads = scan(dir).leads.filter((l) => l.file === '.env');
  assert.deepEqual(leads.map((l) => l.rule).sort(), ['SEC-ENV-FILE-VALUE', 'SEC-PUBLIC-ENV-SECRET-NAME']);
  assert.deepEqual(leads.map((l) => l.line).sort(), [1, 2]);
});

test('an output directory inside the target is not scanned', () => {
  const dir = project({
    'package.json': pkg(),
    'audit-output/findings.json': JSON.stringify({ note: 'clientSecret: "abcd1234efgh5678"' }),
    'audit-output/old.ts': 'const apiSecret = "abcd1234efgh5678ijkl";',
  });
  assert.ok(scan(dir).leads.some((l) => l.file.startsWith('audit-output/')), 'scanned when not excluded');
  assert.ok(!scan(dir, { exclude: path.join(dir, 'audit-output') }).leads.some((l) => l.file.startsWith('audit-output/')));
  const out = execFileSync('node', [path.join(scripts, 'scan.mjs'), dir, '--out', path.join(dir, 'audit-output/leads.json'), '--json'], { encoding: 'utf8' });
  assert.ok(!JSON.parse(out).leads.some((l) => l.file.startsWith('audit-output/')));
});

test('summary always states sensitive-file and quiet-domain status', () => {
  const text = renderSummary(scan(fixture), 8);
  assert.match(text, /## Sensitive files\n\nNone found by file name/);
  assert.match(text, /Domains with no leads: crypto/);
  assert.match(text, /hits across \d+ rules/);
});
