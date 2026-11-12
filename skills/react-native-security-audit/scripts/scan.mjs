#!/usr/bin/env node
// Reconnaissance scanner for React Native / Expo projects.
//
//   node scan.mjs <project-dir> [--out leads.json] [--max-per-rule 8] [--json]
//
// Prints a project profile and a list of LEADS: places worth reading, each with
// a note on what decides whether it is real. Leads are not findings.
//
// Safe by construction: reads files only, never executes project code, never
// touches the network, and masks secret values in everything it prints.
// Zero dependencies; needs Node.js 18+.

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { RULES, FILE_CLASSES, SENSITIVE_FILE_KINDS, GENERIC_SECRET_ASSIGNMENT, looksLikeSecretValue } from './lib/rules.mjs';
import { SECRET_PATTERNS, redact, describeJwt } from './lib/secret-patterns.mjs';

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'Pods', 'build', '.gradle', '.expo', '.expo-shared', 'dist', 'web-build',
  'DerivedData', '.cxx', 'coverage', '.idea', '.vscode', '.yarn', '.pnpm-store', 'vendor',
  '.next', '.turbo', '.cache', 'xcuserdata', '__snapshots__', '.bundle',
]);
const TEXT_EXT = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.json', '.xml', '.plist', '.entitlements',
  '.gradle', '.kts', '.properties', '.java', '.kt', '.m', '.mm', '.swift', '.h', '.yml', '.yaml',
  '.rules', '.xcconfig', '.sh', '.rb', '.toml', '.pbxproj',
]);
const MAX_FILE_BYTES = 1_000_000;
const MAX_FILES = 20_000;
const EXCERPT_LEN = 180;
const ENV_SECRET_ASSIGNMENT =
  /\b([A-Za-z0-9_.]*(?:SECRET|PASSWORD|PRIVATE|TOKEN|API_?KEY|SERVICE_ROLE|CREDENTIAL)[A-Za-z0-9_]*)[ \t]*=[ \t]*["']?([^\s"'#]{8,})/gi;

const KNOWN_LIBRARIES = {
  plainStorage: ['@react-native-async-storage/async-storage', 'react-native-mmkv', 'redux-persist', 'zustand', '@tanstack/react-query-persist-client', 'apollo3-cache-persist', 'realm', '@nozbe/watermelondb', 'react-native-sqlite-storage', 'expo-sqlite', '@op-engineering/op-sqlite', 'react-native-fs', 'expo-file-system'],
  secureStorage: ['expo-secure-store', 'react-native-keychain', 'react-native-encrypted-storage', 'react-native-sensitive-info', 'redux-persist-sensitive-storage'],
  webview: ['react-native-webview'],
  auth: ['expo-auth-session', 'react-native-app-auth', '@react-native-google-signin/google-signin', 'react-native-auth0', '@clerk/clerk-expo', '@supabase/supabase-js', '@react-native-firebase/auth', 'firebase', 'aws-amplify', '@okta/okta-react-native', 'react-native-msal'],
  biometrics: ['expo-local-authentication', 'react-native-biometrics', 'react-native-touch-id'],
  navigation: ['expo-router', '@react-navigation/native', 'expo-linking'],
  network: ['axios', 'react-native-blob-util', 'rn-fetch-blob', '@apollo/client', 'socket.io-client'],
  pinning: ['react-native-ssl-public-key-pinning', 'react-native-ssl-pinning', 'react-native-cert-pinner', 'react-native-pinch'],
  crypto: ['crypto-js', 'react-native-quick-crypto', 'expo-crypto', 'react-native-get-random-values', 'react-native-aes-crypto', 'jwt-decode', 'jsrsasign', 'tweetnacl'],
  ota: ['expo-updates', 'react-native-code-push', '@code-push-next/react-native-code-push', 'react-native-ota-hot-update'],
  telemetry: ['@sentry/react-native', '@react-native-firebase/analytics', '@react-native-firebase/crashlytics', '@amplitude/analytics-react-native', 'mixpanel-react-native', 'posthog-react-native', '@segment/analytics-react-native', '@bugsnag/react-native', '@datadog/mobile-react-native', 'react-native-appsflyer', 'react-native-adjust'],
  devTools: ['reactotron-react-native', 'react-native-flipper', 'expo-dev-client', '@welldone-software/why-did-you-render'],
  resilience: ['jail-monkey', 'freerasp-react-native', 'react-native-obfuscating-transformer', '@react-native-firebase/app-check', '@expo/app-integrity', 'expo-screen-capture', 'react-native-privacy-snapshot'],
  payments: ['@stripe/stripe-react-native', 'react-native-purchases', 'react-native-iap', 'expo-in-app-purchases'],
};

function parseArgs(argv) {
  const args = { target: null, out: null, maxPerRule: 8, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out') args.out = argv[++i];
    else if (a === '--max-per-rule') args.maxPerRule = Number(argv[++i]);
    else if (a === '--json') args.json = true;
    else if (a === '-h' || a === '--help') args.help = true;
    else if (!args.target) args.target = a;
    else fail(`Unexpected argument: ${a}`);
  }
  return args;
}

function fail(msg) {
  process.stderr.write(`scan.mjs: ${msg}\nUsage: node scan.mjs <project-dir> [--out leads.json] [--max-per-rule N] [--json]\n`);
  process.exit(2);
}

function walk(root, excludeRel = null) {
  const files = [];
  const skipped = { tooLarge: [], limitReached: false };
  const stack = [''];
  while (stack.length) {
    const rel = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(path.join(root, rel), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const relPath = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue; // never follow links out of the project
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && relPath !== excludeRel) stack.push(relPath);
      } else if (e.isFile()) {
        if (files.length >= MAX_FILES) {
          skipped.limitReached = true;
          return { files, skipped };
        }
        files.push(relPath);
      }
    }
  }
  return { files: files.sort(), skipped };
}

function fileContext(relPath) {
  const p = `/${relPath}`;
  let variant = 'main';
  if (/\/src\/debug\/|\/debug\/|[.-]debug\.|Debug\.(plist|entitlements|xcconfig)$/i.test(p)) variant = 'debug';
  else if (/\/src\/release\/|[.-]release\./i.test(p)) variant = 'release';
  let context = 'app';
  if (/\/(__tests__|__mocks__|e2e|tests?|fixtures|stories|storybook|\.storybook)\/|\.(test|spec|stories)\.[jt]sx?$/i.test(p)) context = 'test';
  else if (/\.(example|sample|template|dist|defaults)$/i.test(p) || /\/(docs?|examples?)\//i.test(p)) context = 'example';
  else if (/\/(scripts|tools|\.github|fastlane|\.circleci|ci)\//i.test(p) || /(^|\/)(metro|babel|jest|webpack)\.config\.[cm]?[jt]s$/.test(relPath)) context = 'tooling';
  return { variant, context };
}

function readText(root, relPath, skipped) {
  const abs = path.join(root, relPath);
  let stat;
  try {
    stat = fs.statSync(abs);
  } catch {
    return null;
  }
  if (stat.size > MAX_FILE_BYTES) {
    skipped.tooLarge.push(relPath);
    return null;
  }
  const buf = fs.readFileSync(abs);
  if (buf.subarray(0, 4096).includes(0)) return null; // binary
  return buf.toString('utf8');
}

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function excerptAt(text, index, matchText, secret, keyValueFile = false) {
  const start = text.lastIndexOf('\n', index - 1) + 1;
  let end = text.indexOf('\n', index + Math.min(matchText.length, 1));
  if (end === -1) end = text.length;
  let line = text.slice(start, end);
  if (secret) line = line.split(secret).join(redact(secret));
  line = maskKnownSecrets(line, keyValueFile).replace(/\s+/g, ' ').trim();
  return line.length > EXCERPT_LEN ? `${line.slice(0, EXCERPT_LEN)}…` : line;
}

// Belt and braces: whatever rule produced an excerpt, provider-format secrets
// inside it are masked before anything is printed or written.
function maskKnownSecrets(s, keyValueFile = false) {
  let out = s;
  for (const p of SECRET_PATTERNS) {
    if (p.public) continue;
    p.re.lastIndex = 0;
    out = out.replace(p.re, (m) => redact(m));
  }
  GENERIC_SECRET_ASSIGNMENT.lastIndex = 0;
  out = out.replace(GENERIC_SECRET_ASSIGNMENT, (whole, name, value) =>
    looksLikeSecretValue(value, name) && !value.includes('[redacted:') ? whole.replace(value, redact(value)) : whole,
  );
  // Unquoted KEY=value lines. Only in env and properties files: in code the
  // right-hand side is an expression, not a value.
  if (!keyValueFile) return out;
  out = out.replace(ENV_SECRET_ASSIGNMENT, (whole, name, value) =>
    value.includes('[redacted:') || value.includes('…') ? whole : whole.replace(value, redact(value)),
  );
  return out;
}

function gitTracked(root) {
  try {
    const out = execFileSync('git', ['-c', 'core.fsmonitor=false', '-C', root, 'ls-files', '-z'], {
      encoding: 'utf8', timeout: 15_000, maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'],
    });
    return new Set(out.split('\0').filter(Boolean));
  } catch {
    return null; // not a git repo, or git unavailable
  }
}

function readJson(root, rel) {
  try {
    return JSON.parse(fs.readFileSync(path.join(root, rel), 'utf8'));
  } catch {
    return null;
  }
}

function buildProfile(root, files, tracked) {
  const has = (rel) => files.includes(rel);
  const pkg = readJson(root, 'package.json') || {};
  const deps = { ...(pkg.dependencies || {}) };
  const devDeps = { ...(pkg.devDependencies || {}) };
  const all = { ...devDeps, ...deps };

  const libraries = {};
  for (const [group, names] of Object.entries(KNOWN_LIBRARIES)) {
    const present = names.filter((n) => n in all).map((n) => (n in deps ? n : `${n} (dev)`));
    if (present.length) libraries[group] = present;
  }

  const hasAndroid = files.some((f) => f.startsWith('android/'));
  const hasIos = files.some((f) => f.startsWith('ios/'));
  const appJson = readJson(root, 'app.json');
  const expoCfg = appJson?.expo || null;
  const dynamicConfig = files.find((f) => /^app\.config\.(js|ts|mjs|cjs)$/.test(f)) || null;
  const usesExpo = 'expo' in all;

  let framework = 'bare-react-native';
  if (usesExpo) {
    const nativeTracked = tracked ? [...tracked].some((f) => f.startsWith('android/') || f.startsWith('ios/')) : null;
    if (!hasAndroid && !hasIos) framework = 'expo-managed (native projects generated at build time)';
    else if (nativeTracked === false) framework = 'expo-prebuild (android/ and ios/ present but untracked: generated)';
    else framework = 'expo with committed native projects';
  }

  const gradleProps = safeRead(root, 'android/gradle.properties');
  const podfile = safeRead(root, 'ios/Podfile');
  let hermes = 'default (on for RN >= 0.70)';
  if (/hermesEnabled\s*=\s*false/.test(gradleProps) || /:hermes_enabled\s*=>\s*false/.test(podfile) || expoCfg?.jsEngine === 'jsc') hermes = 'disabled on at least one platform';
  else if (/hermesEnabled\s*=\s*true/.test(gradleProps)) hermes = 'enabled';

  const entry = { androidSchemes: [], iosSchemes: [], expoScheme: null, associatedDomains: [], androidAutoVerify: false };
  for (const f of files.filter((x) => x.endsWith('AndroidManifest.xml') && !x.includes('/debug/'))) {
    const xml = safeRead(root, f);
    for (const m of xml.matchAll(/android:scheme\s*=\s*"([^"]+)"/g)) entry.androidSchemes.push(m[1]);
    if (/android:autoVerify\s*=\s*"true"/.test(xml)) entry.androidAutoVerify = true;
  }
  for (const f of files.filter((x) => /(^|\/)Info\.plist$/.test(x) && x.startsWith('ios/'))) {
    const xml = safeRead(root, f);
    for (const block of xml.matchAll(/<key>CFBundleURLSchemes<\/key>\s*<array>([\s\S]*?)<\/array>/g)) {
      for (const s of block[1].matchAll(/<string>([^<]+)<\/string>/g)) entry.iosSchemes.push(s[1]);
    }
  }
  for (const f of files.filter((x) => x.endsWith('.entitlements'))) {
    const xml = safeRead(root, f);
    for (const m of xml.matchAll(/<string>((?:applinks|webcredentials):[^<]+)<\/string>/g)) entry.associatedDomains.push(m[1]);
  }
  if (expoCfg) {
    entry.expoScheme = expoCfg.scheme ?? null;
    for (const d of expoCfg.ios?.associatedDomains || []) entry.associatedDomains.push(d);
  }
  entry.androidSchemes = [...new Set(entry.androidSchemes)];
  entry.iosSchemes = [...new Set(entry.iosSchemes)];
  entry.associatedDomains = [...new Set(entry.associatedDomains)];

  const expo = expoCfg
    ? {
        sdk: all.expo || null,
        dynamicConfig,
        plugins: (expoCfg.plugins || []).map((p) => (Array.isArray(p) ? p[0] : p)),
        extraKeys: Object.keys(expoCfg.extra || {}),
        androidAllowBackup: expoCfg.android?.allowBackup ?? 'unset (defaults to true)',
        updates: expoCfg.updates
          ? { url: expoCfg.updates.url || null, codeSigning: Boolean(expoCfg.updates.codeSigningCertificate) }
          : null,
      }
    : usesExpo
      ? { sdk: all.expo || null, dynamicConfig, note: 'No static app.json expo block: read the dynamic config by hand.' }
      : null;

  const lockfiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'].filter(has);

  return {
    name: pkg.name || path.basename(root),
    framework,
    reactNative: all['react-native'] || null,
    expo,
    hermes,
    newArchitecture: /newArchEnabled\s*=\s*true/.test(gradleProps) || expoCfg?.newArchEnabled === true ? 'enabled' : 'not explicitly enabled',
    platforms: { android: hasAndroid, ios: hasIos },
    monorepo: Boolean(pkg.workspaces) || has('pnpm-workspace.yaml'),
    lockfiles,
    patchesDir: files.some((f) => f.startsWith('patches/')),
    backendRulesInRepo: files.filter((f) => FILE_CLASSES.backendRules(f)),
    libraries,
    entryPoints: entry,
    git: tracked ? 'repository' : 'not a git repository (tracked status unknown)',
  };
}

function safeRead(root, rel) {
  try {
    return fs.readFileSync(path.join(root, rel), 'utf8');
  } catch {
    return '';
  }
}

function resolveFiles(rule) {
  return typeof rule.files === 'function' ? rule.files : FILE_CLASSES[rule.files];
}

// `exclude` is a directory inside the target to leave out, normally the audit's
// own output directory, so a re-run never reports leads from its own artifacts.
function scan(root, { exclude = null } = {}) {
  const excludeRel = exclude ? path.relative(root, path.resolve(exclude)).split(path.sep).join('/') : null;
  const { files, skipped } = walk(root, excludeRel && !excludeRel.startsWith('..') ? excludeRel : null);
  const tracked = gitTracked(root);
  const profile = buildProfile(root, files, tracked);

  const sensitiveFiles = [];
  for (const f of files) {
    for (const k of SENSITIVE_FILE_KINDS) {
      if (k.test(f)) {
        sensitiveFiles.push({ file: f, kind: k.kind, tracked: tracked ? tracked.has(f) : null, note: k.note });
        break;
      }
    }
  }

  const leads = [];
  const seen = new Set();
  const push = (lead) => {
    const key = `${lead.rule}|${lead.file}|${lead.line}`;
    if (seen.has(key)) return;
    seen.add(key);
    leads.push(lead);
  };

  let filesScanned = 0;
  for (const rel of files) {
    const ext = path.extname(rel);
    const isEnv = FILE_CLASSES.env(rel);
    if (!TEXT_EXT.has(ext) && !isEnv) continue;
    if (/(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(rel)) continue;
    const text = readText(root, rel, skipped);
    if (text == null) continue;
    filesScanned++;
    const ctx = fileContext(rel);
    const kv = isEnv || ext === '.properties';

    for (const p of SECRET_PATTERNS) {
      p.re.lastIndex = 0;
      for (const m of text.matchAll(p.re)) {
        const line = lineOf(text, m.index);
        let excerpt = excerptAt(text, m.index, m[0], m[0], kv);
        if (p.jwt) excerpt += `  [JWT claims: ${describeJwt(m[0])}]`;
        push({ rule: `SEC-${p.id.toUpperCase()}`, domain: 'secrets', file: rel, line, excerpt, ...ctx });
      }
    }

    for (const rule of RULES) {
      if (!resolveFiles(rule)(rel)) continue;
      rule.re.lastIndex = 0;
      for (const m of text.matchAll(rule.re)) {
        if (rule.keep && !rule.keep(m, ctx)) continue;
        const secret = typeof rule.redact === 'function' ? rule.redact(m) : rule.redact ? m[rule.redact] : null;
        push({
          rule: rule.id,
          domain: rule.domain,
          file: rel,
          line: lineOf(text, m.index),
          excerpt: excerptAt(text, m.index, m[0], secret, kv),
          ...ctx,
        });
        if (rule.oncePerFile) break;
      }
    }
  }

  // Structural checks that are about something being absent.
  const mainManifest = files.find((f) => /android\/app\/src\/main\/AndroidManifest\.xml$/.test(f));
  if (mainManifest) {
    const xml = safeRead(root, mainManifest);
    const app = xml.match(/<application\b[^>]*>/);
    if (app && !/android:allowBackup\s*=/.test(app[0])) {
      push({
        rule: 'PLT-ANDROID-BACKUP-ENABLED', domain: 'platform', file: mainManifest,
        line: lineOf(xml, app.index), excerpt: '<application> has no android:allowBackup attribute (defaults to true)',
        variant: 'main', context: 'app',
      });
    }
  }
  if (profile.lockfiles.length === 0 && files.includes('package.json')) {
    push({ rule: 'SUP-NO-LOCKFILE', domain: 'supply-chain', file: 'package.json', line: 1, excerpt: 'No lockfile found next to package.json', variant: 'main', context: 'app' });
  }

  const ruleInfo = {};
  for (const r of RULES) ruleInfo[r.id] = { title: r.title, masvs: r.masvs, signal: r.signal, triage: r.triage };
  for (const p of SECRET_PATTERNS) {
    ruleInfo[`SEC-${p.id.toUpperCase()}`] = {
      title: p.label,
      masvs: ['MASVS-AUTH-1'],
      signal: p.public ? 'low' : p.jwt ? 'medium' : 'high',
      triage: p.public
        ? 'Public client identifier by design. Not a secret; the question is whether the key is restricted (bundle id / package + SHA-1, API allowlist) on the provider side, which only the owner can confirm.'
        : p.jwt
          ? 'Read the decoded claims. A Supabase `anon` token is public; a `service_role` token or a long-lived user/admin token is a real credential.'
          : 'Provider-format credential. Establish whether it reaches the app bundle, the repository only, or just a test fixture, and what it can do. Do not call the provider to check that it works.',
    };
  }
  ruleInfo['SUP-NO-LOCKFILE'] = { title: 'No dependency lockfile', masvs: ['MASVS-CODE-3'], signal: 'medium', triage: 'Without a lockfile every install can resolve different code. Check whether one exists higher up (monorepo root).' };

  return {
    schema: 'rn-audit-scan/1',
    target: path.basename(root),
    profile,
    sensitiveFiles,
    leads,
    rules: Object.fromEntries(Object.entries(ruleInfo).filter(([id]) => leads.some((l) => l.rule === id))),
    stats: {
      filesSeen: files.length,
      filesScanned,
      leads: leads.length,
      skippedTooLarge: skipped.tooLarge,
      fileLimitReached: skipped.limitReached,
    },
  };
}

const DOMAIN_ORDER = ['secrets', 'storage', 'crypto', 'auth', 'network', 'platform', 'supply-chain', 'privacy'];
const SIGNAL_ORDER = { high: 0, medium: 1, low: 2 };

function renderSummary(result, maxPerRule) {
  const out = [];
  const p = result.profile;
  out.push(`# Scan of ${result.target}`, '');
  out.push('These are leads to read and judge, not findings. Secret values are masked.', '');
  out.push('## Project profile', '');
  out.push(`- Framework: ${p.framework}`);
  out.push(`- React Native: ${p.reactNative ?? 'not found in package.json'}${p.expo?.sdk ? ` | Expo: ${p.expo.sdk}` : ''}`);
  out.push(`- Hermes: ${p.hermes}`);
  out.push(`- Native projects present: android=${p.platforms.android}, ios=${p.platforms.ios} | monorepo: ${p.monorepo}`);
  out.push(`- Lockfiles: ${p.lockfiles.join(', ') || 'none'} | patches/: ${p.patchesDir} | source control: ${p.git}`);
  if (p.expo) {
    if (p.expo.dynamicConfig) out.push(`- Expo dynamic config: ${p.expo.dynamicConfig} (not evaluated: read it)`);
    if (p.expo.plugins?.length) out.push(`- Expo config plugins: ${p.expo.plugins.join(', ')}`);
    if (p.expo.extraKeys?.length) out.push(`- Expo extra keys (all embedded in the app): ${p.expo.extraKeys.join(', ')}`);
    if ('androidAllowBackup' in p.expo) out.push(`- Expo android.allowBackup: ${p.expo.androidAllowBackup}`);
    if (p.expo.updates) out.push(`- Expo updates: url=${p.expo.updates.url ?? 'none'}, code signing=${p.expo.updates.codeSigning}`);
  }
  const e = p.entryPoints;
  out.push(`- URL schemes: android=[${e.androidSchemes.join(', ')}] ios=[${e.iosSchemes.join(', ')}]${e.expoScheme ? ` expo=${JSON.stringify(e.expoScheme)}` : ''}`);
  out.push(`- Verified links: associated domains=[${e.associatedDomains.join(', ')}], android autoVerify=${e.androidAutoVerify}`);
  if (p.backendRulesInRepo.length) out.push(`- Backend rules in repo: ${p.backendRulesInRepo.join(', ')}`);
  out.push('- Libraries by concern:');
  for (const [group, names] of Object.entries(p.libraries)) out.push(`  - ${group}: ${names.join(', ')}`);
  if (!Object.keys(p.libraries).length) out.push('  - (none recognised)');
  out.push('');

  out.push('## Sensitive files', '');
  if (!result.sensitiveFiles.length) {
    out.push('None found by file name (env files, keystores, signing certificates and keys, Firebase config, sentry.properties, .npmrc, committed bundles and source maps). Secrets inside other files appear as leads below.', '');
  } else {
    for (const f of result.sensitiveFiles) {
      const t = f.tracked === null ? 'tracked: unknown' : f.tracked ? 'TRACKED in git' : 'untracked';
      out.push(`- ${f.file} [${f.kind}, ${t}] ${f.note}`);
    }
    out.push('');
  }

  out.push(`## Leads (${result.leads.length} hit${result.leads.length === 1 ? '' : 's'} across ${Object.keys(result.rules).length} rule${Object.keys(result.rules).length === 1 ? '' : 's'})`, '');
  if (!result.leads.length) out.push('No rule matched. That is not a clean bill of health: logic issues are found by reading, not by pattern.', '');
  for (const domain of DOMAIN_ORDER) {
    const inDomain = result.leads.filter((l) => l.domain === domain);
    if (!inDomain.length) continue;
    out.push(`### ${domain}`, '');
    const ruleIds = [...new Set(inDomain.map((l) => l.rule))].sort(
      (a, b) => SIGNAL_ORDER[result.rules[a].signal] - SIGNAL_ORDER[result.rules[b].signal] || a.localeCompare(b),
    );
    for (const id of ruleIds) {
      const info = result.rules[id];
      const hits = inDomain.filter((l) => l.rule === id);
      // App code in the shipping variant first; tests, examples and debug-only files last.
      const rank = (l) => (l.context === 'app' ? 0 : 2) + (l.variant === 'debug' ? 1 : 0);
      hits.sort((a, b) => rank(a) - rank(b));
      out.push(`**${id}** — ${info.title} (${hits.length} hit${hits.length === 1 ? '' : 's'}, signal: ${info.signal}, ${info.masvs.join(' ')})`);
      out.push(`Triage: ${info.triage}`);
      for (const h of hits.slice(0, maxPerRule)) {
        const tags = [h.context !== 'app' ? h.context : null, h.variant !== 'main' ? `${h.variant} variant` : null].filter(Boolean);
        out.push(`- ${h.file}:${h.line}${tags.length ? ` [${tags.join(', ')}]` : ''}  ${h.excerpt}`);
      }
      if (hits.length > maxPerRule) out.push(`- … ${hits.length - maxPerRule} more (see the JSON output)`);
      out.push('');
    }
  }

  const quiet = DOMAIN_ORDER.filter((d) => !result.leads.some((l) => l.domain === d));
  if (quiet.length) out.push(`Domains with no leads: ${quiet.join(', ')}. No pattern matched there; they still need reading (resilience has no patterns at all).`, '');
  out.push('## Scan limits', '');
  out.push(`- ${result.stats.filesScanned} source and config files scanned, of ${result.stats.filesSeen} files seen. Not scanned: node_modules, Pods, build output, lockfiles, binaries, and file types with no rules (docs, images).`);
  if (result.stats.skippedTooLarge.length) out.push(`- Too large to scan (>1 MB): ${result.stats.skippedTooLarge.slice(0, 10).join(', ')}`);
  if (result.stats.fileLimitReached) out.push(`- File limit reached: the scan is partial. Re-run on a subdirectory.`);
  out.push('- Not covered by any pattern: authorization logic, server behaviour, git history, compiled binaries, third-party SDK internals.');
  return out.join('\n');
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) fail('help');
  if (!args.target) fail('Missing <project-dir>.');
  const root = path.resolve(args.target);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) fail(`Not a directory: ${root}`);
  if (!Number.isInteger(args.maxPerRule) || args.maxPerRule < 1) fail('--max-per-rule must be a positive integer.');

  // Leave the output directory out of the scan when it sits inside the target.
  const result = scan(root, { exclude: args.out ? path.dirname(path.resolve(args.out)) : null });
  if (args.out) {
    fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true });
    fs.writeFileSync(args.out, `${JSON.stringify(result, null, 2)}\n`);
  }
  process.stdout.write(args.json ? `${JSON.stringify(result, null, 2)}\n` : `${renderSummary(result, args.maxPerRule)}\n`);
  if (!fs.existsSync(path.join(root, 'package.json'))) {
    process.stderr.write('scan.mjs: warning: no package.json in the target. Point the scanner at the app root (in a monorepo, the app package).\n');
  }
}

export { scan, renderSummary };

// Skills are often installed as symlinks, so compare real paths.
if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) main();
