---
name: react-native-security-audit
description: Security audit and vulnerability review for React Native and Expo apps, covering the JavaScript/TypeScript code and the native Android and iOS projects. Use whenever the user asks to audit, pen-test, security-review or harden a React Native or Expo app, wants a pre-release or compliance check (OWASP MASVS, MASTG, Mobile Top 10), or asks a security question about one - hardcoded API keys and secrets in the bundle, .env or EXPO_PUBLIC values, token storage (AsyncStorage, SecureStore, Keychain, MMKV, redux-persist), deep links, WebViews, OAuth and PKCE, certificate pinning, biometrics, AndroidManifest or Info.plist settings, OTA updates (EAS Update, CodePush) or risky dependencies. Also use when reviewing a diff or PR in a mobile app for security impact, even if the user never says the word audit. Runs the full report-producing workflow only when a full audit or a report is requested; otherwise gives focused guidance.
license: MIT
compatibility: Bundled scripts need Node.js 18+ (already part of any React Native toolchain), with no dependencies to install and no network access. Sub-agents are used when the host agent provides them and are optional.
metadata:
  author: mdmush
  version: "1.0.0"
---

# React Native Security Audit

Find the weaknesses in a React Native or Expo app that let someone cross a real trust boundary on a real device, and hand the owner the evidence, an honest severity, and the smallest fix that works.

A pattern match is a lead. It becomes a finding only when you can name who the attacker is, how they reach the code in the build that ships, and what they get. Most of the value of this skill is in that step: mobile audits fail by drowning real issues in checklist noise far more often than by missing a grep hit.

## Pick a mode first

Loading this skill does not by itself authorize a full audit or writing files.

- **Focused mode** (default). A security question, a review of specific files or a diff, triage of one suspected issue. Read only the reference files that apply, answer in the conversation, and write no artifacts. You may run the scanner without `--out` (it then writes nothing); it is the safe way to look at env and config files because it masks values. Apply the same evidence bar and severity anchors as a full audit: before calling something a vulnerability, run the refutation checklist in [references/validation-and-reporting.md](references/validation-and-reporting.md). Answer in plain terms (fix this, this is fine, this needs checking on the server) with one severity word where it helps.
- **Full audit mode.** The user asks to audit, pen-test or security-review the app or codebase, asks for a pre-release or compliance review, or asks for a report. Run every step of the workflow below and write the artifacts.
- **Scoped audit.** A full audit limited to named paths, one platform, or the changes between two refs. Same workflow, but record the scope and mark every domain you did not review as not reviewed. Never let a scoped run read as a clean bill of health for the rest.

If you cannot tell which the user wants, ask one short question before creating files.

## Ground rules

These hold in every mode.

- **Read, do not run.** Inspecting source is always fine. Do not build the app, run its tests, install dependencies, or run `expo prebuild` or `npx expo config` without asking first: all of them execute project-controlled code (lifecycle scripts, config plugins, Gradle and CocoaPods hooks). When a decisive fact needs one of them, say so and let the user choose.
- **Never use what you find.** Do not call a provider to check whether a discovered key works, do not log in with found credentials, do not send requests to the app's backend or any deployed service. Whether a key is live is the owner's fact to confirm; you report where it is and what it could do.
- **Redact secrets everywhere.** In the conversation, in notes and in artifacts, show a secret as its first four characters plus its length. An audit report that contains working credentials is itself a leak. The bundled scanner masks values for you; do not undo that by pasting the source line. Prefer the scanner over opening `.env`, `gradle.properties` and similar files directly, since a direct read puts the raw values into the transcript.
- **Do not edit the audited project** during an audit. Describe fixes. Apply them only if the user asks, as a separate step afterwards, using [references/remediation.md](references/remediation.md).
- **Network tools need a yes.** `npm audit`, `yarn npm audit` and similar send the dependency list to a registry. Offer them; do not run them unprompted.

## Three facts that decide most mobile findings

Keep these in mind before reading any code. They are where generic web-security instincts go wrong.

**1. The app bundle is public.** Anyone can download the IPA or APK and read every string in it. Hermes bytecode, minification and obfuscation slow that down by minutes. So anything the JavaScript can read at runtime without the user logging in is known to every attacker: `EXPO_PUBLIC_*` variables, `react-native-config` and `react-native-dotenv` values, `app.json` `extra`, `google-services.json`. Moving a secret "into an environment variable" changes nothing, because the variable is inlined at build time. A real secret has exactly one fix: it moves to a server, and the app talks to that server as an authenticated user. The other half of this fact matters just as much: many values that look like secrets are public identifiers by design (Firebase config, a Stripe publishable key, a Sentry DSN, a Supabase anon key). Reporting those as leaked credentials is the most common false positive in mobile audits. [references/secrets-and-config.md](references/secrets-and-config.md) has the table that tells them apart.

**2. Every finding has a named attacker.** "Insecure" means nothing until you say for whom. Use exactly one of these classes per finding; it drives severity.

| Attacker | Starting capability | Typical issues |
|---|---|---|
| `binary-holder` | Downloads the app and unpacks it | Backend secrets in the bundle, hidden endpoints, logic that trusts the client |
| `remote-content` | Gets the victim to open a link, scan a QR code, receive a push, or view a page inside a WebView | Deep-link abuse, WebView bridge abuse, open redirects into authenticated views |
| `local-app` | Has another app installed on the same device | Custom-scheme hijacking, exported Android components, shared storage, pasteboard |
| `network` | Sits on the path (public Wi-Fi, hostile proxy) | Cleartext traffic, disabled TLS validation |
| `device-access` | Holds the unlocked or backed-up device, no root | Plaintext tokens and PII in backups and app files, screenshots, Files-app exposure |
| `compromised-device` | Root, jailbreak or instrumentation, including the device's own user | Bypassing client-side gates: biometrics as a boolean, paywalls, root checks |
| `backend-peer` | Is another logged-in user of the same backend | Client-only authorization, IDs the server may not check |
| `supply-chain` | Controls a dependency, build step or update channel, or can read the repository | Unsigned OTA updates, committed signing keys, install scripts, CI secrets |

If you cannot fit a candidate into a row, it is not a finding yet.

**3. Only the release build ships.** Debug manifests, `src/debug/`, `__DEV__` branches (Metro strips them from release bundles), Flipper and dev-client code, test fixtures and example env files do not reach users. Always establish which build variant a setting belongs to before reporting it. With Expo's managed workflow there may be no `android/` or `ios/` directory at all, or an untracked generated one: the native configuration is then produced from `app.json`/`app.config.*` and config plugins, so audit those, and treat anything you cannot derive from them as unknown rather than assumed. See [references/expo.md](references/expo.md).

## Full audit workflow

Work through the steps in order. Scripts live in `scripts/` next to this file; in the commands below `<skill-dir>` is the directory that contains this `SKILL.md`.

### Step 0: Setup

Resolve and state these before reading code:

- **Target**: the app root (the directory with the app's `package.json`). In a monorepo, the app package, plus any shared packages it imports.
- **Source ref**: the commit hash and whether the worktree is dirty, or "not a git repository".
- **Output directory**: the user's choice if given. Otherwise a new directory outside the repository, by default `~/rn-security-audits/<project>/<YYYY-MM-DD>-<n>/`. Audit artifacts describe how to attack the app, so they should not be committed by accident; write inside the repository only if the user asks, and tell them to keep the directory out of version control.
- **Scope**: full, or the named subset.

### Step 1: Reconnaissance

Run the scanner. It only reads files, never executes project code, and masks secrets:

```bash
node <skill-dir>/scripts/scan.mjs <target> --out <output-dir>/leads.json
```

It prints a project profile (framework and workflow, RN and Expo versions, Hermes, URL schemes, security-relevant libraries), any sensitive files by name with their git-tracked status, and leads grouped by domain. Each lead has a triage line saying what decides whether it is real. A rule's `signal` is how often that pattern turns out to be real, not how severe it would be: a low-signal lead can be the critical finding. An output directory inside the target is left out of the scan.

Then read enough to sketch the app's attack surface in a few lines, because the scanner cannot see design:

- How does a user authenticate, and where do the tokens live afterwards?
- What comes into the app from outside: URL schemes and universal links, push payloads, WebView content, files and share intents, exported Android components, OTA updates?
- What does the app talk to: its own API, third-party APIs called directly from the client, a backend-as-a-service (Firebase, Supabase, Amplify)?
- What native code exists beyond the template (custom modules, networking setup, `AppDelegate` and `MainApplication` changes)?

Skim [references/threat-model.md](references/threat-model.md) if this is your first audit with the skill in this session.

### Step 2: Hunt by domain

Work through the nine domains. For each one, read its reference file, follow the scanner's leads into the source, then look for what no pattern finds (logic and data-flow problems are listed in each reference). Mark a domain not applicable only with a reason ("no WebView and no deep-link config in the project").

| Domain | Look for | Reference |
|---|---|---|
| `secrets` | Credentials the app holds or that sit in app config and env files; public identifiers correctly left alone | [references/secrets-and-config.md](references/secrets-and-config.md) |
| `storage` | Tokens and PII in plaintext storage, persisted state, logs, backups | [references/data-storage-and-crypto.md](references/data-storage-and-crypto.md) |
| `crypto` | Predictable randomness, hardcoded keys, home-made schemes | [references/data-storage-and-crypto.md](references/data-storage-and-crypto.md) |
| `auth` | OAuth and session flows, biometrics, client-side authorization | [references/network-and-auth.md](references/network-and-auth.md) |
| `network` | Cleartext, broken TLS validation, credentials in URLs, pinning status | [references/network-and-auth.md](references/network-and-auth.md) |
| `platform` | Deep links, WebViews and bridges, exported components, native config | [references/platform-entry-points.md](references/platform-entry-points.md), plus [references/android.md](references/android.md) and [references/ios.md](references/ios.md) |
| `supply-chain` | Dependencies, install scripts, OTA updates, signing keys and passwords, CI and publish credentials | [references/supply-chain-and-release.md](references/supply-chain-and-release.md) |
| `privacy` | Permissions, data sent to third-party SDKs, tracking | [references/android.md](references/android.md), [references/ios.md](references/ios.md) |
| `resilience` | Debuggable builds, tamper and root handling, where the app's threat model calls for it | [references/supply-chain-and-release.md](references/supply-chain-and-release.md) |

For an Expo project, also read [references/expo.md](references/expo.md) before the platform domain.

Keep a running list of candidates. For each, note the files and lines, the attacker class, and what you still need to check.

**With sub-agents.** If your platform can delegate, give each domain (or a pair of small ones) to its own agent in parallel. Each brief must stand alone: the target path, the profile and that domain's leads from the scanner output, the absolute paths of this file and the relevant references to read, the ground rules above, and the instruction to return candidates as structured records (title, attacker, locations, the trace, what is unverified) rather than prose. Without sub-agents, do the domains yourself in table order.

### Step 3: Try to break each candidate

Before anything is recorded as confirmed, attack your own claim. Read [references/validation-and-reporting.md](references/validation-and-reporting.md) and run its refutation checklist on every candidate. The short version:

1. Re-open every cited file and line. Does the code say what you think it says?
2. Is it in the release build, and reachable?
3. Is there a control elsewhere that already stops it (a server check you can see, an OS default, a wrapper)?
4. Can you state the attacker class and one concrete thing they gain?
5. Does the decisive fact live outside the repository?

Then assign one of three verdicts:

- **confirmed**: the path from the attacker's entry point to the effect is visible in source and configuration for the release build, with no unknowns that could remove it.
- **needs_validation**: a specific, source-grounded lead whose deciding fact is outside the repository (what the server enforces, how a key is restricted in a provider console, what a generated native project contains, which rules are deployed). State exactly what is unknown and how the owner can settle it safely. Not a parking place for vague worries, and never given a severity.
- **rejected**: investigated and refuted. Keep a one-line record so the next run does not rediscover it.

Things that are good practice but cross no boundary by themselves (no certificate pinning, no root detection, no obfuscation, a permissive setting with nothing behind it) go in the separate **hardening** list, unrated.

**With sub-agents**, the checker must not be the finder: hand each candidate to a fresh agent with only the candidate record, the source access and the validation reference, and ask it to refute the claim. A finding that survives someone trying to disprove it is worth far more than one its author likes.

### Step 4: Record

Write `<output-dir>/findings.json` following [assets/findings.example.json](assets/findings.example.json) (schema: [assets/findings.schema.json](assets/findings.schema.json)). It holds the run facts, a short posture summary, coverage for all nine domains, every confirmed, needs-validation and rejected record, and the hardening notes. Then validate it against the audited source:

```bash
node <skill-dir>/scripts/validate-findings.mjs <output-dir>/findings.json --target <target>
```

The validator checks that every cited file and line exists, that only confirmed records carry a severity, that each verdict has the fields it needs, that all nine domains are accounted for, and that no unredacted credential is in the file. Fix every error. Treat its warnings as a prompt to re-read the severity anchors, not as noise.

### Step 5: Report

Render the report from the validated records, so prose and data cannot drift apart:

```bash
node <skill-dir>/scripts/render-report.mjs <output-dir>/findings.json --target <target> --out <output-dir>/REPORT.md
```

Finish with a short message to the user: where the artifacts are, the confirmed findings by severity in one line each, what needs their validation, and what was not covered. Lead with what they should fix first. Do not paste the whole report.

## Severity

Rate only confirmed findings, by what the named attacker demonstrably gets, never by which checklist item was missed. If you cannot say the concrete damage in one sentence, the rating is lower than it feels.

| Severity | Anchor |
|---|---|
| `critical` | No access to the victim's device needed, and the result is broad: a backend credential with wide privileges in the bundle, takeover of arbitrary accounts, an update channel anyone can push code through |
| `high` | One realistic step against one victim defeats a control with real consequences: a link or a malicious app steals the session or triggers a sensitive action; TLS validation off in the release build; an OAuth code that another app can intercept and redeem |
| `medium` | A real boundary crossing with meaningful preconditions or a narrow blast radius: long-lived tokens in plaintext recoverable from a backup or lost device; cleartext traffic carrying personal data; a billing-abuse key with a limited scope |
| `low` | Limited disclosure or an effect that needs a compromised device: sensitive values in device logs, a biometric gate that is only a boolean in front of something modest |
| `info` | Confirmed and worth knowing, with negligible direct impact |

The dividing question between high and medium: does the demonstrated result fully defeat a control for something that matters, or does it need luck, physical access or a second flaw?

You may not test whether a credential is live or what it is scoped to. Rate a bundled or committed secret by what that type of credential normally permits, and say the rating assumes it is live and unrestricted; the owner can lower it with facts you cannot see.

## What not to do

- Report a missing best practice as a vulnerability. No pinning, no root detection and no obfuscation are hardening notes unless the app's own threat model makes them controls.
- Call a public identifier a leaked secret, or recommend an environment variable as the fix for a real one.
- Report debug-only, test-only or dev-tooling configuration as shipped behaviour.
- Rate a rooted-device-only issue high. The device owner attacking their own session is rarely the threat.
- Guess what the server, a provider console or a generated native project does. That is what needs_validation is for.
- Inflate one root cause into several findings, or pad the report with low-value entries so it looks thorough. A short report with three real findings beats a long one with thirty.
- Write the report by hand in a way that could disagree with `findings.json`, or skip validation because the run felt careful.
- State or imply that one pass found everything. Say what was covered and what was not.

## Reference index

Read on demand. Focused mode needs one or two of these; a full audit ends up reading most of them, one domain at a time.

| File | Use it when |
|---|---|
| [references/threat-model.md](references/threat-model.md) | Starting an audit: trust boundaries of an RN app and the attack-surface questions |
| [references/secrets-and-config.md](references/secrets-and-config.md) | Any key, token, env var or config value: secret vs public identifier, and the real fixes |
| [references/data-storage-and-crypto.md](references/data-storage-and-crypto.md) | Storage libraries, persisted state, logs, backups, randomness and encryption |
| [references/network-and-auth.md](references/network-and-auth.md) | TLS, pinning, OAuth and session handling, biometrics, client-side authorization |
| [references/platform-entry-points.md](references/platform-entry-points.md) | Deep links, navigation linking, expo-router, WebViews and bridges, push and share input |
| [references/android.md](references/android.md) | AndroidManifest, network security config, Gradle signing, native Android code |
| [references/ios.md](references/ios.md) | Info.plist, entitlements, ATS, Keychain, native iOS code |
| [references/expo.md](references/expo.md) | Expo projects: app config, config plugins, generated native projects, EAS, expo-updates |
| [references/supply-chain-and-release.md](references/supply-chain-and-release.md) | Dependencies, OTA updates, signing and CI secrets, resilience controls |
| [references/validation-and-reporting.md](references/validation-and-reporting.md) | Before confirming anything: the refutation checklist, verdict rules, the record format |
| [references/masvs-mapping.md](references/masvs-mapping.md) | Mapping a finding to OWASP MASVS v2 controls and the Mobile Top 10; the pre-release question list |
| [references/remediation.md](references/remediation.md) | Writing a fix, answering "how do I fix this", or applying fixes when asked: concrete patterns with code |
