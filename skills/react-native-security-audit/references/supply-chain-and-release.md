# Supply chain, release and resilience

Covers the `supply-chain` and `resilience` domains: the code and credentials that reach users without passing through the app's own source review, and the controls that make a released binary harder to tamper with.

## Dependencies

A React Native app runs thousands of packages, many with native code and install-time scripts. The audit's job is to find the few that matter, not to print `npm audit`.

**What to read**

- `package.json`: dependencies installed from git URLs, tarballs, `file:` paths or forks instead of the registry. Are they pinned to a commit hash? Who controls the source?
- Lockfile: present and tracked? Without one, every install resolves afresh. In a monorepo it may sit at the workspace root.
- `scripts`: `preinstall`/`postinstall`/`prepare`. `patch-package` and `pod install` are normal. Anything that downloads and runs code is worth reading.
- `patches/` (patch-package) and `.yarn/patches`: local modifications to dependencies. Read them; a patch that removes a certificate check or an origin check in a library is an invisible finding.
- `.npmrc` / `.yarnrc.yml`: custom registries (dependency-confusion exposure when an internal scope is not pinned to the private registry), and auth tokens that should not be tracked.
- `overrides` / `resolutions`: forced versions, sometimes pinning a known-vulnerable release.

**Known vulnerabilities.** `npm audit` / `yarn npm audit` / `pnpm audit` contact the registry: offer to run them, or ask the user for existing output. Treat results as leads and filter hard:

- A vulnerable package only matters if its vulnerable code runs in the app with attacker-influenced input. A ReDoS in a build-time CLI tool is not an app vulnerability.
- Separate runtime dependencies (in the bundle or native binary) from dev tooling. Dev-tool advisories affect developers and CI, which can still be serious: for example CVE-2025-11953, an OS command injection in the Metro dev server shipped with `@react-native-community/cli-server-api` from 4.8.0 up to but not including 20.0.0 (fixes were also backported to 17.0.1, 18.0.1 and 19.1.2), let anyone who could reach a developer's dev-server port run commands on that machine. Record it in the `supply-chain` domain with a `network` attacker, and say plainly that it affects developer machines, not the shipped app. Without a lockfile the installed version is unknown, which makes it `needs_validation`.
- Prioritise packages that handle untrusted input in production: `react-native-webview`, networking and parsing libraries, image/PDF/markdown renderers, deep-linking and auth SDKs.

**Health signals worth one line each**, as hardening: abandoned native modules that handle secrets or networking, packages with a handful of downloads standing in for a well-known name (typosquats of `react-native-*` packages are a recurring pattern), and the React Native / Expo SDK version itself being out of support (support windows cannot be judged offline: record the version and let the owner check).

## Over-the-air updates

An OTA mechanism replaces the app's JavaScript after install. It is remote code execution by design, so the question is who holds the keys.

- **expo-updates / EAS Update**: see [expo.md](expo.md) for config, code signing and publish tokens.
- **CodePush**: Microsoft retired App Center in March 2025; apps still on `react-native-code-push` are either pointed at a self-hosted server or at nothing. Find the server URL and deployment key (`CodePushDeploymentKey` in `strings.xml` / `Info.plist`; the key itself is a public identifier). Check the transport is https, whether bundle signing is configured (`CodePushPublicKey`), and who operates the server. A dead endpoint on a domain or service that could be claimed by someone else is a real takeover risk.
- **Home-made updaters**: code that downloads a bundle or "config script" and loads it (`getJSBundleFile` override, `RCTBridge` with a file URL, `eval` of fetched code). Read all of it. Required for safety: https, a signature check against a key embedded in the app before the bundle is used, and storage in app-private files. Missing signature verification is a `confirmed` `supply-chain` finding, and a `network` one too if the download is cleartext or TLS validation is off.
- **Publish credentials**: `EXPO_TOKEN`, CodePush access keys or S3 credentials for the bundle bucket in the repo or CI config give repo readers code execution on every device.

Store policy limits OTA to changes that do not alter the app's primary purpose; that is a compliance note, not a security finding.

## Signing material and CI

The scanner lists sensitive files with their git-tracked status. For each tracked one, decide what it unlocks:

| Material | If exposed |
|---|---|
| Android upload/release keystore plus its passwords | Sign builds as the app. With Play App Signing the upload key can be rotated through Google; without it, the key is the app's identity for life. |
| Apple distribution certificate (`.p12`) plus password, provisioning profiles | Sign builds as the developer; revocable. |
| App Store Connect API key (`AuthKey_*.p8`), Google Play service-account JSON | Upload builds and change store listings; scope depends on the key's role. |
| Fastlane `match` repo passphrase, `Appfile`/`Matchfile` secrets | Access to all signing identities. |
| `sentry.properties` `auth.token`, Firebase CI tokens, `EXPO_TOKEN`, npm tokens | Whatever the token's scope allows: reading crash data, uploading artifacts, publishing updates or packages. |
| expo-updates code-signing private key | Sign OTA updates the app will accept. |

All of these are `supply-chain` findings (repository exposure), not `binary-holder` ones, unless the file is also bundled into the app. Severity follows the end effect: a credential that lets a repo reader ship code to all users is `high` even though it needs repo access; a crash-reporting upload token is `low`/`medium`.

**CI configuration** (`.github/workflows`, `.gitlab-ci.yml`, `bitrise.yml`, `.circleci`, `codemagic.yaml`): literal secrets instead of secret references; workflows triggered by `pull_request_target` or fork PRs that have access to signing secrets; build steps piping remote scripts to a shell; unpinned third-party actions with write permissions. Report what is visible; deployment settings in the CI provider are outside the repo.

**Committed build output**: a tracked `main.jsbundle`, `index.android.bundle` or source map can ship stale code and is not covered by a source scan. Source maps and iOS dSYMs uploaded to a crash service are fine; packaged into the app or served publicly they reveal the original source and symbols, which matters only when those were meant to be private (`low`/`info`).

## Release configuration

Check that development conveniences do not reach the store build:

- Dev tooling in `dependencies` wired without a `__DEV__` guard: Reactotron, Flipper plugins, `redux-logger`, in-app debug menus, environment switchers that let a user point the app at an arbitrary server.
- An Expo development client or `developmentClient: true` profile used for distribution ([expo.md](expo.md)).
- `android:debuggable`, `get-task-allow`, WebView debugging ([android.md](android.md), [ios.md](ios.md)).
- Staging hosts, test accounts and feature flags selected at runtime in the release bundle. A hidden "use staging" switch is `info` unless staging is weaker and shares data with production.
- `console.*` not stripped ([data-storage-and-crypto.md](data-storage-and-crypto.md)).

## Resilience

Resilience controls protect the app against its own environment: reverse engineering, tampering, repackaging, instrumentation. In OWASP MASVS they form a separate group that applies according to the app's threat model, not to every app.

- Obfuscation of JS (and R8 for Java/Kotlin), root/jailbreak detection (`jail-monkey`, freeRASP), debugger and hook detection, integrity checks, emulator detection, attestation (Play Integrity, App Attest, Firebase App Check).

How to treat them:

- **Ordinary apps**: absence is a hardening note at most, often not worth mentioning. Do not pad the report with "no root detection".
- **High-value and anti-abuse apps** (see the purpose section of [threat-model.md](threat-model.md)): expected. Their absence can be a `low`/`medium` `resilience` finding, and their presence should be checked for being decorative.
- **Decorative controls**: a root check whose result is logged and ignored, an integrity check that compares against a constant in the same bundle. These are worth reporting because the team believes they are protected.
- **Local signals used as gates**: `jail-monkey`-style booleans (`isJailBroken`, `hookDetected`, `isDebuggedMode`) deciding access in JS are flipped by the same tooling they detect. They are useful as telemetry and warnings. Blocking outright on them mostly hurts legitimate users on unusual devices.
- **Client-enforced business rules**: licence checks, paywalls and entitlements decided only in JS. For apps where revenue depends on them, a `compromised-device` finding; the fix is server-side entitlement checks, not more obfuscation.

Attestation (App Attest, Play Integrity, via `@expo/app-integrity`, Firebase App Check or native code) is the one resilience control with a server-verifiable result. Recommend it where API abuse from scripted clients matters. When it is present, check the client half and ask about the server half:

- Is the challenge issued by the server per request or session, or is it a constant or client-generated value (replayable)?
- Is the token bound to the request (`requestHash`, an assertion over the payload), or a free-floating "this device is fine" token?
- Is the token sent to the backend, or is the verdict read and acted on in JS (decorative)?
- What happens when attestation is unsupported or fails: does the client simply skip it and call the API anyway? If the server accepts requests without a token, the control is optional for attackers.
- Server-side verification, replay rejection and verdict policy are outside the repository → `needs_validation` with those exact questions.

## Not findings

- `npm audit` output pasted wholesale; advisories in dev-only tooling reported as app vulnerabilities.
- `patch-package` in `postinstall`.
- The debug keystore; untracked local credential files.
- Public identifiers for update and crash services (deployment keys, DSNs, project ids).
- Absent resilience controls in an app with no reason to resist its own user.
