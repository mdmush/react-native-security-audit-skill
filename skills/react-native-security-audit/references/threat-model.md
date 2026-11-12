# Threat model of a React Native app

Read this at the start of an audit. It explains where the trust boundaries of an RN/Expo app actually are, so the later domain files can be short.

## What the app is made of

| Layer | What it is | Who can read or change it |
|---|---|---|
| JS bundle | All app JavaScript, compiled to Hermes bytecode (or plain minified JS on JSC), shipped inside the IPA/APK or delivered over the air | Anyone can read it. Strings survive compilation verbatim. On a compromised device it can be replaced. |
| Native shell | `android/` and `ios/` projects: manifest, plist, entitlements, Gradle/Xcode settings, any Kotlin/Java/Swift/Obj-C | Readable by anyone with the binary. Decides what the OS lets the app do and what other apps can ask of it. |
| Native modules | Code behind `NativeModules`/TurboModules, from dependencies or the app itself | Callable from the app's JS. Callable by web content only if the app builds a bridge to it (WebView `onMessage`). |
| App sandbox | AsyncStorage, MMKV, SQLite/Realm files, caches, Keychain/Keystore entries | Private from other apps on a healthy device. Open to backups, device forensics and root, except hardware-backed Keychain/Keystore items. |
| Backend | The app's API, a BaaS (Firebase, Supabase, Amplify), third-party APIs | Not in the repository. The client is only one of its callers: anyone can call it directly with whatever the bundle reveals. |

Two consequences drive most findings:

- **The client enforces nothing.** Any rule that exists only in JS (role checks, price calculation, feature gating, "this endpoint is hidden") is advice to honest users. A finding of this kind is really a question about the server, so it usually ends as `needs_validation` unless the server-side rules are in the repository (Firestore rules, Supabase policies, an API in the same monorepo).
- **The app is also a server.** It accepts input it did not ask for: URLs from other apps and web pages, push payloads, messages from pages in its WebViews, intents to exported Android components, files shared into it, and JS bundles from its update channel. Each of those is an entry point for a lower-trust party and deserves the scrutiny an HTTP endpoint would get.

## Attack-surface questions

Answer these during reconnaissance. Each "yes" points at a reference file.

**Identity and session**
- How does login work: password to own API, OAuth/OIDC, magic link, OTP, BaaS SDK? → [network-and-auth.md](network-and-auth.md)
- Where are access and refresh tokens after login: memory, AsyncStorage, redux-persist, SecureStore, Keychain? How long do they live? → [data-storage-and-crypto.md](data-storage-and-crypto.md)
- Is there a local unlock (PIN, biometrics)? What does it actually gate? → [network-and-auth.md](network-and-auth.md)

**Inbound entry points**
- Which URL schemes, universal links and app links are registered, and which screens do they reach with which parameters? → [platform-entry-points.md](platform-entry-points.md)
- Is there a WebView? What can it load, what can a page inside it ask the app to do, and what does the app hand to the page? → [platform-entry-points.md](platform-entry-points.md)
- What does the app do with push notification payloads, shared files and pasted content? → [platform-entry-points.md](platform-entry-points.md)
- Android: which components are exported beyond `MainActivity`? → [android.md](android.md)

**Outbound trust**
- Does the client call any third-party API directly with a credential that belongs on a server (payments, LLMs, email/SMS, maps with billing, cloud storage)? → [secrets-and-config.md](secrets-and-config.md)
- Is all traffic TLS with default validation? Any custom trust code, proxy/debug overrides, pinning? → [network-and-auth.md](network-and-auth.md)
- If a BaaS is used, are its access rules in the repository? → [secrets-and-config.md](secrets-and-config.md)

**Code and release**
- Is there an OTA update channel, and who can publish to it? → [supply-chain-and-release.md](supply-chain-and-release.md)
- Is signing material or CI credentials in the repository? → [supply-chain-and-release.md](supply-chain-and-release.md)
- Expo managed or prebuild: is the native configuration generated? → [expo.md](expo.md)

## How much the app's purpose changes the bar

The same weakness is rated differently in different apps, and the audit should say which kind it is looking at:

- **Ordinary consumer and internal apps.** The device owner is the user, not the adversary. Resilience controls (root detection, anti-tamper, obfuscation, pinning) are hardening. A compromised device is out of scope beyond noting what a thief would recover.
- **Apps holding money, health data or credentials** (banking, wallets, health, password managers, enterprise SSO). Storage and local-auth weaknesses weigh more, pinning and backup exclusion become expected, and `device-access` findings are taken at full value.
- **Apps whose business depends on resisting their own user** (DRM, paid content, anti-cheat, loyalty or coupon logic). Here `compromised-device` is a first-class attacker, and client-only enforcement of entitlements is a real finding rather than hardening.

When the category is not obvious from the code, ask the user or state your assumption in the report's limitations.

## Chains are worth more than parts

Weak signals combine. Look for these in particular:

- A deep link that reaches a WebView, plus a WebView that receives the session token → one-tap account takeover from a web page.
- Tokens in AsyncStorage, plus `allowBackup` enabled with no exclusions, plus a long-lived refresh token → session recovery from a backup.
- A custom-scheme OAuth redirect, plus no PKCE → another installed app completes the login.
- A cleartext endpoint, plus platform configuration that permits cleartext in release → credentials readable on the network.
- An OTA channel, plus a publish credential in the repository or CI config → anyone with repo access ships code to every user.

Report a chain as one finding at the severity of its end result, citing each link. Report a lone link at its own, usually lower, weight.
