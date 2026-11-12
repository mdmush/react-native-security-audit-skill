# OWASP MASVS v2 and Mobile Top 10 mapping

Use this to tag findings with standard identifiers. The tags help readers who work to these standards; they never set severity, and a control not being met is not by itself a finding.

MASVS v2 has eight control groups. It dropped the L1/L2/R levels of v1; depth is now expressed through MAS testing profiles in the MASTG. Older material that cites `V2: Data Storage` or `MSTG-STORAGE-1` uses the retired v1 numbering.

## Controls

| Control | Statement (short) | Typical React Native findings |
|---|---|---|
| MASVS-STORAGE-1 | The app securely stores sensitive data | Tokens or PII in AsyncStorage, MMKV, persisted Redux/query state, plaintext databases; weak Keychain accessibility |
| MASVS-STORAGE-2 | The app prevents leakage of sensitive data | Secrets in logs, backups without exclusions, clipboard, screenshots, shared storage, data sent to analytics or crash SDKs |
| MASVS-CRYPTO-1 | The app employs current strong cryptography and uses it according to best practice | `Math.random` for security values, ECB, static IVs, MD5/SHA-1 for integrity or passwords |
| MASVS-CRYPTO-2 | The app performs key management according to best practice | Hardcoded encryption keys and passphrases, keys stored beside the data they protect, weak PIN-derived keys |
| MASVS-AUTH-1 | The app uses secure authentication and authorization protocols and follows best practice | Backend secrets used as client credentials, OAuth without PKCE, implicit flow, client secret in the app, client-only authorization |
| MASVS-AUTH-2 | The app performs local authentication securely according to platform best practice | Biometrics or PIN as a boolean gate, not bound to Keychain/Keystore |
| MASVS-AUTH-3 | The app secures sensitive operations with additional authentication | Payments, credential changes or data export with no step-up or re-authentication |
| MASVS-NETWORK-1 | The app secures all network traffic according to current best practice | Cleartext endpoints, disabled TLS validation, user CAs trusted in release, tokens in URLs |
| MASVS-NETWORK-2 | The app performs identity pinning for all remote endpoints under the developer's control | Missing or broken certificate pinning where the threat model calls for it |
| MASVS-PLATFORM-1 | The app uses IPC mechanisms securely | Deep-link handling, custom-scheme hijack, exported Android components, intents, FileProvider paths, app groups |
| MASVS-PLATFORM-2 | The app uses WebViews securely | Untrusted URLs in WebViews, bridge handlers without origin checks, injected tokens, file access flags |
| MASVS-PLATFORM-3 | The app uses the user interface securely | Sensitive data in notifications, app-switcher snapshots, missing masking, overlay/tapjacking exposure |
| MASVS-CODE-1 | The app requires an up-to-date platform version | Very low `minSdkVersion` / deployment target disabling platform protections |
| MASVS-CODE-2 | The app has a mechanism for enforcing app updates | No way to force users off a build with a known security flaw |
| MASVS-CODE-3 | The app only uses software components without known vulnerabilities | Vulnerable or abandoned dependencies in the runtime path, unsigned OTA code, risky install scripts |
| MASVS-CODE-4 | The app validates and sanitizes all untrusted inputs | Deep-link and push parameters reaching sinks, HTML/script injection into WebViews, `eval`, path traversal from shared files |
| MASVS-RESILIENCE-1 | The app validates the integrity of the platform | Missing or decorative root/jailbreak detection, where required |
| MASVS-RESILIENCE-2 | The app implements anti-tampering mechanisms | Release signed with a public key, missing integrity checks or OTA signing, exposed signing material |
| MASVS-RESILIENCE-3 | The app implements anti-static analysis mechanisms | No obfuscation of sensitive logic, where required; debug symbols and source maps shipped |
| MASVS-RESILIENCE-4 | The app implements anti-dynamic analysis techniques | Debuggable release build, WebView debugging enabled, no hook/debugger detection where required |
| MASVS-PRIVACY-1 | The app minimizes access to sensitive data and resources | Unneeded permissions, excessive data sent to third-party SDKs |
| MASVS-PRIVACY-2 | The app prevents identification of the user | Persistent device identifiers, advertising-id use, cross-app tracking |
| MASVS-PRIVACY-3 | The app is transparent about data collection and usage | Privacy manifest or store label not matching SDK behaviour |
| MASVS-PRIVACY-4 | The app offers user control over their data | No account or data deletion path, consent not honoured before tracking starts |

The RESILIENCE group applies according to the app's threat model. Tag resilience gaps as hardening for ordinary apps (see [supply-chain-and-release.md](supply-chain-and-release.md)).

Picking a tag when several fit: use the control that names the broken rule, then at most two more for links in a chain. A backend secret in the bundle is MASVS-AUTH-1 (it is being used as an authentication credential by a client that cannot keep one); a keystore password in the repository is MASVS-RESILIENCE-2.

## OWASP Mobile Top 10 (2024)

For readers who think in Top 10 terms. Mention the category in a finding's description when it helps; `findings.json` stores MASVS ids only.

| Category | Audit domain here | Closest MASVS |
|---|---|---|
| M1 Improper Credential Usage | `secrets` | MASVS-AUTH-1, MASVS-STORAGE-1 |
| M2 Inadequate Supply Chain Security | `supply-chain` | MASVS-CODE-3, MASVS-RESILIENCE-2 |
| M3 Insecure Authentication/Authorization | `auth` | MASVS-AUTH-1, -2, -3 |
| M4 Insufficient Input/Output Validation | `platform` | MASVS-CODE-4, MASVS-PLATFORM-1, -2 |
| M5 Insecure Communication | `network` | MASVS-NETWORK-1, -2 |
| M6 Inadequate Privacy Controls | `privacy` | MASVS-PRIVACY-1 to -4 |
| M7 Insufficient Binary Protections | `resilience` | MASVS-RESILIENCE-1 to -4 |
| M8 Security Misconfiguration | `platform`, `supply-chain` | MASVS-PLATFORM-1, MASVS-STORAGE-2, MASVS-RESILIENCE-4 |
| M9 Insecure Data Storage | `storage` | MASVS-STORAGE-1, -2 |
| M10 Insufficient Cryptography | `crypto` | MASVS-CRYPTO-1, -2 |

## Pre-release questions

A compact list for "are we ready to ship?" requests. Each line is a question to answer from the code, not a box to tick: a "no" is a lead to run through the refutation checklist, and several can only be answered by the owner.

| Question | Domain |
|---|---|
| Is every value the app reads at runtime either public by design or absent from JS, `EXPO_PUBLIC_*`, `extra` and native resources? | `secrets` |
| Are tokens only in Keychain/Keystore-backed storage, and does sign-out clear all local data? | `storage` |
| Does the release build strip console output, keep source maps and dSYMs private, and exclude dev menus and dev clients? | `storage`, `supply-chain` |
| Is all traffic HTTPS with default validation, with no cleartext or user-CA exceptions outside debug? If pinning is used, does it have backup pins and a live expiry? | `network` |
| Does login use the authorization-code flow with PKCE in the system browser, with no client secret, and verified-link redirects for sensitive callbacks? | `auth` |
| Are deep-link parameters, push payloads and WebView messages validated before they navigate, load or act? | `platform` |
| Are permissions minimal and each backed by a feature and a usage string? | `privacy` |
| Are screens with credentials, card data or one-time codes protected from capture, where the app's data calls for it? | `storage` |
| Are integrity or attestation tokens verified by the server for the endpoints that rely on them? (owner) | `resilience` |
| Are dependencies audited, a lockfile committed, and React Native / Expo on a supported version? | `supply-chain` |
| Do the iOS privacy manifest and the Play Data safety form match what the app and its SDKs collect? (owner) | `privacy` |
| If over-the-air updates are shipped, are they signed and published only from CI? | `supply-chain` |

## Using the standards honestly

- A source audit can show that a control is violated at a specific place. It cannot certify that a control is met across the app, and it is not a MASTG test run against a binary. If the user needs a compliance statement, say what this audit does and does not support.
- "Fails MASVS-NETWORK-2" for an app with no reason to pin is a hardening note, not a finding.
- When the user asks for a MASVS checklist view, derive it from the coverage table and findings: per group, list confirmed violations, items needing validation, and what was reviewed without issue. Do not mark a group "pass".
