# Secrets and configuration

The question is never "is there a key in the code". Client apps are full of keys. The question is: **can this value do something its holder should not be able to do, and who gets to hold it?**

## Contents

- Two different exposures
- What ends up in the bundle
- Secret or public identifier
- Tracing a lead
- Fixes that work, and the one that does not
- Backend-as-a-service rules
- Not findings

## Two different exposures

Keep these apart; they have different attackers and different fixes.

| Exposure | Attacker class | Example | Fix |
|---|---|---|---|
| **In the shipped app** | `binary-holder`: everyone | A payment provider's secret key read by JS | Move the capability to a server |
| **In the repository only** | `supply-chain`: anyone with repo or CI access | Keystore password in `gradle.properties`, Sentry auth token in `sentry.properties`, `.env` tracked in git | Rotate, remove from history, use a secret store |

A value can be both. Say which, because "it is only in the repo" caps severity at what a repo reader can do, and "it is in the bundle" means the whole internet.

## What ends up in the bundle

Assume a value ships if app JavaScript can read it:

- Any literal in JS/TS source, including "config" modules and constants files.
- `process.env.EXPO_PUBLIC_*`: inlined at build time. This is the documented behaviour, not a leak in Expo. Inlining applies to static dot access (`process.env.EXPO_PUBLIC_X`), so that is the form to search for when looking for reads.
- `react-native-config` (`Config.X`): compiled into native resources and BuildConfig; trivially extracted.
- `react-native-dotenv` / `babel-plugin-inline-dotenv` (`@env`): inlined by Babel.
- `app.json` / `app.config.*` → `expo.extra`, read through `expo-constants`: embedded in the app manifest.
- `google-services.json`, `GoogleService-Info.plist`, `strings.xml`, `Info.plist` values, `BuildConfig` fields.
- Anything fetched by the app before login from an unauthenticated endpoint (a "remote config" that hands out a secret is the same problem with an extra hop).

Hermes does not help: the bytecode file keeps string literals in a readable table, and public decompilers exist. Obfuscators and "encrypting" a key with another key in the same bundle only raise effort slightly. Do not accept either as a mitigation, and do not recommend them as a fix.

Values that do **not** ship: variables used only by build tooling, CI, Fastlane, EAS (`eas.json` env without the `EXPO_PUBLIC_` prefix, EAS secrets), Metro or Babel config, and scripts. A secret there is a repository exposure at most.

## Secret or public identifier

Decide which before rating anything. The right-hand column is the mistake to avoid.

| Value | Verdict | Notes |
|---|---|---|
| Firebase web/app config (`apiKey` starting `AIza`, `appId`, `projectId`), `google-services.json` | Public identifier | Security lives in Firebase rules, App Check and API key restrictions. Check rules if they are in the repo. |
| Google Maps / Places key in the app | Public, must be restricted | Unrestricted, it allows quota and billing abuse. Restriction is set in the cloud console → `needs_validation`. |
| Stripe `pk_live_` / `pk_test_`, RevenueCat public SDK keys (`appl_`, `goog_`) | Public identifier | Made to ship. |
| Stripe `sk_live_`, `rk_live_` | **Secret** | Full or scoped account access. |
| Supabase `anon` key or `sb_publishable_` key | Public identifier | Security lives in row-level-security policies. |
| Supabase `service_role` JWT or `sb_secret_` key | **Secret** | Bypasses row-level security entirely. The scanner decodes JWT claims so you can tell `anon` from `service_role`. |
| Sentry DSN | Public identifier | Lets anyone send events; not a confidentiality problem. |
| Sentry auth token (`sntrys_`, `sntryu_`, or `auth.token=` in `sentry.properties`) | **Secret** (repo exposure, sometimes bundle) | Can read and modify the Sentry org's data and upload artifacts. |
| OneSignal app id, Segment/Amplitude/Mixpanel/PostHog write keys, Algolia search-only key, Mapbox `pk.` token | Public identifier | Abuse is spam or quota at worst. |
| OneSignal REST API key, Algolia admin key, Mapbox `sk.` token | **Secret** | |
| AWS access key id + secret, any `service_account` JSON, private key blocks | **Secret** | Scope decides between high and critical. Cognito identity pool ids are public. |
| LLM provider keys (OpenAI, Anthropic, Gemini, Groq, OpenRouter...) | **Secret** | Direct financial abuse, and often access to stored files or fine-tunes. Very common in AI-feature prototypes that went to production. |
| Twilio auth token, SendGrid/Mailgun/Postmark key, SMS gateway key | **Secret** | Lets the holder send messages as the company and run up cost. |
| OAuth `client_id` | Public identifier | |
| OAuth `client_secret` in the app | Design flaw | A mobile app is a public client. Impact depends on what the provider lets the secret do; the fix is the PKCE public-client flow. |
| CodePush deployment key, EAS project id, `expo-updates` URL | Public identifier | The publish credentials are the secret, and they live in CI. |
| A hardcoded user or admin password, basic-auth credentials, a long-lived personal JWT | **Secret** | |
| An "API key" for the company's own backend that every install shares | Not really a secret | It identifies the app, not the user. Fine if the backend treats it that way; a finding only if it is the *only* thing protecting user data. Usually `needs_validation`. |

When a format is not in the table, reason from the provider's own model: does the provider document it for client-side use? What API calls does it authorize? If you do not know, say so and mark `needs_validation` rather than guessing in either direction.

## Tracing a lead

1. **Is it real or a placeholder?** Example files, test fixtures and docs are not findings. A real-looking value in `.env.example` is. A value that does not match the provider's usual format is still treated as real when the code sends it as a credential to a real endpoint: report it, and mention the format mismatch.
2. **Does it reach the bundle?** Find the import or `process.env` read in app code, then check that module is reachable from the app's entry point. Metro bundles only modules that something imports, so a value in a file nothing imports does not ship. A constant that is bundled but unused does ship. Values in `app.json` `extra` and in native resources ship regardless of imports.
3. **What is it used for?** Follow it to the request it authorizes. A secret sent as `Authorization` to a third-party API straight from the client is the complete finding: the endpoint and the credential are both in the attacker's hands.
4. **What can it do?** Read from the code what the app does with it, and from the provider's model what else it permits. Do not test it.
5. **Is it tracked in git?** The scanner reports this per sensitive file. Check `.gitignore` covers `.env` and `.env*.local`; a missing ignore rule is how the next secret gets committed. Whether it is in git *history* after deletion is out of the scanner's view; suggest `gitleaks` or `trufflehog` to the owner if a secret was recently removed.

Never verify a credential by using it. Report location, type and potential; the owner checks liveness and rotates.

**Rating without knowing liveness or scope.** Rate by what that credential type normally permits, assuming it is live and unrestricted, and say so. A full-account secret (cloud root keys, a BaaS service-role key, a payment secret key) in a shipped bundle is `critical`. A key whose abuse is mainly spend or sending on the company's behalf (LLM, email, SMS) is `high`. A key the provider scopes narrowly by design is `medium`. If the value is only in the repository, cap it at what a repository reader could do with it.

## Fixes that work, and the one that does not

- **Does not work:** moving the value to `.env`, `EXPO_PUBLIC_*`, `react-native-config`, native code, a keystore populated at build time, or an obfuscated string. It still ships. If the current code already does this, the finding stands.
- **Works:** the app calls the company's own backend (or an edge function) as an authenticated user; the backend holds the secret and makes the third-party call, applying per-user authorization and rate limits. Code for this and the other fixes is in [remediation.md](remediation.md).
- **Works for providers that support it:** short-lived, narrowly scoped credentials minted per user by the backend (ephemeral keys, signed upload URLs, scoped tokens).
- **For public identifiers:** restrict them in the provider console (bundle id / package name plus signing-certificate SHA-1, API allowlist, quotas) and add attestation (App Check, App Attest, Play Integrity) where abuse matters.
- **For anything already exposed:** rotate first, then remove. Deleting the line does not un-leak it; it remains in git history and in every released build.

## Backend-as-a-service rules

When the app talks straight to Firebase or Supabase, the access rules *are* the authorization layer, and the public config in the bundle is all an attacker needs to talk to the same backend.

- If `firestore.rules`, `storage.rules`, `database.rules.json` or Supabase migrations/policies are in the repository, audit them: `allow read, write: if true`, rules that check only `request.auth != null` on per-user data, tables without row-level security.
- Whether the repository's rules are the deployed ones is outside the repo. A wide-open rules file is `confirmed` as "these rules, if deployed, expose X" only when you word it that way; otherwise `needs_validation` with "confirm the deployed rules match".
- If no rules are in the repository, record one `needs_validation` item asking the owner to review them, listing the collections/tables the client reads and writes. That list is real audit output.

## Not findings

- Public identifiers from the table above, however key-shaped.
- Example and template env files with placeholders, and fixtures in tests.
- The React Native template's debug keystore and its `android` password.
- A secret used only by local tooling and not tracked in git (an untracked `.env` on the developer's machine is how it is supposed to work).
