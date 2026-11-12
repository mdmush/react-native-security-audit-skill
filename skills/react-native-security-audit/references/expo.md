# Expo projects

Read this for any project that depends on `expo`, before the platform domain. Expo changes *where the security-relevant configuration lives*, and auditing the wrong place produces confident wrong answers.

## Which workflow is this?

The scanner's profile line tells you. The three cases:

| Case | Signs | Source of truth for native config |
|---|---|---|
| **Managed / CNG** (continuous native generation) | No `android/` or `ios/` directory | `app.json` / `app.config.(js\|ts)` and the config plugins it lists. The native projects are generated at build time by `expo prebuild` on EAS or locally. |
| **Prebuild, generated dirs present** | `android/`, `ios/` exist but are gitignored or untracked | Still the app config. The directories are build output; they show what one prebuild produced and can be stale. |
| **Committed native projects** ("bare" with Expo modules) | `android/`, `ios/` tracked in git | The native files, audited as in [android.md](android.md) and [ios.md](ios.md). The app config may still be applied on the next prebuild, so check both and note conflicts. |

In the first two cases you cannot read the final manifest or plist from the repository. What you can do:

- Audit the app config statically (below). Most security-relevant settings are plain keys.
- Read each config plugin that is local to the repo (`./plugins/*.js`, `withXxx` functions in `app.config.js`). They are code that rewrites the manifest, plist, Gradle files and entitlements, and can add exported components, permissions or cleartext exceptions.
- For anything that depends on the merged result, record `needs_validation` with the exact check: "run `npx expo config --type introspect` and confirm `android.manifest` has no exported service other than X", or "inspect the release build's AndroidManifest".

`npx expo config --type introspect` and `npx expo prebuild` execute the project's config and plugins. That is running project code: ask the user first, and never use `prebuild` in the working tree without `--no-install` and their agreement, because it writes native directories.

A dynamic `app.config.js|ts` is code, not data. Read it; the scanner does not evaluate it. Look at how it builds `extra` and which env vars it copies in.

**Where fixes go.** In the first two cases, recommend native changes as app-config keys or a config plugin (for example a plugin that writes `network_security_config.xml`, or `expo-build-properties` options). An edit to a generated `android/` or `ios/` file is lost on the next prebuild, so a fix described that way does not hold.

## App config keys that matter

**What ships to every user**

- `extra`: everything under it is embedded in the app and readable through `expo-constants`. `extra.eas.projectId` is public. Any credential here is in the bundle ([secrets-and-config.md](secrets-and-config.md)).
- `process.env.EXPO_PUBLIC_*` referenced anywhere in app code: inlined at build time. Variables *without* that prefix are not available to app JS at runtime, but a dynamic config can copy them into `extra`, which ships them anyway. Trace `process.env.X` reads inside `app.config.*`.
- `android.googleServicesFile`, `ios.googleServicesFile`: public Firebase config.
- `android.config.googleMaps.apiKey`, `ios.config.googleMapsApiKey`: public but must be restricted in the cloud console.
- `hooks.postPublish` (older projects) with a Sentry `authToken`: a real secret committed in config.

**Entry points**

- `scheme`: the app's custom URL scheme(s). With expo-router, every route file is reachable through it ([platform-entry-points.md](platform-entry-points.md)).
- `android.intentFilters`: check `autoVerify: true` for `https` data entries; without it they are not verified app links.
- `ios.associatedDomains`: Universal Links and shared credentials.
- `plugins` entry for `expo-router` with `origin`, and `experiments.typedRoutes`, are not security controls.

**Platform behaviour**

- `android.allowBackup`: defaults to **true**. Set to `false`, or accept backups knowingly. Matters when sensitive data is in AsyncStorage or other plaintext stores. `expo-secure-store` has a config plugin option (`configureAndroidBackup`) that excludes its own data from backup so restores do not break; that does not cover AsyncStorage.
- `android.permissions` / `android.blockedPermissions`: the effective permission list also includes what each library contributes. `blockedPermissions` is how unwanted ones are removed.
- `ios.infoPlist`: arbitrary plist keys, including `NSAppTransportSecurity`, `UIFileSharingEnabled`, `LSSupportsOpeningDocumentsInPlace`, usage descriptions.
- `ios.entitlements`: arbitrary entitlements.
- `expo-build-properties` plugin: `android.usesCleartextTraffic`, R8 minification (`android.enableMinifyInReleaseBuilds`; older SDKs called it `enableProguardInReleaseBuilds`, and the default has changed between SDK versions, so read the value rather than assuming), `android.enableShrinkResourcesInReleaseBuilds`, `android.extraProguardRules`, `android.networkInspector`, `ios.deploymentTarget`, min/target SDK versions.
- `jsEngine`: Hermes on current SDKs. Not a security control either way.

**Updates** (`updates`, `runtimeVersion`): see below.

## expo-updates and EAS Update

An OTA channel ships new JavaScript to installed apps without store review. Whoever can publish to it can run code as the app for every user.

- `updates.url` must be `https`. `updates.enabled`, `checkAutomatically`, `fallbackToCacheTimeout` shape behaviour, not security.
- **Code signing**: `updates.codeSigningCertificate` plus `codeSigningMetadata`. With it, the app only runs updates signed by the holder of the private key, so a compromised update server or account alone cannot ship code. Without it, the trust is in TLS plus EAS account security. Absence is a hardening note for most apps and a reasonable finding (`low`/`medium`, `supply-chain`) for high-value ones. The certificate in the repo is public; the **private key** (`keys/private-key.pem` or similar) must not be tracked. The scanner lists `.pem` files with tracked status.
- `updates.requestHeaders` with a static secret: it is in the app, so not a secret.
- `runtimeVersion` policy mismatches cause crashes, not vulnerabilities.
- Who can publish: EAS access tokens (`EXPO_TOKEN`) in CI config or committed files are `supply-chain` secrets with code-execution impact on the user base.
- Self-hosted update servers: read the manifest endpoint and asset hosting for authentication of publishers and integrity of assets.

## eas.json and build secrets

- `build.<profile>.env`: committed values, available at build time. Plain config is fine. Credentials here are a repository exposure; they belong in EAS environment variables marked secret/sensitive.
- `EXPO_PUBLIC_*` values in `eas.json` env end up in the bundle like any other.
- `credentials.json` and `credentialsSource: "local"`: local signing credentials (keystore passwords, provisioning profiles). Must be untracked.
- `submit` profiles referencing `serviceAccountKeyPath` or App Store Connect API keys: the referenced files must be untracked.
- `developmentClient: true` and `distribution: "internal"` profiles are for development builds. Check that the profile used for store submission is not one of them: a development client in production exposes the dev menu and lets the app load arbitrary bundles from a URL.

## Expo libraries: what to check

- **expo-secure-store**: the right place for tokens. Check `keychainAccessible` (avoid `ALWAYS*`) and `requireAuthentication` for biometric-bound items. It is unavailable on web: look at the fallback (often `localStorage` or AsyncStorage) when the same code targets web.
- **expo-auth-session / expo-web-browser**: PKCE is on by default for the code flow; flag `usePKCE: false` and `ResponseType.Token`. `makeRedirectUri` with a custom scheme is hijackable ([network-and-auth.md](network-and-auth.md)). The old `auth.expo.io` proxy is deprecated; flag any remaining `useProxy`.
- **expo-local-authentication**: `authenticateAsync` returns a boolean ([network-and-auth.md](network-and-auth.md)). The crypto-bound alternative in Expo is a SecureStore item with `requireAuthentication: true`.
- **expo-router**: all routes are deep-linkable; API routes (`+api.ts`) are server code and get a server-side review (authn/authz, input validation, secrets) if the project deploys them.
- **expo-file-system / expo-sqlite**: plaintext in the sandbox; `documentDirectory` is backed up.
- **expo-notifications**: payload handling ([platform-entry-points.md](platform-entry-points.md)); the push token is an identifier, not a secret, but lets its holder target the device through the app's push credentials.
- **expo-crypto**: correct source of randomness (`getRandomBytesAsync`, `randomUUID`).
- **@expo/app-integrity**: App Attest and Play Integrity. Only meaningful when the server issues the challenge and verifies the result ([supply-chain-and-release.md](supply-chain-and-release.md)).
- **expo-screen-capture**: screenshot and recording protection for specific sensitive screens.
- **expo-dev-client / expo-dev-menu**: should be devDependencies or excluded from production profiles.
- **expo-constants**: `Constants.expoConfig` exposes the public config at runtime, another way `extra` values are read.

## Not findings

- `EXPO_PUBLIC_` variables holding public identifiers (API base URL, Firebase config, Supabase anon key, publishable keys).
- `extra.eas.projectId`, the updates URL, the code-signing certificate.
- Missing `android/` and `ios/` directories: that is the managed workflow, not an incomplete project. Say what could not be verified instead.
- Updates without code signing in an ordinary app (hardening note).
- A dev client in a profile that is only used for internal development builds.
