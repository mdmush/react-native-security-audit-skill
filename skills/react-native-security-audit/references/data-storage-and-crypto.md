# Data storage and cryptography

Covers the `storage` and `crypto` domains: what the app leaves on the device, who can get at it, and whether its use of randomness and encryption holds up.

## Who reads local data

A healthy, locked device keeps one app's sandbox away from other apps. Storage findings are therefore about three other readers, and the report must say which:

- **Backups** (`device-access`): Android auto-backup and device-to-device transfer copy app data unless excluded; iOS backups include the app's Documents and Library data. Keychain items marked `ThisDeviceOnly` and Android Keystore keys do not travel.
- **Someone holding the device** (`device-access`): an unlocked or weakly locked phone, a repair shop, a shared family device, forensic tooling.
- **Root, jailbreak or malware with elevated rights** (`compromised-device`): reads everything in the sandbox; hardware-backed keys can still be *used* but not exported.

So "tokens in AsyncStorage" is a real but conditional finding. Its weight comes from what the token is worth and how long it lives, not from the API name.

## Storage options at a glance

| Store | Protection | Appropriate for |
|---|---|---|
| AsyncStorage | None: plaintext file/SQLite in the sandbox, included in backups | Preferences, UI state, non-sensitive cache |
| `react-native-mmkv` | None by default. With `encryptionKey`, AES, but only as good as where the key comes from | Same as above unless the key is generated on device and held in Keychain/Keystore |
| redux-persist, zustand `persist`, React Query persisters, Apollo cache persist | Whatever storage engine they are given, usually AsyncStorage or MMKV | Depends on which slices/queries are persisted |
| SQLite, Realm, WatermelonDB | Plaintext unless SQLCipher/Realm encryption is configured with a device-held key | Bulk app data; sensitive data only with real encryption |
| `expo-file-system`, `react-native-fs` | Sandbox files; documents directory is backed up; external/shared paths on Android are readable by other apps and the user | Files; never secrets on shared paths |
| `expo-secure-store` | iOS Keychain; Android Keystore-encrypted storage. Options: `keychainAccessible`, `requireAuthentication` | Tokens, small secrets (values are size-limited; store a key, not a document) |
| `react-native-keychain` | iOS Keychain; Android Keystore. Options: `accessible`, `accessControl`, `securityLevel` | Tokens, credentials, biometric-bound secrets |
| `react-native-encrypted-storage` | Keychain / EncryptedSharedPreferences | Tokens; check that the package version is still maintained |

## What to trace

**Tokens and credentials.** Find where the login response goes. Typical real findings:

- Refresh or long-lived access tokens written with `AsyncStorage.setItem`, or sitting in a persisted Redux/zustand slice. Check the persist config: a `whitelist` containing `auth`/`user`/`session`, or no whitelist at all (everything is persisted).
- A persisted React Query or Apollo cache that contains token or profile responses.
- Passwords or PINs stored at all, anywhere, in recoverable form. The same goes for full card numbers and CVVs, and for ID tokens kept after sign-in: these should be exchanged for a session and dropped.
- A "secure" wrapper that falls back to AsyncStorage on error or on one platform. Read the fallback path.

For each, record lifetime and power of the stored value (read it from the auth code or ask), whether backups are enabled without exclusions ([android.md](android.md), [expo.md](expo.md)), and the fix: move the value to SecureStore/Keychain and take it out of persisted state (a redux-persist `blacklist` or a transform that strips it).

**Personal and regulated data.** Health, financial, identity-document, precise-location and message content cached in plaintext is the same finding with a different payload. Note the data class; do not paste the data.

**Keychain / SecureStore options.** These decide when an item is readable:

- `ALWAYS`, `ALWAYS_THIS_DEVICE_ONLY` (deprecated classes): readable while the device is locked. Rarely needed; `AFTER_FIRST_UNLOCK` covers background refresh.
- Items without a `THIS_DEVICE_ONLY` class are included in encrypted backups and can migrate to a new device. Fine for most apps; worth a hardening note for high-value secrets.
- `cloudSync: true` (`react-native-keychain`) or `kSecAttrSynchronizable` puts the item in iCloud Keychain, on all the user's devices. Wrong for device-bound session tokens and local encryption keys.
- Android `securityLevel`: `SECURE_HARDWARE` refuses a software-only Keystore. Its absence is a hardening note for high-value apps.
- `requireAuthentication` / `accessControl: BIOMETRY_CURRENT_SET` binds the item to biometrics. See [network-and-auth.md](network-and-auth.md) for why this is the strong form of biometric login.
- iOS Keychain items survive app uninstall. An app that does not clear its Keychain on first launch after reinstall can resurrect a previous user's session. Low severity, easy fix, worth one line.

**Leaks around the edges.**

- **Logs.** `console.*` runs in release unless removed by `babel-plugin-transform-remove-console` (check `babel.config.js` for it under the production env). Output goes to logcat / the unified log. Since Android 4.1 other apps cannot read it, so the readers are someone with the device and a cable, and bug-report captures. Also check whether a crash or analytics SDK records console breadcrumbs or network bodies (Sentry `beforeBreadcrumb`/`beforeSend`, `sendDefaultPii`, session replay masking): that turns a local log into data sent to a third party. Usually `low`; `medium` when credentials or regulated data are sent off-device.
- **Redux/network debugging middleware** (`redux-logger`, Reactotron, Flipper plugins) wired in without a `__DEV__` guard.
- **Clipboard.** Copying a credential or recovery phrase exposes it to other apps and, on iOS, to Universal Clipboard. Only a finding for genuinely sensitive values.
- **Screenshots and app-switcher snapshots.** Absence of `FLAG_SECURE` or a privacy overlay (`expo-screen-capture`, `react-native-privacy-snapshot`) is hardening for most apps, expected on credential, card and one-time-code screens in finance/health apps. Blocking capture app-wide is not the goal.
- **Notifications.** Push payloads that carry message bodies, codes or account details are shown on the lock screen and pass through the push provider. Look at what the backend-facing code expects in the payload and what local notifications display. Usually `low`; the fix is to send an id and fetch after unlock.
- **Shared and external storage.** Exports, downloaded statements or logs written to `ExternalStorageDirectoryPath`, `DownloadDirectoryPath` or the iOS Documents directory with file sharing enabled.
- **WebView storage.** Cookies and localStorage of in-app WebViews persist in the sandbox and survive logout unless cleared.

**Logout and account switch.** Read the sign-out path. Does it clear persisted state, secure storage, query caches, WebView cookies and push tokens? Data from user A visible to user B on a shared device is a `device-access` finding that needs no special tooling.

## Cryptography

Most RN apps should not be doing their own cryptography; the platform (TLS, Keychain/Keystore) does it. When the app does, check these.

**Randomness.** `Math.random()` is not unpredictable. It is a finding where the output must not be guessable: OAuth `state` and PKCE verifiers written by hand, session or device identifiers used for auth, encryption keys, IVs and salts, one-time codes generated on the client. It is nothing for list keys, animation, jitter or sampling. The fix is `expo-crypto` (`getRandomBytesAsync`, `randomUUID`), `react-native-get-random-values` (`crypto.getRandomValues`) or `react-native-quick-crypto`. Also check `uuid` usage: without a secure RNG polyfill installed, older setups fell back to `Math.random`.

**Hardcoded keys.** An AES key, passphrase, HMAC secret or database `encryptionKey` literal in the source is recoverable from the bundle, so the "encryption" is encoding. This includes MMKV (`createMMKV({ encryptionKey })` in v4, `new MMKV({ encryptionKey })` earlier), Realm and SQLCipher keys, and a store opened at module scope with a placeholder key "until the real one loads". Rate by what it was supposed to protect and from whom: local data "encrypted" this way is as exposed as plaintext to anyone with the device data; a request-signing HMAC secret lets anyone forge app requests (often only an anti-abuse measure, sometimes the server's only authentication, which is worse).

**Algorithms and modes.** ECB mode, DES/3DES/RC4, a static or zero IV with CBC/CTR/GCM, MD5 or SHA-1 used for password hashing, signatures or integrity. Plain use of MD5 as a cache key or ETag is fine. `crypto-js` with a string passphrase uses a weak legacy key derivation; flag it when the data matters.

**Key handling.** The sound pattern: generate a random key on first run, store it in Keychain/Keystore, use it for the database or file encryption. Keys derived from a user PIN need a slow KDF (PBKDF2 with a high iteration count, scrypt, Argon2); a four-digit PIN through one SHA-256 is brute-forced instantly.

**Client-side "verification".** Decoding a JWT with `jwt-decode` verifies nothing. That is fine for reading display claims, and a lead when the result drives a security decision that the server might not repeat (see client-side authorization in [network-and-auth.md](network-and-auth.md)).

## Not findings

- Non-sensitive preferences and flags in AsyncStorage, whatever their key names. Read the value being stored, not the key.
- Access tokens held only in memory.
- Short-lived tokens (minutes) in plaintext with the refresh token in secure storage: a hardening note at most.
- Test code and mocks writing fake tokens.
- `Math.random()` with no security meaning.
- Encrypted storage libraries used with their defaults.
