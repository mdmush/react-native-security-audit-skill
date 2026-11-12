# Remediation patterns

Use this when writing the `fix` field of a finding, when the user asks how to fix something, or when they ask you to apply fixes after an audit. Each pattern is the smallest change that removes the weakness, not a hardening wish list.

Library APIs move. Before writing code into a project, check the installed version in `package.json` and adapt: the samples show the shape of the fix. In Expo projects with generated native directories, make native changes through `app.json` / `app.config.*` and config plugins, never by editing `android/` or `ios/`, because the next prebuild discards those edits.

## Contents

- An exposed secret
- A secret the app needs at runtime
- Tokens in plaintext storage
- Biometric-bound secrets
- Encrypting local data
- Deep-link parameters
- WebViews
- OAuth
- Transport security and pinning
- Backups, logs and screen content
- Logout and reinstall
- OTA updates
- Attestation

## An exposed secret

Order matters, and removing the line is the last step, not the first.

1. **Rotate or revoke** the credential at the provider. A secret that shipped in any build, or was pushed to any remote, is public for good.
2. Check the provider's usage and audit logs for activity the team does not recognise.
3. Replace the capability (next section), then delete the value from source, env files, EAS/CI variables and native resources.
4. If it was committed, it is still in git history: rotation makes that harmless, and a history scan (`gitleaks`, `trufflehog`, GitHub secret scanning) finds any others.

## A secret the app needs at runtime

The app must not hold it. Put a server between the app and the provider.

```ts
// App: authenticated call to your own backend. No provider key anywhere in the app.
const res = await fetch(`${API_URL}/ai/pairing`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ dishes }),
});
```

```ts
// Server (any backend, edge function or Expo Router API route)
export async function POST(req: Request) {
  const user = await requireSession(req);        // who is calling
  await enforceQuota(user.id);                    // per-user rate limit and spend cap
  const { dishes } = validate(await req.json());  // the server builds the prompt, not the client
  return Response.json(await callProvider(dishes, process.env.PROVIDER_API_KEY));
}
```

The server decides what the call may do (model, recipients, amounts); a proxy that forwards arbitrary client requests with the secret attached has only moved the problem. Where the provider offers them, per-user short-lived credentials minted by the backend (ephemeral keys, signed upload URLs) avoid proxying the data path.

Build-time secrets (Sentry upload token, store API keys) belong in the CI or EAS secret store and are read by build tooling, never by app code. For public identifiers, the fix is provider-side restriction (bundle id, package signature, API allowlist, quotas), not removal.

## Tokens in plaintext storage

Move the credential to Keychain/Keystore-backed storage and take it out of persisted state.

```ts
// Expo
import * as SecureStore from 'expo-secure-store';
const opts = { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY };
await SecureStore.setItemAsync('refreshToken', token, opts);
const token = await SecureStore.getItemAsync('refreshToken', opts);
```

```ts
// Bare React Native
import * as Keychain from 'react-native-keychain';
await Keychain.setGenericPassword('session', refreshToken, {
  service: 'com.example.auth',
  accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
});
```

- Use `AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY` only when background work must read the token while the device is locked.
- Use the same options on read, write and delete; items are looked up by them.
- Persisted state: remove the token fields with a redux-persist `blacklist` or transform (zustand: `partialize`), or stop persisting that slice. Keep the access token in memory; persist only the refresh token, in secure storage.
- Do not keep at all: the user's password, full card numbers or CVV, and ID tokens after sign-in (read the claims, then drop them).
- Migration: on first launch of the fixed version, move the old value across and delete the plaintext copy, otherwise it stays on disk and in backups.

## Biometric-bound secrets

Replace "prompt, then check a boolean" with an item the OS releases only after a successful biometric check.

```ts
// Expo: reading the item triggers the system prompt
await SecureStore.setItemAsync('refreshToken', token, { requireAuthentication: true });

// react-native-keychain
await Keychain.setGenericPassword('session', token, {
  accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
  accessible: Keychain.ACCESSIBLE.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
});
```

Enrolling a new fingerprint or face invalidates such items. Handle the read error by sending the user through a normal sign-in.

## Encrypting local data

Generate the key on the device, keep it in secure storage, and pass it to the database or store.

```ts
import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';

const KEY_ID = 'local-store-key';
const toHex = (n: number) => n.toString(16).padStart(2, '0');

export async function loadStoreKey(): Promise<string> {
  const saved = await SecureStore.getItemAsync(KEY_ID);
  if (saved) return saved;

  const random = await Crypto.getRandomBytesAsync(16);   // size the key for the store you use
  const fresh = [...random].map(toHex).join('');
  await SecureStore.setItemAsync(KEY_ID, fresh, {
    keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
  });
  return fresh;
}
```

Pass the result as `encryptionKey` to MMKV (`createMMKV({ id, encryptionKey })` in v4, `new MMKV({ id, encryptionKey })` in earlier versions), as the Realm `encryptionKey`, or as the SQLCipher key. Open the store after the key resolves; a store created at module scope with a placeholder or literal key is the original problem again. Because Keystore keys are not backed up, either exclude the encrypted files from backup or handle "key missing after restore" by resetting the store.

## Deep-link parameters

Validate where the value enters, against an allowlist, and never act on arrival.

```ts
const ALLOWED_HOSTS = new Set(['help.example.com']);

function safePortalUrl(raw: unknown): string {
  try {
    const url = new URL(String(raw));
    if (url.protocol === 'https:' && ALLOWED_HOSTS.has(url.hostname)) return url.toString();
  } catch {}
  return 'https://help.example.com'; // fixed fallback
}
```

Compare a parsed hostname exactly. `startsWith`, `includes` and regexes without anchors are bypassed by `trusted.com.evil.io` and `evil.io/?trusted.com`. For ids and enums, validate the shape with the schema library the project already uses. For anything that changes state (accept, pay, delete, link account), land on a screen that shows what will happen and wait for the user to confirm. Keep auth guards in the screen or layout, not in the navigator that deep links skip.

## WebViews

```tsx
<WebView
  source={{ uri: safePortalUrl(route.params?.url) }}
  originWhitelist={['https://help.example.com']}
  onShouldStartLoadWithRequest={(req) => isAllowedUrl(req.url)}   // every navigation, not only the first
  onMessage={(event) => {
    if (!isAllowedUrl(event.nativeEvent.url)) return;             // who is talking
    const msg = parseMessage(event.nativeEvent.data);              // validate shape, ignore unknown types
    if (msg?.type === 'close') navigation.goBack();
  }}
/>
```

- Do not inject access tokens, user objects or keys into the page. If the web content needs a session, have the app request a short-lived single-use code from the backend, pass that in the URL, and let the web app exchange it server-side.
- Bridge messages should request narrow, harmless UI actions. Anything with consequences (payments, account changes) needs a native confirmation and a server-side check.
- Build injected script with `JSON.stringify` for every interpolated value.
- Leave file-access and mixed-content props at their defaults. For static content that needs no script, `javaScriptEnabled={false}` removes the whole class.

## OAuth

- Authorization-code flow with PKCE in the system browser. `expo-auth-session` and `react-native-app-auth` both do this by default: remove `usePKCE: false`, `ResponseType.Token` and any `clientSecret`.
- Prefer a Universal Link / App Link redirect URI for production. With a custom scheme, PKCE is what stops another app using an intercepted code.
- Exchange the code on the backend when the backend issues its own session; verify ID tokens there (signature, issuer, audience, nonce), not in the app.
- On sign-out, revoke the refresh token with the provider, then clear local storage.
- Require fresh authentication for sensitive operations (changing email or password, payments, data export).

## Transport security and pinning

```xml
<!-- android/app/src/main/res/xml/network_security_config.xml, referenced by android:networkSecurityConfig -->
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors><certificates src="system" /></trust-anchors>
  </base-config>
  <debug-overrides>
    <trust-anchors><certificates src="user" /></trust-anchors>
  </debug-overrides>
</network-security-config>
```

- iOS: remove `NSAllowsArbitraryLoads`; if one legacy host needs an exception, scope it to that host. Keep dev-server exceptions in the Debug configuration.
- A staging server with a self-signed certificate is fixed by giving staging a real certificate or by a debug-only trust override, never by a trust-all client in the main source set.
- Delete custom `TrustManager` / `HostnameVerifier` / challenge-handler code rather than guarding it, unless it is genuine pinning.

Pinning, where the threat model calls for it:

```ts
import { initializeSslPinning, addSslPinningErrorListener } from 'react-native-ssl-public-key-pinning';

await initializeSslPinning({
  'api.example.com': {
    includeSubdomains: true,
    publicKeyHashes: ['<current SPKI SHA-256, base64>', '<backup key held offline>'],
    expirationDate: '2027-06-30',
  },
});
addSslPinningErrorListener((e) => report('pinning_failure', e.serverHostname));
```

Pin public keys (SPKI hashes), not certificates. Always ship a backup pin, initialise before the first request, report failures, and plan rotation before the server key changes. After `expirationDate` pinning switches off so old builds keep working: treat that date as a deadline. Pinning set up this way does not cover WebViews or native SDKs that bring their own HTTP client.

## Backups, logs and screen content

- Android backups: `android:allowBackup="false"`, or `dataExtractionRules` / `fullBackupContent` that exclude the sensitive files. Expo: `"android": { "allowBackup": false }`.
- Console output: add `babel-plugin-transform-remove-console` under the production env in `babel.config.js`, and remove logging of tokens and request bodies at the source.
- Crash and analytics SDKs: scrub in the SDK hook (Sentry `beforeSend` / `beforeBreadcrumb`), keep `sendDefaultPii` off, mask inputs in session replay.
- Push notifications: send an identifier and fetch the sensitive content after the app is unlocked, so it never sits on the lock screen or in the notification service's logs.
- Screens showing credentials, card data, one-time codes or private messages: block capture on those screens only (`expo-screen-capture` `usePreventScreenCapture()`, or `FLAG_SECURE` natively) and cover the app-switcher snapshot. App-wide blocking breaks legitimate screenshots and screen sharing.
- Source maps and iOS dSYMs: upload to the crash service with a build-time token; do not package them in the app or serve them publicly.

## Logout and reinstall

- Sign-out clears secure storage, persisted state, query caches, encrypted stores, WebView cookies and push registration, after revoking the refresh token server-side.
- iOS Keychain items survive app deletion. On first launch, check a flag kept outside the Keychain; if it is missing, wipe the app's Keychain items before doing anything else.

## OTA updates

- expo-updates: enable code signing (`updates.codeSigningCertificate` and `codeSigningMetadata` in app config), keep the private key in the CI secret store, and publish only from CI.
- Self-hosted or custom updaters: https only, verify a signature against a public key embedded in the binary before a bundle is loaded, store bundles in app-private files.
- Treat publish credentials (`EXPO_TOKEN`, update-server keys) as production-deploy secrets: scoped, rotated, never in the repository.

## Attestation

Local root, hook and debugger checks are signals: report them and warn, do not treat a JS boolean as access control. The control that survives a hostile device is platform attestation verified by the server.

1. The server issues a fresh single-use challenge.
2. The app obtains an attestation bound to that challenge and to the request: App Attest (`generateKeyAsync`, `attestKeyAsync`, then `generateAssertionAsync` per request) or Play Integrity (`requestIntegrityCheckAsync(requestHash)`), both available through `@expo/app-integrity`; Firebase App Check wraps the same services.
3. The server verifies it with Apple or Google, checks the challenge, the request hash, the app identity and the verdict, and rejects replays.
4. The server decides per endpoint: block, require step-up authentication, or allow and flag. Devices that cannot attest are handled by server policy, not by the client declaring itself exempt.
