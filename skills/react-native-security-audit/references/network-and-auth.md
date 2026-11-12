# Network and authentication

Covers the `network` and `auth` domains: what protects data between the app and its servers, and how the app establishes and keeps a user's identity.

## Transport security

### Cleartext

A cleartext finding needs two things at once: the release app makes an `http://` or `ws://` request, and the platform lets it.

- **Android** blocks cleartext by default for apps targeting API 28+. It is allowed by `android:usesCleartextTraffic="true"` on `<application>` in the *main* manifest, or by `cleartextTrafficPermitted="true"` in a network security config. The debug manifest allowing it is the template default (Metro needs it) and not a finding.
- **iOS** blocks it through App Transport Security unless `NSAllowsArbitraryLoads` is true or the host has an `NSExceptionAllowsInsecureHTTPLoads` exception. `NSAllowsLocalNetworking` is the template default and harmless.
- **Expo**: `expo-build-properties` (`android.usesCleartextTraffic`), `ios.infoPlist.NSAppTransportSecurity` in app config.

A permissive setting with no cleartext request behind it is a hardening note ("tighten it so a future mistake fails closed"). A cleartext URL that both platforms would refuse is dead configuration. Both present: rate by what travels over it. Credentials or session tokens → `high`. Personal data → `medium`. Public content only → `low`, with the caveat that injected responses can still mislead the app.

Also look for the base URL being chosen at runtime from something a user or a link can set (a "server URL" field, a debug menu left in release, a deep-link parameter). That is an entry-point issue: see [platform-entry-points.md](platform-entry-points.md).

### TLS validation switched off

The most serious network finding, and usually introduced "temporarily" for a staging server. Look in native code and in library options:

- **Android**: an `X509TrustManager` with an empty `checkServerTrusted`, a `HostnameVerifier` returning `true`, `OkHttpClientProvider.setOkHttpClientFactory(...)` installing such a client for React Native's own networking (`fetch`, XHR, and usually images and WebSockets; WebViews and native SDKs with their own HTTP client are separate, so scope the claim), a WebView `onReceivedSslError` that calls `handler.proceed()`, a network security config trusting user-installed CAs outside `<debug-overrides>`.
- **iOS**: a `URLSession`/`RCTHTTPRequestHandler` challenge delegate that returns a credential for the server trust without evaluating it, `RCTSetCustomNSURLSessionConfigurationProvider` used to loosen settings, `allowsAnyHTTPSCertificate`.
- **JS-level options**: `trusty: true` (`react-native-blob-util`, `rn-fetch-blob`), `disableAllSecurity: true` (`react-native-ssl-pinning`). `rejectUnauthorized: false` is a Node option: it matters in scripts and servers, not in the app's `fetch`.

Then establish the variant. Is the class in `src/main` or `src/debug`? Is its registration guarded by `BuildConfig.DEBUG`, `#if DEBUG` or a build flavor? Registered unconditionally in the release path it is `confirmed`, `network` attacker, normally `high`: anyone on the same Wi-Fi reads and alters all API traffic, tokens included. Present in the release source but guarded by a flag whose value you cannot see → `needs_validation`.

### Certificate pinning

Pinning protects against a mis-issued or user-installed CA. Its absence is **hardening**, not a vulnerability, for nearly every app; platform TLS validation is the control. Mention it as expected practice only for high-value apps (see the purpose section of [threat-model.md](threat-model.md)).

When pinning is present, check that it works, because a team that believes it is pinned stops worrying about interception:

- Pins cover the hosts actually used, and there is a backup pin (the common JS library requires at least two per domain on iOS).
- Expiry: an Android `pin-set expiration` or a library `expirationDate` in the past means pinning is silently off.
- Pinning is initialised before the first request. Requests made earlier (startup config, token refresh) go out unpinned.
- Coverage: JS-level pinning applies to the React Native networking stack. WebViews and native SDKs with their own HTTP client are not covered.
- Failures are reported and not swallowed with a fallback to an unpinned client. A remote "disable pinning" switch is a bypass if an attacker on the path can flip it: check what channel delivers it.

Broken or partial pinning is worth a `low`/`info` finding in an app that relies on it.

### Credentials in the wrong place

- Tokens, API keys or passwords in URL query strings end up in server and proxy logs, analytics, and crash breadcrumbs. Rate by token lifetime and power.
- Authorization headers attached to every request by an interceptor, including requests to third-party hosts or to URLs taken from server or user content. Check that the interceptor is scoped to the API's own origin. A token sent to an attacker-chosen host is a clean finding.
- Full request/response logging in an interceptor (see logs in [data-storage-and-crypto.md](data-storage-and-crypto.md)).

## Authentication and session

### OAuth and OpenID Connect

A mobile app is a public client. The sound shape: system browser (`ASWebAuthenticationSession` / Custom Tabs, which is what `expo-auth-session`, `expo-web-browser` and `react-native-app-auth` use), authorization-code flow with PKCE, a `state` value checked on return, no client secret, tokens stored in secure storage.

Findings to look for:

- **No PKCE with a custom-scheme redirect** (`usePKCE: false`, a hand-rolled flow without `code_challenge`). Any app can register the same scheme, and whichever app receives the redirect gets the authorization code. Without PKCE nothing ties that code to the app instance that started the login, so the interceptor can redeem it: the client id, and any client secret, are in the bundle. `local-app` attacker, normally `high` on Android. On iOS, flows that run in `ASWebAuthenticationSession` (which is what `react-native-app-auth`, `expo-web-browser` and `expo-auth-session` use) return the callback to the session that started it instead of dispatching the scheme, so interception there is limited to flows that open the browser with plain `openURL`. Say which platforms are exposed. The client code is enough evidence: if the provider insisted on PKCE, a flow that sends none would not work at all, so a shipping non-PKCE login means the provider accepts it.
- **Implicit flow** (`response_type=token`, `ResponseType.Token`): tokens travel in the redirect URL itself. Same interception problem with no exchange step to protect.
- **Password grant** (`grant_type=password`) against a third-party identity provider: the app collects the user's provider password itself. Acceptable only for first-party login to the app's own API; otherwise a design finding, and many providers have removed it.
- **ID tokens trusted without verification.** Reading claims in the app is fine for display. An ID token that the app forwards to its backend as proof of identity must be verified there (signature, issuer, audience, nonce); whether it is lives on the server → `needs_validation`.
- **Client secret in the app.** See [secrets-and-config.md](secrets-and-config.md).
- **`state` not checked** in a hand-rolled flow: login CSRF, attaching the victim's app to the attacker's account.
- **Login inside an embedded WebView** instead of the system browser: the app can read the user's credentials for the identity provider, and many providers block it. A design weakness; rate `low`/`medium` unless the WebView also has a bridge.
- **Redirect URI handling**: the callback screen accepts a code or token from any deep link at any time, without a pending request to match it to. See [platform-entry-points.md](platform-entry-points.md).

Universal Links / App Links as the redirect URI remove the scheme-hijack risk because the OS verifies domain ownership. Recommend them for sensitive flows.

### Sessions and tokens

- Lifetime and rotation: a refresh token that never expires and is not rotated turns any storage leak into permanent access. Usually visible only in part from the client; note what you can see.
- Logout: is the refresh token revoked server-side (a call is made), or only forgotten locally? Is local state fully cleared (storage section in [data-storage-and-crypto.md](data-storage-and-crypto.md))?
- Step-up: do sensitive operations (changing email or password, payments, adding a payee, exporting data) ask for fresh authentication, or does any unlocked session suffice? Enforcement is server-side, so absence in the client is a lead (MASVS-AUTH-3), usually `needs_validation` or hardening.
- Token refresh races and retry loops are reliability issues, not security findings, unless they leak tokens.
- Magic-link and OTP flows: is the code long and random enough, and is verification done by the server? A client that receives the expected OTP in the API response and compares locally is a `confirmed` break.

### Biometrics and local unlock

Two different designs hide behind the same Face ID prompt:

- **Event-bound**: call `LocalAuthentication.authenticateAsync()` / `simplePrompt()`, get `success: true`, proceed. The check is a boolean in JS. On a compromised device it can be forced to true. It also says nothing about *which* enrolled biometric approved.
- **Crypto-bound**: the secret (token, key) is stored in Keychain/Keystore with biometric access control (`requireAuthentication`, `accessControl: BIOMETRY_CURRENT_SET`, or a Keystore-backed signature as in `react-native-biometrics` `createSignature`). The OS releases it only after a successful biometric check, and enrolling a new fingerprint invalidates it. There is no boolean to flip.

Event-bound biometrics as a convenience re-lock over an existing session is fine: hardening note at most. It is a finding (`low` to `medium`, `compromised-device` or `device-access`) when it is the only thing in front of a high-value action or of credentials stored in plaintext beside it. A local PIN compared in JS against a value in AsyncStorage is the same pattern with less ceremony.

### Client-side authorization

Role flags (`isAdmin`), entitlement flags (`isPremium`), prices, limits and feature gates in client state are for rendering. They are leads when the code suggests the server might rely on them:

- A privileged API call guarded only by a client-side `if`.
- A request body that carries its own authority (`role`, `userId`, `price`, `isVerified`) rather than the server deriving it from the session.
- Object ids taken from route params and sent straight to "get/update by id" endpoints.
- Purchases validated on the device (receipt checked locally, entitlement flag flipped locally) rather than by the server or the store's server API.

Whether the server checks is almost always outside the repository, so these become `needs_validation` with a precise request for the owner: "confirm `DELETE /teams/:id/members/:userId` rejects a caller who does not own the team". Name the endpoint and the missing check. Confirm only when the server side is in the repo (same monorepo, BaaS rules) and visibly lacks the check, or when the business depends on client-side enforcement (see [threat-model.md](threat-model.md)).

## Not findings

- No certificate pinning in an ordinary app.
- Cleartext allowed only in the debug variant, or cleartext URLs to localhost and emulator addresses.
- `rejectUnauthorized: false` in Metro, Jest or build scripts.
- Hiding UI by role when nothing suggests the server skips the check.
- Biometric prompts used as a convenience lock.
- Access tokens in memory; standard SDK-managed sessions (Firebase Auth, Auth0, Clerk) used as documented.
