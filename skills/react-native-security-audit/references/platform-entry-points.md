# Platform entry points: deep links, WebViews and other inbound input

The part of the `platform` domain that lives in JavaScript. These are the places where someone other than the user decides what the app receives. They produce most of the high-severity findings in React Native apps, and almost none of them can be found by pattern alone: you have to follow the data.

## Contents

- Deep links and navigation
- WebViews
- The deep link to WebView chain
- Other inbound input
- Not findings

## Deep links and navigation

### Who can send one

- **Custom scheme** (`myapp://...`): any web page (the victim taps a link or is redirected), any other app, a QR code, an NFC tag, a message. On Android, also `adb` and intents from installed apps. No sender identity is available to JS.
- **Universal Links (iOS) / App Links (Android, `autoVerify`)**: the same senders can still *open* them. What verification adds is that only this app *receives* links for the domain. It protects the app from impersonation, not from hostile parameters.

So every path segment and query parameter of an incoming URL is `remote-content` input, exactly like an HTTP request from the internet.

### Where the links land

Find every route by which a URL becomes behaviour:

- **React Navigation `linking` config**: `prefixes` plus the `config.screens` map. Every screen in the map is externally reachable; path params and query params arrive in `route.params` mixed with params from in-app navigation. A custom `getStateFromPath` can widen this further.
- **expo-router**: every file under `app/` is a route and is deep-linkable by default. `useLocalSearchParams()` / `useGlobalSearchParams()` return external input. Check `+native-intent` and any redirect logic in layouts, and whether authenticated groups are actually guarded (a layout that redirects when there is no session) rather than merely hidden from the UI.
- **Manual handlers**: `Linking.getInitialURL()`, `Linking.addEventListener('url', ...)`, `Linking.useURL()`, `expo-linking` `parse`. Read what the handler does with each parsed piece.
- **Native side**: `AppDelegate` `openURL`/`continueUserActivity` and Android `onNewIntent` overrides that do more than forward to React Native.

### What to look for

For each externally reachable screen or handler, ask what an attacker-chosen parameter can cause **without the user understanding or confirming it**:

- **State-changing actions on arrival**: a screen that performs an action in `useEffect` from its params (accept invite, add payee, redeem code, join team, change setting, confirm payment, delete). This is CSRF for mobile apps. `high` when the action matters.
- **Attacker-chosen destinations**: a `url`, `next`, `redirect`, `returnTo` or `path` param that feeds a WebView `source`, `Linking.openURL`, a `fetch` base URL or a navigation call. See the chain below.
- **Auth callbacks**: screens that accept a `code`, `token`, `session` or `magic` param and log the app in. Is the value bound to a login the user started (state/PKCE, a pending-request check)? Otherwise an attacker can sign the victim's app into the attacker's account (login CSRF), or inject a token.
- **Auth bypass by navigation**: a deep link that opens a screen behind the login wall, or behind a local PIN/biometric lock, because the guard lives in the tab navigator rather than on the screen.
- **Parameters used as identifiers**: `userId`, `orderId`, `accountId` from the URL sent to the API. Client-side this is input validation; the security question is server-side authorization → `needs_validation` (see [network-and-auth.md](network-and-auth.md)).
- **Scheme hijack exposure**: sensitive data *sent to* the app through a custom scheme (OAuth codes, magic-link tokens, payment results) can be received by another app that registers the scheme. `local-app` attacker. The fix is verified links or PKCE-style binding.
- **`Linking.openURL(untrusted)`**: lets remote content launch `tel:`, `sms:`, `intent:` (Android), other apps' schemes, or `file:` URLs. Needs a scheme allowlist.

Fixes are specific: validate against an allowlist (hosts, routes, enum values), require a user confirmation step for anything state-changing, keep auth guards on the screen or layout, and bind callbacks to a pending request.

## WebViews

`react-native-webview` is a browser the app controls. Three questions per WebView:

### 1. What can it load?

- `source={{ uri }}` where `uri` is a constant on a domain the company owns: low risk. Note third-party scripts on that page; they run inside the WebView too.
- `uri` built from route params, deep links, push payloads, API responses or user content: the attacker picks the page. Everything in the next two questions is then exposed to them.
- `source={{ html }}` with interpolated server or user content: script injection into the page (stored XSS inside the app). `baseUrl` decides the origin that script runs as.
- Navigation after load: redirects and link clicks can leave the starting origin. Is there an `onShouldStartLoadWithRequest` that restricts navigation to an allowlist, with a host comparison on a parsed URL rather than `startsWith`/`includes` (which `https://trusted.com.evil.io` and `https://evil.io/?trusted.com` defeat)?
- `originWhitelist={['*']}` additionally lets the WebView navigate to `javascript:`, `file:` and custom schemes. The default is `http://*` and `https://*` only.

### 2. What can the page make the app do?

`onMessage` receives `window.ReactNativeWebView.postMessage` calls from **whatever document is currently loaded**, including after a redirect, and on Android from any frame. Read the handler as an API open to that page:

- Which message types exist, and what does each trigger: navigation, API calls with the user's session, purchases, file access, opening URLs, returning data?
- Is the sender checked? The only meaningful check is on `event.nativeEvent.url` (the page's URL) against an exact-origin allowlist, done per message.
- Is the payload parsed defensively? `JSON.parse` on arbitrary input in an unguarded handler is a crash at least.

A handler that performs privileged actions or returns secrets, on a WebView whose content an attacker can influence, is a `confirmed` `remote-content` finding, typically `high`.

### 3. What does the app hand to the page?

- `injectedJavaScript` / `injectedJavaScriptBeforeContentLoaded` / `injectJavaScript()` that write the access token, user profile or API keys into `window`: any page loaded there can read them. Combined with an open URL, that is direct session theft.
- Template strings that interpolate untrusted data into injected script without `JSON.stringify`: script injection from data.
- Auth headers in `source.headers`, and `sharedCookiesEnabled`: sent to the first URL, and cookies to wherever navigation goes.
- Token in the URL itself (`?token=`): leaks through history, Referer and server logs.

### Supporting settings

These widen the blast radius once untrusted content is in; with trusted fixed content they are hardening:

- `allowFileAccess`, `allowFileAccessFromFileURLs`, `allowUniversalAccessFromFileURLs`, `allowingReadAccessToURL`: let page script read local files. With attacker content and a `file://` load this exposes the app sandbox.
- `mixedContentMode="always"`: HTTPS pages may load HTTP scripts.
- `webviewDebuggingEnabled`, or native `setWebContentsDebuggingEnabled(true)` without a debug guard: anyone with USB access inspects the WebView.
- `javaScriptEnabled` is on by default and necessary for most content. Not a finding. Turning it off is a good recommendation for WebViews that only display static or user-supplied HTML.
- Missing `setSupportMultipleWindows={false}` on old `react-native-webview` versions had a known cross-origin issue on Android; flag the outdated dependency rather than the prop.

## The deep link to WebView chain

The single most valuable pattern to check for, because each half looks harmless alone:

1. A linking config or handler exposes a screen that takes a URL-like param (`myapp://web?url=...`, `/browser/[url]`, a "help article" route, a push payload with `link`).
2. That screen renders a WebView with the param as `source.uri`, with no host allowlist.
3. The WebView injects the session token, or its `onMessage` performs authenticated actions.

Result: a link on any web page opens the app, loads the attacker's page inside it, and that page reads the token or drives the bridge. One tap, no warning. `remote-content`, `high`; `critical` only if no tap is needed or the effect is account takeover at scale.

To confirm, cite all three links in the chain with file and line. The fix is an exact-host allowlist where the URL enters, never injecting credentials into web content (use a short-lived, single-purpose code exchanged by the web app, or cookies scoped to the first-party domain), and an origin check in `onMessage`.

## Other inbound input

- **Push notifications**: the payload's `data` is set by whoever can send to the app's push channel. Normally that is the backend, but treat `url`/`screen`/`params` fields in notification handlers like deep-link input, because marketing tools, compromised FCM server keys and misconfigured topics do send arbitrary payloads. Handlers that navigate to `data.url` without validation join the chain above.
- **Shared files and intents** (`react-native-share-menu`, `expo-sharing` receivers, document pickers, "open in"): file names and contents are attacker-controlled. Look for path traversal when a received file name is used to build a destination path, and for parsing of complex formats.
- **Clipboard and QR codes**: scanned or pasted values that are navigated to or sent to the API without checks are deep-link input by another route.
- **Server responses**: content from the app's own API is lower-risk but not trusted when it carries user-generated data or third-party content. A `url`, `html`, `deeplink` or `action` field from a response that reaches a WebView, `Linking.openURL`, navigation or injected script deserves the same checks as a deep-link parameter. Unvalidated response shapes (no schema check) are a robustness and hardening note rather than a finding.
- **Android exported components and iOS extensions**: see [android.md](android.md) and [ios.md](ios.md).
- **Dynamic code**: `eval`, `new Function`, or a remote "script"/"formula"/"template" feature executing server- or user-supplied code in the app's JS context has the app's full privileges (tokens, native modules).

## Not findings

- A deep link that only opens public or read-only screens with validated or harmless params.
- A custom scheme used for non-sensitive navigation. Custom schemes are fine; routing secrets through them is the problem.
- A WebView showing a fixed first-party URL with no bridge and no injected secrets, including one with `javaScriptEnabled`.
- `postMessage` used only from native to web for non-sensitive UI state.
- Universal Links being absent, by itself: a hardening suggestion when sensitive callbacks use a custom scheme, otherwise nothing.
