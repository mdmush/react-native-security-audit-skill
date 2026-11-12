// Lead rules for the scanner.
//
// A rule match is a LEAD: a place worth reading. It is never a finding by
// itself. Every rule carries a `triage` line telling the reviewer what decides
// whether the lead is real, because the same line of code can be a critical
// issue in one app and nothing at all in another.
//
// Rule shape:
//   id, domain, title, masvs[]   identification
//   files                        file class (see FILE_CLASSES) or a (relPath) => boolean
//   re                           global RegExp, matched against whole file content
//   redact                       capture-group index, or (match) => string, of a secret value to mask
//   oncePerFile                  report only the first hit in each file
//   keep                         optional (match, ctx) => boolean post-filter
//   triage                       what to check before believing it
//   signal                       'high' | 'medium' | 'low' (how often a hit is real)

const JS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];

export const FILE_CLASSES = {
  js: (p) => JS.some((e) => p.endsWith(e)),
  jsAndConfig: (p) => JS.some((e) => p.endsWith(e)) || p.endsWith('.json') || isEnvFile(p),
  env: (p) => isEnvFile(p),
  packageJson: (p) => base(p) === 'package.json',
  appConfig: (p) => /^(app\.json|app\.config\.(js|ts|mjs|cjs))$/.test(base(p)),
  easJson: (p) => base(p) === 'eas.json',
  manifest: (p) => base(p) === 'AndroidManifest.xml',
  androidXml: (p) => p.endsWith('.xml') && /(^|\/)android\//.test(p),
  gradle: (p) => /\.(gradle|kts|properties)$/.test(p) && /(^|\/)android\//.test(p),
  androidCode: (p) => /\.(java|kt)$/.test(p),
  plist: (p) => /\.(plist|entitlements)$/.test(p),
  iosCode: (p) => /\.(m|mm|swift|h)$/.test(p),
  backendRules: (p) => /\.rules$/.test(p) || base(p) === 'database.rules.json',
  anyText: () => true,
};

function base(p) {
  return p.slice(p.lastIndexOf('/') + 1);
}

export function isEnvFile(p) {
  return /^\.env(\..+)?$/.test(base(p));
}

const PLACEHOLDER =
  /^(x{3,}|y{3,}|0{6,}|1234|changeme|change[_-]me|example|placeholder|dummy|sample|test|todo|your[_-]|my[_-]|<|\{\{|\$\{|process\.env|null|undefined|true|false)/i;

// Generic "name looks secret, value is a literal" filter. The aim is to drop
// form labels, i18n keys and placeholders without dropping real credentials.
function looksLikeSecretValue(value, name) {
  if (!value || PLACEHOLDER.test(value)) return false;
  if (value.toLowerCase() === String(name).toLowerCase()) return false;
  if (/^[A-Za-z]+$/.test(value) && value.length < 20) return false; // a word, not a credential
  if (/^[a-z]+([._-][a-z]+)+$/.test(value)) return false; // i18n key or dotted path
  if (/^https?:\/\//i.test(value)) return false;
  return /\d/.test(value) || value.length >= 20;
}

// Every printed excerpt is passed through this as a last line of defence, so a
// secret sharing a line with some unrelated lead is still masked.
export const GENERIC_SECRET_ASSIGNMENT =
  /\b([A-Za-z0-9_]*(?:secret|passw(?:or)?d|private[_-]?key|api[_-]?key|access[_-]?token|auth[_-]?token|signing[_-]?key|encryption[_-]?key|service[_-]?role)[A-Za-z0-9_]*)["']?\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]/gi;
export { looksLikeSecretValue };

const SENSITIVE_WORD = '(?:token|passw|secret|credential|session|jwt|auth|pin\\b|ssn|card|cvv|otp|private)';

export const RULES = [
  // ---------------------------------------------------------------- secrets
  {
    id: 'SEC-GENERIC-ASSIGNMENT',
    domain: 'secrets',
    title: 'Secret-looking name assigned a literal value',
    masvs: ['MASVS-AUTH-1'],
    // Env and Gradle files have their own rules, so they are left out here.
    files: (p) => FILE_CLASSES.js(p) || /\.(json|ya?ml|xcconfig)$/.test(p),
    re: /\b([A-Za-z0-9_]*(?:secret|passw(?:or)?d|private[_-]?key|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|signing[_-]?key|encryption[_-]?key|service[_-]?role)[A-Za-z0-9_]*)["']?\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]/gi,
    redact: 2,
    keep: (m) => looksLikeSecretValue(m[2], m[1]) && !/client_?secret/i.test(m[1]),
    signal: 'medium',
    triage:
      'Decide what the value is before rating it: a backend secret (real finding, and moving it to an env var does not fix it), or a public client identifier (publishable key, DSN, app id). See references/secrets-and-config.md.',
  },
  {
    id: 'SEC-PUBLIC-ENV-SECRET-NAME',
    domain: 'secrets',
    title: 'Bundled env var whose name says it is a secret',
    masvs: ['MASVS-AUTH-1'],
    files: 'anyText',
    re: /\b(?:EXPO_PUBLIC|REACT_APP|NEXT_PUBLIC|VITE)_[A-Z0-9_]*(?:SECRET|PRIVATE|PASSWORD|SERVICE_ROLE|ADMIN|SIGNING|OPENAI|ANTHROPIC|GEMINI|MISTRAL|GROQ|OPENROUTER|TWILIO|SENDGRID|MAILGUN|RESEND|AWS)[A-Z0-9_]*/g,
    signal: 'high',
    triage:
      'EXPO_PUBLIC_* (and react-native-config / dotenv values read in JS) are inlined into the shipped bundle. If the name is accurate, anyone with the app has this credential. Confirm it is read by app code, then identify the service and privilege.',
  },
  {
    id: 'SEC-ENV-FILE-VALUE',
    domain: 'secrets',
    title: 'Secret-looking value in an env file',
    masvs: ['MASVS-AUTH-1'],
    files: 'env',
    re: /^[ \t]*(?:export[ \t]+)?([A-Z0-9_]*(?:SECRET|PASSWORD|PRIVATE|TOKEN|API_?KEY|SERVICE_ROLE|CREDENTIAL)[A-Z0-9_]*)[ \t]*=[ \t]*["']?([^\s"'#]{8,})/gim,
    redact: 2,
    // Bundled-prefix names are reported once, by SEC-PUBLIC-ENV-SECRET-NAME.
    keep: (m, ctx) => ctx.context !== 'example' && !PLACEHOLDER.test(m[2]) && !/^(?:EXPO_PUBLIC|REACT_APP|NEXT_PUBLIC|VITE)_/.test(m[1]),
    signal: 'medium',
    triage:
      'Two separate questions: is the file tracked by git (repository exposure), and is the value read by JS and therefore embedded in the app (binary exposure)? Check `sensitiveFiles` for tracked status.',
  },
  {
    id: 'SEC-GRADLE-SIGNING-PASSWORD',
    domain: 'supply-chain',
    title: 'Release keystore password in Gradle files',
    masvs: ['MASVS-RESILIENCE-2'],
    files: 'gradle',
    // Quoted literal in a Gradle script, or KEY=value in a properties file. A bare
    // identifier after storePassword is a variable reference, not a password.
    re: /\b(?:store|key)Password\s*[=(]?\s*["']([^"'$]{4,})["']|^[ \t]*[A-Za-z0-9_.]*(?:STORE|KEY)_PASSWORD[ \t]*=[ \t]*(\S{4,})/gm,
    redact: (m) => m[1] || m[2],
    keep: (m) => (m[1] || m[2]) !== 'android',
    signal: 'high',
    triage:
      'The RN template debug keystore uses the password "android" and is not a finding. A literal upload/release keystore password in a tracked file lets anyone with repo access sign as the app if the keystore is also reachable.',
  },
  {
    id: 'SEC-CREDENTIALS-IN-URL',
    domain: 'secrets',
    title: 'Credentials embedded in a URL',
    masvs: ['MASVS-AUTH-1'],
    files: 'anyText',
    re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@'"`<>]{2,}:([^\s/:@'"`<>${}]{4,})@[A-Za-z0-9.-]+/g,
    redact: 1,
    signal: 'high',
    triage: 'user:password@host in a URL. Check whether it reaches the bundle or only build tooling.',
  },
  {
    id: 'SEC-SERVICE-ACCOUNT-JSON',
    domain: 'secrets',
    title: 'Cloud service-account key file',
    masvs: ['MASVS-AUTH-1'],
    files: (p) => p.endsWith('.json'),
    re: /"type"\s*:\s*"service_account"/g,
    signal: 'high',
    triage:
      'A service-account key is a backend credential. Critical if it is bundled into the app or imported by JS; still a repository exposure if only CI uses it (Play upload key).',
  },
  {
    id: 'SEC-SECRET-KEY-API-CALLED-FROM-CLIENT',
    domain: 'secrets',
    title: 'Direct call from app code to an API that needs a server-side key',
    masvs: ['MASVS-AUTH-1'],
    files: 'js',
    re: /\bapi\.(?:openai|anthropic|mistral|groq|cohere|perplexity|x)\.(?:com|ai)\b|\bopenrouter\.ai\/api\b|\bgenerativelanguage\.googleapis\.com\b|\bapi\.(?:sendgrid|twilio|postmarkapp|resend|stripe)\.com\b|\bapi\.mailgun\.net\b/g,
    signal: 'high',
    triage:
      'These APIs authenticate with an account secret. If the request is built in app code, the credential it sends is in the bundle whatever variable it came from. Read the Authorization header. (Stripe is the exception when only a publishable key or the official SDK is used.)',
  },
  {
    id: 'SEC-OAUTH-CLIENT-SECRET',
    domain: 'secrets',
    title: 'OAuth client secret in a public client',
    masvs: ['MASVS-AUTH-1'],
    files: 'js',
    re: /\bclient_?[sS]ecret["']?\s*[:=]\s*["'`]([^"'`]{4,})["'`]/g,
    redact: 1,
    signal: 'high',
    triage:
      'A mobile app is a public OAuth client and cannot keep a client secret. Check which provider and whether the secret unlocks anything beyond what PKCE already allows.',
  },

  // ---------------------------------------------------------------- storage
  {
    id: 'STO-ASYNCSTORAGE-SENSITIVE',
    domain: 'storage',
    title: 'Sensitive-looking value written to AsyncStorage',
    masvs: ['MASVS-STORAGE-1'],
    files: 'js',
    re: new RegExp(`AsyncStorage\\.(?:setItem|multiSet|mergeItem)\\s*\\([^)\\n]{0,200}?${SENSITIVE_WORD}`, 'gi'),
    signal: 'high',
    triage:
      'AsyncStorage is plaintext in the app sandbox. Establish what is stored (long-lived refresh token vs a feature flag named "authSeen") and who can read it: device backups, a rooted or jailbroken device, forensic access.',
  },
  {
    id: 'STO-PERSISTED-STATE',
    domain: 'storage',
    title: 'State persistence configuration',
    masvs: ['MASVS-STORAGE-1'],
    files: 'js',
    re: /\b(?:persistReducer|persistStore|createJSONStorage|createAsyncStoragePersister|persistQueryClient|CachePersistor|createSyncStoragePersister)\s*\(|\bpersist\s*\(\s*(?:\(|[a-zA-Z])/g,
    signal: 'medium',
    triage:
      'Find which slices/queries are persisted and into what storage. A whitelisted `auth` slice or a persisted query cache holding tokens or PII is the same issue as writing them to AsyncStorage directly.',
  },
  {
    id: 'STO-HARDCODED-ENCRYPTION-KEY',
    domain: 'storage',
    title: 'Hardcoded database/storage encryption key',
    masvs: ['MASVS-CRYPTO-2', 'MASVS-STORAGE-1'],
    files: 'js',
    re: /\bencryptionKey\s*:\s*["'`]([^"'`]{4,})["'`]/g,
    redact: 1,
    signal: 'high',
    triage:
      'An encryption key that ships in the bundle protects nothing against anyone who has the app. The key should be generated on device and held in Keychain/Keystore.',
  },
  {
    id: 'STO-KEYCHAIN-ALWAYS-ACCESSIBLE',
    domain: 'storage',
    title: 'Keychain item accessible while the device is locked',
    masvs: ['MASVS-STORAGE-1'],
    files: (p) => FILE_CLASSES.js(p) || FILE_CLASSES.iosCode(p),
    re: /\b(?:ACCESSIBLE\.ALWAYS(?:_THIS_DEVICE_ONLY)?|SecureStore\.ALWAYS(?:_THIS_DEVICE_ONLY)?|kSecAttrAccessibleAlways(?:ThisDeviceOnly)?)\b/g,
    signal: 'medium',
    triage: 'Deprecated accessibility class. Check what the item is and whether background access really needs it; AFTER_FIRST_UNLOCK usually does.',
  },
  {
    id: 'STO-KEYCHAIN-CLOUD-SYNC',
    domain: 'storage',
    title: 'Keychain item synchronised to iCloud',
    masvs: ['MASVS-STORAGE-1'],
    files: (p) => FILE_CLASSES.js(p) || FILE_CLASSES.iosCode(p),
    re: /\bcloudSync\s*:\s*true\b|\bkSecAttrSynchronizable\b(?!Any)/g,
    signal: 'low',
    triage: 'The item leaves the device and appears on the user\'s other devices. Reasonable for user passwords, wrong for device-bound session tokens and encryption keys.',
  },
  {
    id: 'STO-EXTERNAL-STORAGE',
    domain: 'storage',
    title: 'Write to shared/external storage',
    masvs: ['MASVS-STORAGE-2'],
    files: 'js',
    re: /\b(?:ExternalStorageDirectoryPath|ExternalDirectoryPath|DownloadDirectoryPath|ExternalCachesDirectoryPath)\b/g,
    signal: 'medium',
    triage: 'Other apps and the user can read shared storage. What is written there?',
  },
  {
    id: 'STO-SENSITIVE-LOGGING',
    domain: 'storage',
    title: 'Sensitive-looking value passed to console',
    masvs: ['MASVS-STORAGE-2'],
    files: 'js',
    re: new RegExp(`console\\.(?:log|debug|info|warn|error)\\s*\\([^)\\n]{0,200}?${SENSITIVE_WORD}`, 'gi'),
    signal: 'medium',
    triage:
      'console.* still runs in release builds unless stripped (babel transform-remove-console) and goes to the device log. Check whether the value is the secret itself or just a label, and whether a crash/analytics SDK also captures console breadcrumbs.',
  },
  {
    id: 'STO-CLIPBOARD-WRITE',
    domain: 'storage',
    title: 'Clipboard write',
    masvs: ['MASVS-STORAGE-2'],
    files: 'js',
    re: /\bClipboard\.setString(?:Async)?\s*\(/g,
    signal: 'low',
    triage: 'Only relevant when the copied value is a credential, recovery phrase or OTP.',
  },

  // ----------------------------------------------------------------- crypto
  {
    id: 'CRY-MATH-RANDOM-SECURITY',
    domain: 'crypto',
    title: 'Math.random() near a security-relevant value',
    masvs: ['MASVS-CRYPTO-1'],
    files: 'js',
    re: /^.*(?:token|nonce|otp|passw|secret|salt|verifier|session|challenge).*Math\.random\s*\(\).*$|^.*Math\.random\s*\(\).*(?:token|nonce|otp|passw|secret|salt|verifier|session|challenge).*$/gim,
    signal: 'medium',
    triage:
      'Math.random is predictable. Real when it produces something an attacker must not guess (OAuth state/PKCE verifier, reset token, key, IV). Not a finding for UI keys, jitter or animation.',
  },
  {
    id: 'CRY-WEAK-ALGORITHM',
    domain: 'crypto',
    title: 'Weak hash, cipher or mode',
    masvs: ['MASVS-CRYPTO-1'],
    files: (p) => FILE_CLASSES.js(p) || FILE_CLASSES.androidCode(p) || FILE_CLASSES.iosCode(p),
    re: /\bCryptoJS\.(?:MD5|SHA1|DES|TripleDES|RC4)\b|createHash\(\s*["'](?:md5|sha1)["']|CryptoDigestAlgorithm\.(?:MD5|SHA1)\b|\bmode\.ECB\b|["']AES\/ECB\/|\bCC_MD5\s*\(|MessageDigest\.getInstance\(\s*"(?:MD5|SHA-?1)"/g,
    signal: 'medium',
    triage: 'Depends entirely on use. MD5 for a cache key is fine; MD5/SHA1 for passwords, signatures or integrity is not. ECB for any real data is.',
  },
  {
    id: 'CRY-HARDCODED-PASSPHRASE',
    domain: 'crypto',
    title: 'Symmetric encryption with a literal key',
    masvs: ['MASVS-CRYPTO-2'],
    files: 'js',
    re: /\bCryptoJS\.(?:AES|DES|TripleDES|Rabbit|RC4)\.(?:encrypt|decrypt)\s*\([^,\n]+,\s*["'`]([^"'`]+)["'`]/g,
    redact: 1,
    signal: 'high',
    triage: 'The key ships with the app, so this is obfuscation. Rate it by what the "encrypted" data is and who is meant to be kept out.',
  },

  // ------------------------------------------------------------------- auth
  {
    id: 'AUTH-BIOMETRIC-BOOLEAN-GATE',
    domain: 'auth',
    title: 'Biometric prompt that returns a boolean',
    masvs: ['MASVS-AUTH-2'],
    files: 'js',
    re: /\b(?:LocalAuthentication\.authenticateAsync|authenticateAsync|simplePrompt|TouchID\.authenticate|FingerprintScanner\.authenticate)\s*\(/g,
    signal: 'medium',
    triage:
      'A boolean result can be flipped on a compromised device. It is a real weakness when it is the only gate on a high-value action or secret; it is fine as a convenience re-lock. The strong form binds a Keychain/Keystore item to biometrics.',
  },
  {
    id: 'AUTH-OAUTH-WEAK-FLOW',
    domain: 'auth',
    title: 'OAuth flow without PKCE, or using the implicit or password grant',
    masvs: ['MASVS-AUTH-1'],
    files: 'js',
    re: /\busePKCE\s*:\s*false\b|ResponseType\.Token\b|response_type=token\b|\bskipCodeExchange\s*:\s*true\b|\bgrant_type["']?\s*[:=]\s*["']?password\b/g,
    signal: 'high',
    triage:
      'With a custom-scheme redirect and no PKCE, another app that registers the same scheme can take the authorization code. Check the redirect URI type. The password grant (grant_type=password) means the app itself handles the user\'s identity-provider password: fine only for a first-party login to the app\'s own API.',
  },
  {
    id: 'AUTH-OAUTH-ENTRY',
    domain: 'auth',
    title: 'OAuth / SSO entry point',
    masvs: ['MASVS-AUTH-1'],
    files: 'js',
    re: /\b(?:useAuthRequest|openAuthSessionAsync|makeRedirectUri|startAsync)\s*\(|\bauthorize\s*\(\s*\w*[cC]onfig/g,
    signal: 'low',
    triage: 'Read the whole flow: redirect URI, state check, PKCE, where tokens land, and whether an embedded WebView is used instead of the system browser.',
  },
  {
    id: 'AUTH-CLIENT-SIDE-AUTHZ',
    domain: 'auth',
    title: 'Authorization decision made from client state',
    masvs: ['MASVS-AUTH-1'],
    files: 'js',
    re: /\b(?:isAdmin|is_admin|isSuperuser|isStaff)\b|\brole\s*={2,3}\s*["'](?:admin|owner|staff)["']|\b(?:jwtDecode|jwt_decode)\s*[<(]/g,
    signal: 'low',
    triage:
      'Hiding UI by role is fine. It becomes a lead when it implies the server may trust the client: follow one privileged request and see whether anything but the client check protects it. Server behaviour is usually outside the repo, so this often ends as needs_validation.',
  },

  // ---------------------------------------------------------------- network
  {
    id: 'NET-CLEARTEXT-URL',
    domain: 'network',
    title: 'Cleartext http:// or ws:// endpoint',
    masvs: ['MASVS-NETWORK-1'],
    files: (p) => FILE_CLASSES.jsAndConfig(p) || /\.(java|kt|swift|m|mm)$/.test(p),
    re: /\b(?:http|ws):\/\/(?!localhost\b|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0|10\.\d|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|\[::1\]|www\.w3\.org|schemas\.|www\.apple\.com\/DTDs|ns\.adobe\.com|json-schema\.org|example\.(?:com|org)|[A-Za-z0-9.-]*\.local\b|\$\{|["'`])[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}[^\s"'`)]*/g,
    signal: 'medium',
    triage:
      'Is it requested by the release app, and does the platform allow it (Android cleartext policy, iOS ATS)? A cleartext URL that both platforms would block is dead code, not a finding.',
  },
  {
    id: 'NET-TLS-VALIDATION-DISABLED',
    domain: 'network',
    title: 'TLS certificate validation switched off',
    masvs: ['MASVS-NETWORK-1'],
    files: (p) => FILE_CLASSES.js(p) || FILE_CLASSES.androidCode(p) || FILE_CLASSES.iosCode(p),
    re: /\brejectUnauthorized\s*:\s*false\b|\btrusty\s*:\s*true\b|\bdisableAllSecurity\s*:\s*true\b|NODE_TLS_REJECT_UNAUTHORIZED|ALLOW_ALL_HOSTNAME_VERIFIER|\ballowsAnyHTTPSCertificate|\ballowInvalidCertificates\s*=\s*(?:YES|true)|\bvalidatesDomainName\s*=\s*(?:NO|false)|\bcontinueWithoutCredentialForAuthenticationChallenge\b/g,
    signal: 'high',
    triage:
      'Confirm it is compiled into the release variant and applies to app traffic (rejectUnauthorized in a Node script or Metro config is not app code).',
  },
  {
    id: 'NET-CUSTOM-TRUST-ANDROID',
    domain: 'network',
    title: 'Custom Android trust manager / hostname verifier / WebView SSL handler',
    masvs: ['MASVS-NETWORK-1'],
    files: 'androidCode',
    re: /^(?![ \t]*import\b).*\b(?:X509TrustManager|HostnameVerifier|checkServerTrusted|onReceivedSslError|setHostnameVerifier|OkHttpClientFactory)\b/gm,
    oncePerFile: true,
    signal: 'medium',
    triage: 'Read the implementation: an empty checkServerTrusted, `return true` verifier or `handler.proceed()` accepts any certificate. Check which build variant registers it.',
  },
  {
    id: 'NET-CUSTOM-TRUST-IOS',
    domain: 'network',
    title: 'Custom iOS authentication-challenge handling',
    masvs: ['MASVS-NETWORK-1'],
    files: 'iosCode',
    re: /\bdidReceiveChallenge\b|\bdidReceive\s+challenge\b|URLCredential\(\s*trust\s*:|\bcredentialForTrust\b/g,
    oncePerFile: true,
    signal: 'medium',
    triage: 'Accepting the server trust without evaluating it disables TLS validation. Pinning code looks similar, so read what happens before the credential is returned.',
  },
  {
    id: 'NET-SECRET-IN-QUERY-STRING',
    domain: 'network',
    title: 'Credential placed in a URL query string',
    masvs: ['MASVS-NETWORK-1', 'MASVS-STORAGE-2'],
    files: 'js',
    re: /[?&](?:access_?token|id_?token|refresh_?token|token|api_?key|apikey|password|secret|session_?id)=(?:\$\{|["'`]\s*\+)/gi,
    signal: 'medium',
    triage: 'URLs end up in server logs, proxies, analytics and Referer headers. Check what the token can do and how long it lives.',
  },

  // --------------------------------------------------------------- platform
  {
    id: 'PLT-DEEPLINK-HANDLER',
    domain: 'platform',
    title: 'Deep link / incoming URL handler',
    masvs: ['MASVS-PLATFORM-1', 'MASVS-CODE-4'],
    files: 'js',
    re: /\bLinking\.(?:addEventListener|getInitialURL|parse|useURL|useLinkingURL)\s*\(|\buse(?:URL|LinkingURL)\s*\(/g,
    signal: 'medium',
    triage:
      'Everything in an incoming URL is chosen by whoever sent the link: a web page, another app, a QR code. Follow each parameter to where it is used (navigation target, WebView source, API call, token exchange).',
  },
  {
    id: 'PLT-NAVIGATION-LINKING-CONFIG',
    domain: 'platform',
    title: 'React Navigation linking configuration',
    masvs: ['MASVS-PLATFORM-1'],
    files: 'js',
    re: /\bprefixes\s*:\s*\[|\bgetStateFromPath\b/g,
    signal: 'medium',
    triage: 'Every screen listed in the linking config can be opened from outside with attacker-chosen params. List them and look for screens that act on params without asking the user.',
  },
  {
    id: 'PLT-ROUTE-PARAMS',
    domain: 'platform',
    title: 'Route params read in an expo-router screen',
    masvs: ['MASVS-PLATFORM-1', 'MASVS-CODE-4'],
    files: 'js',
    re: /\buse(?:Local|Global)SearchParams\s*[<(]/g,
    signal: 'low',
    triage: 'With expo-router every file under app/ is deep-linkable by default, so these params are external input. Check the ones that reach a WebView, a fetch URL, a redirect or a state-changing call.',
  },
  {
    id: 'PLT-OPEN-DYNAMIC-URL',
    domain: 'platform',
    title: 'Opening a non-literal URL',
    masvs: ['MASVS-PLATFORM-1', 'MASVS-CODE-4'],
    files: 'js',
    re: /\b(?:Linking\.openURL|WebBrowser\.openBrowserAsync|openBrowserAsync)\s*\(\s*(?!["'`])[A-Za-z_$]/g,
    signal: 'low',
    triage: 'If the URL can come from a deep link, push payload or server content, check for a scheme/host allowlist (intent:, file:, tel:, custom schemes of other apps).',
  },
  {
    id: 'PLT-WEBVIEW',
    domain: 'platform',
    title: 'WebView component',
    masvs: ['MASVS-PLATFORM-2'],
    files: 'js',
    re: /<WebView\b(?!>\s*\()/g,
    signal: 'medium',
    triage: 'For each WebView answer: what can it load (fixed origin, or a URL from params/server)? what can the page ask native to do (onMessage)? what does native inject into it (tokens)? See references/platform-entry-points.md.',
  },
  {
    id: 'PLT-WEBVIEW-ANY-ORIGIN',
    domain: 'platform',
    title: 'WebView originWhitelist allows every origin',
    masvs: ['MASVS-PLATFORM-2'],
    files: 'js',
    re: /\boriginWhitelist\s*=\s*\{\s*\[\s*["']\*["']/g,
    signal: 'high',
    triage: 'This also allows javascript:, file: and custom-scheme navigations inside the WebView. Real when the content or a navigation can be influenced from outside.',
  },
  {
    id: 'PLT-WEBVIEW-BRIDGE',
    domain: 'platform',
    title: 'WebView-to-native message bridge or script injection',
    masvs: ['MASVS-PLATFORM-2'],
    files: 'js',
    re: /\bonMessage\s*=\s*\{|\binjectJavaScript\s*\(|\binjectedJavaScript(?:BeforeContentLoaded)?\s*=\s*\{/g,
    signal: 'medium',
    triage:
      'onMessage receives messages from whatever page is currently loaded, including after a redirect or inside a frame. Check for an origin check on nativeEvent.url and for what each message type can trigger. For injected script, check for interpolated tokens or untrusted strings.',
  },
  {
    id: 'PLT-WEBVIEW-RISKY-PROPS',
    domain: 'platform',
    title: 'WebView file access, mixed content or debugging enabled',
    masvs: ['MASVS-PLATFORM-2'],
    files: 'js',
    re: /\b(?:allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs|allowFileAccess|webviewDebuggingEnabled)\b(?!\s*=\s*\{\s*false)|\bmixedContentMode\s*=\s*["']always["']/g,
    signal: 'medium',
    triage: 'Hardening unless untrusted content can actually reach this WebView; then it widens what that content can read.',
  },
  {
    id: 'PLT-HTML-OR-CODE-INJECTION',
    domain: 'platform',
    title: 'Dynamic HTML or dynamic code execution',
    masvs: ['MASVS-CODE-4'],
    files: 'js',
    re: /\bdangerouslySetInnerHTML\b|\bsource\s*=\s*\{\{\s*html\s*:\s*(?!["'`]<)|\beval\s*\(|\bnew\s+Function\s*\(/g,
    signal: 'medium',
    triage: 'Where does the string come from? Server- or user-supplied HTML rendered in a WebView that also has a native bridge is script injection into that bridge.',
  },
  {
    id: 'PLT-ANDROID-EXPORTED-COMPONENT',
    domain: 'platform',
    title: 'Exported Android component',
    masvs: ['MASVS-PLATFORM-1'],
    files: 'manifest',
    re: /android:exported\s*=\s*"true"/g,
    signal: 'low',
    triage: 'MainActivity must be exported. Look at the others: services, receivers and providers exported without a signature-level permission can be driven by any installed app.',
  },
  {
    id: 'PLT-ANDROID-DEEPLINK-FILTER',
    domain: 'platform',
    title: 'Android deep link intent filter',
    masvs: ['MASVS-PLATFORM-1'],
    files: 'manifest',
    re: /<data\b[^>]*android:scheme\s*=\s*"[^"]+"[^>]*>/g,
    signal: 'low',
    triage: 'Custom schemes can be claimed by any app. https links are only bound to this app when the filter has android:autoVerify="true" and the domain serves assetlinks.json.',
  },
  {
    id: 'PLT-ANDROID-BACKUP-ENABLED',
    domain: 'platform',
    title: 'Android app data backup allowed',
    masvs: ['MASVS-STORAGE-2'],
    files: 'manifest',
    re: /android:allowBackup\s*=\s*"true"/g,
    signal: 'medium',
    triage: 'Only matters together with what the app stores unencrypted. Check for dataExtractionRules / fullBackupContent exclusions before rating it.',
  },
  {
    id: 'PLT-ANDROID-DEBUGGABLE',
    domain: 'platform',
    title: 'android:debuggable set in a manifest',
    masvs: ['MASVS-RESILIENCE-4'],
    files: 'manifest',
    re: /android:debuggable\s*=\s*"true"/g,
    signal: 'high',
    triage: 'Real only in the main or release manifest. Gradle sets this per build type, so an explicit true in src/main is the problem case.',
  },
  {
    id: 'PLT-ANDROID-CLEARTEXT-ALLOWED',
    domain: 'platform',
    title: 'Android cleartext traffic permitted',
    masvs: ['MASVS-NETWORK-1'],
    files: 'androidXml',
    re: /android:usesCleartextTraffic\s*=\s*"true"|cleartextTrafficPermitted\s*=\s*"true"/g,
    signal: 'medium',
    triage: 'Expected in src/debug (Metro). In src/main it is a permission, not a flaw: pair it with an actual cleartext request before calling it a finding.',
  },
  {
    id: 'PLT-ANDROID-USER-CA-TRUSTED',
    domain: 'platform',
    title: 'Network security config trusts user-installed CAs',
    masvs: ['MASVS-NETWORK-1'],
    files: 'androidXml',
    re: /<certificates\s+src\s*=\s*"user"/g,
    signal: 'medium',
    triage: 'Fine inside <debug-overrides>. In <base-config> or a <domain-config> it lets any CA the user was talked into installing intercept traffic.',
  },
  {
    id: 'PLT-ANDROID-RELEASE-SIGNED-WITH-DEBUG-KEY',
    domain: 'platform',
    title: 'Release build type signed with the debug keystore',
    masvs: ['MASVS-RESILIENCE-2'],
    files: 'gradle',
    re: /\brelease\s*\{[^}]*signingConfig\s*=?\s*signingConfigs\.debug\b/g,
    signal: 'medium',
    triage: 'This is the React Native template default with a "generate your own keystore" comment. It matters if release artifacts are really produced this way: the debug keystore is public. Check CI / EAS / fastlane for the real signing path before rating.',
  },
  {
    id: 'PLT-ANDROID-WEBVIEW-DEBUGGING',
    domain: 'platform',
    title: 'WebView remote debugging enabled in native code',
    masvs: ['MASVS-RESILIENCE-4'],
    files: 'androidCode',
    re: /setWebContentsDebuggingEnabled\s*\(\s*true\s*\)/g,
    signal: 'medium',
    triage: 'Check whether it is guarded by BuildConfig.DEBUG.',
  },
  {
    id: 'PLT-ANDROID-FILEPROVIDER-BROAD',
    domain: 'platform',
    title: 'FileProvider exposes a broad path',
    masvs: ['MASVS-PLATFORM-1'],
    files: 'androidXml',
    re: /<root-path\b[^>]*>|<(?:external-path|files-path|cache-path)\b[^>]*path\s*=\s*"(?:\.|\/)?"[^>]*>/g,
    signal: 'medium',
    triage: 'A grant on a URI from this provider can reach everything under the path. Real when the app hands out URIs built from external input.',
  },
  {
    id: 'PLT-IOS-ATS-DISABLED',
    domain: 'platform',
    title: 'App Transport Security exception',
    masvs: ['MASVS-NETWORK-1'],
    files: (p) => FILE_CLASSES.plist(p) || FILE_CLASSES.appConfig(p),
    re: /<key>(NSAllowsArbitraryLoads(?:InWebContent|ForMedia)?|NSExceptionAllowsInsecureHTTPLoads)<\/key>\s*<true\s*\/>|["']?NSAllowsArbitraryLoads(?:InWebContent)?["']?\s*:\s*true/g,
    signal: 'medium',
    triage: 'NSAllowsLocalNetworking and a localhost exception are the template defaults and fine. A global NSAllowsArbitraryLoads permits cleartext everywhere: pair it with real cleartext traffic to rate it.',
  },
  {
    id: 'PLT-IOS-URL-SCHEME',
    domain: 'platform',
    title: 'iOS custom URL scheme registered',
    masvs: ['MASVS-PLATFORM-1'],
    files: 'plist',
    re: /<key>CFBundleURLSchemes<\/key>\s*<array>[\s\S]{0,400}?<\/array>/g,
    signal: 'low',
    triage: 'iOS does not guarantee which app receives a custom scheme. Sensitive callbacks (OAuth, magic links, payments) should use Universal Links or be bound with PKCE/state.',
  },
  {
    id: 'PLT-IOS-DOCUMENTS-EXPOSED',
    domain: 'platform',
    title: 'iOS Documents directory exposed to Files/Finder',
    masvs: ['MASVS-STORAGE-2'],
    files: 'plist',
    re: /<key>(?:UIFileSharingEnabled|LSSupportsOpeningDocumentsInPlace)<\/key>\s*<true\s*\/>/g,
    signal: 'medium',
    triage: 'Anything the app writes to Documents becomes user-visible and exportable. Check what lives there (databases, exports, logs).',
  },

  // ----------------------------------------------------------- supply chain
  {
    id: 'SUP-INSTALL-SCRIPT',
    domain: 'supply-chain',
    title: 'Lifecycle install script in package.json',
    masvs: ['MASVS-CODE-3'],
    files: 'packageJson',
    re: /"(?:preinstall|install|postinstall|prepare)"\s*:\s*"[^"]*"/g,
    signal: 'low',
    triage: 'Usually patch-package or pod install. Read what it runs; anything that downloads and executes is worth a note.',
  },
  {
    id: 'SUP-NON-REGISTRY-DEPENDENCY',
    domain: 'supply-chain',
    title: 'Dependency installed from git, URL or tarball',
    masvs: ['MASVS-CODE-3'],
    files: 'packageJson',
    re: /"[@\w./-]+"\s*:\s*"(?:git\+|git:|github:|https?:|[\w-]+\/[\w.-]+#)[^"]*"/g,
    signal: 'medium',
    triage: 'Not pinned by registry integrity. Is it pinned to a commit hash, and who controls the source?',
  },
  {
    id: 'SUP-OTA-UPDATE',
    domain: 'supply-chain',
    title: 'Over-the-air JavaScript update mechanism',
    masvs: ['MASVS-CODE-3', 'MASVS-RESILIENCE-2'],
    files: (p) => FILE_CLASSES.js(p) || FILE_CLASSES.androidCode(p) || FILE_CLASSES.iosCode(p),
    re: /\bcodePush\s*\(|\bCodePush\.sync\s*\(|\bUpdates\.fetchUpdateAsync\s*\(|\bgetJSBundleFile\b|\bsetJSBundleFile\b|\bloadScriptFromFile\b/g,
    signal: 'medium',
    triage: 'An OTA channel is remote code execution by design. Who can publish, is the update signed (expo-updates code signing), and is the transport https? A hand-rolled bundle downloader deserves a full read.',
  },
  {
    id: 'SUP-EAS-INLINE-ENV',
    domain: 'supply-chain',
    title: 'Environment values committed in eas.json',
    masvs: ['MASVS-AUTH-1'],
    files: 'easJson',
    re: /"env"\s*:\s*\{[^}]*\}/g,
    signal: 'medium',
    triage: 'eas.json is committed. Plain config is fine; credentials belong in EAS environment variables/secrets.',
  },
  {
    id: 'SUP-OPEN-BACKEND-RULES',
    domain: 'supply-chain',
    title: 'Backend security rules that allow everyone',
    masvs: ['MASVS-AUTH-1'],
    files: 'backendRules',
    re: /allow\s+[a-z, ]*(?:read|write)[a-z, ]*:\s*if\s+true\b|"\.(?:read|write)"\s*:\s*(?:true|"true")/g,
    signal: 'high',
    triage: 'If these rules are the ones deployed, the data is open to anyone with the (public) project config. Deployment state is outside the repo, so confirm with the owner.',
  },

  // ---------------------------------------------------------------- privacy
  {
    id: 'PRV-SENSITIVE-PERMISSION',
    domain: 'privacy',
    title: 'Sensitive Android permission requested',
    masvs: ['MASVS-PRIVACY-1'],
    files: 'manifest',
    re: /android\.permission\.(?:CAMERA|READ_CONTACTS|WRITE_CONTACTS|ACCESS_FINE_LOCATION|ACCESS_BACKGROUND_LOCATION|READ_SMS|RECEIVE_SMS|SEND_SMS|RECORD_AUDIO|READ_CALL_LOG|READ_PHONE_STATE|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|MANAGE_EXTERNAL_STORAGE|QUERY_ALL_PACKAGES|SYSTEM_ALERT_WINDOW|REQUEST_INSTALL_PACKAGES)\b/g,
    signal: 'low',
    triage: 'A permission is a privacy note, not a vulnerability. Check that a feature uses it; libraries often add permissions the app never needs.',
  },
  {
    id: 'PRV-USER-DATA-TO-THIRD-PARTY',
    domain: 'privacy',
    title: 'User identity or event data sent to an analytics/crash SDK',
    masvs: ['MASVS-PRIVACY-1'],
    files: 'js',
    re: /\b(?:Sentry\.setUser|analytics\(\)\.setUserProperties?|\.identify|mixpanel\.people\.set|posthog\.identify|crashlytics\(\)\.setAttributes?|Bugsnag\.setUser)\s*\(/g,
    signal: 'low',
    triage: 'What fields are sent (email, phone, precise location, health or payment data)? Does a token or full API response ride along in breadcrumbs or extra data?',
  },
];

// Files worth knowing about regardless of content.
export const SENSITIVE_FILE_KINDS = [
  { kind: 'env-file', test: (p) => isEnvFile(p) && !/\.(example|sample|template|dist|defaults)$/.test(p), note: 'If tracked, its values are exposed to everyone with repo access. Any value that app JS reads ships in the bundle either way.' },
  { kind: 'android-keystore', test: (p) => /\.(keystore|jks)$/.test(p) && base(p) !== 'debug.keystore', note: 'Release/upload keystore. Should not be in the repository.' },
  { kind: 'signing-certificate', test: (p) => /\.(p12|pfx|p8|mobileprovision)$/.test(p), note: 'Apple signing or API key material.' },
  { kind: 'pem-file', test: (p) => /\.(pem|key)$/.test(p), note: 'May hold a private key. A certificate used for pinning or expo-updates code signing is public and fine.' },
  { kind: 'firebase-config', test: (p) => /^(google-services\.json|GoogleService-Info\.plist)$/.test(base(p)), note: 'Public client config by design. The security question is the backend rules and API key restrictions.' },
  { kind: 'sentry-properties', test: (p) => base(p) === 'sentry.properties', note: 'Holds an auth token when `auth.token` is set.' },
  { kind: 'npmrc', test: (p) => base(p) === '.npmrc', note: 'May hold a registry auth token.' },
  { kind: 'prebuilt-js-bundle', test: (p) => /(\.jsbundle|index\.android\.bundle|\.hbc)$/.test(p), note: 'Committed bundle: stale code can ship, and secrets inside it are not covered by a source scan.' },
  { kind: 'source-map', test: (p) => /\.(bundle|jsbundle|js)\.map$/.test(p), note: 'Source maps reveal original source if they ship inside the app or are served publicly.' },
  { kind: 'eas-credentials', test: (p) => base(p) === 'credentials.json', note: 'EAS local credentials file: keystore and certificate passwords.' },
];
