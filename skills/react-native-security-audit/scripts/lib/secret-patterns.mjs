// Shared secret detectors. Used by the scanner (to raise leads) and by the
// findings validator (to stop real credential values landing in a report).
//
// `public: true` marks formats that are identifiers by design: they ship in
// every client and are only a problem when the provider-side restrictions are
// missing. They are still surfaced so the restriction can be checked.

export const SECRET_PATTERNS = [
  {
    id: 'private-key',
    label: 'Private key block',
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
  },
  { id: 'aws-access-key', label: 'AWS access key id', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: 'stripe-secret', label: 'Stripe secret or restricted key', re: /\b[sr]k_live_[0-9A-Za-z]{16,}/g },
  {
    id: 'llm-api-key',
    label: 'LLM provider API key',
    re: /\bsk-(?:ant-|proj-|svcacct-|or-v1-)[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{40,}\b|\bgsk_[A-Za-z0-9]{40,}\b/g,
  },
  { id: 'github-token', label: 'GitHub token', re: /\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}/g },
  { id: 'slack-token', label: 'Slack token', re: /\bxox[abeprs]-[A-Za-z0-9-]{10,}/g },
  {
    id: 'slack-webhook',
    label: 'Slack incoming webhook',
    re: /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{16,}/g,
  },
  { id: 'sendgrid-key', label: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g },
  { id: 'supabase-secret', label: 'Supabase secret key', re: /\bsb_secret_[A-Za-z0-9_-]{10,}/g },
  { id: 'mapbox-secret', label: 'Mapbox secret token', re: /\bsk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/g },
  { id: 'sentry-auth-token', label: 'Sentry auth token', re: /\bsntry[su]_[A-Za-z0-9_=+/-]{20,}/g },
  { id: 'npm-token', label: 'npm access token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  {
    id: 'google-api-key',
    label: 'Google API key (Firebase, Maps)',
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    public: true,
  },
  {
    id: 'jwt',
    label: 'Hardcoded JWT',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    jwt: true,
  },
];

// Show enough of a value to find it again in the source, never enough to use it.
export function redact(value) {
  const v = String(value);
  if (v.length <= 8) return `[redacted:${v.length} chars]`;
  return `${v.slice(0, 4)}…[redacted:${v.length} chars]`;
}

// A JWT payload is not secret, and its claims decide what the token is: a
// Supabase `anon` token is a public identifier, a `service_role` token is not.
export function describeJwt(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    const facts = [];
    for (const key of ['role', 'iss', 'aud', 'scope']) {
      if (typeof payload[key] === 'string') facts.push(`${key}=${payload[key].slice(0, 40)}`);
    }
    if (typeof payload.exp === 'number') {
      facts.push(`exp=${new Date(payload.exp * 1000).toISOString().slice(0, 10)}`);
    }
    return facts.length ? facts.join(', ') : 'no role/iss/aud claims';
  } catch {
    return 'payload not decodable';
  }
}

// Used by the validator: any hit means a live-looking credential was written
// into an audit artifact.
export function findUnredactedSecrets(text) {
  const hits = [];
  for (const p of SECRET_PATTERNS) {
    if (p.public || p.jwt) continue;
    p.re.lastIndex = 0;
    const m = p.re.exec(text);
    if (m) hits.push({ id: p.id, label: p.label, preview: redact(m[0]) });
  }
  return hits;
}
