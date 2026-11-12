# react-native-security-audit

An [Agent Skill](https://agentskills.io) that turns a coding agent into a security auditor for React Native and Expo apps. It covers the JavaScript/TypeScript code and the native Android and iOS projects, and it is built around one rule: **a pattern match is a lead, not a finding.**

Most automated mobile "audits" are a wall of grep hits: every `AsyncStorage` call, every string containing `key`, every missing best practice, each stamped HIGH. This skill does the opposite. A finding is reported only when the agent can name who the attacker is, show how they reach the code in the build that ships, and state what they get. Everything else is filed honestly as a lead that needs the owner's validation, a hardening note, or a dismissed false positive.

## What you get

- **A workflow with an evidence bar.** Reconnaissance, a hunt across nine domains, an explicit attempt to refute each candidate, then structured records and a report.
- **React Native specifics that generic security skills miss.** The bundle is public, so `EXPO_PUBLIC_*` and `react-native-config` values are not secrets and an env var is not a fix. Firebase config, publishable keys and Supabase anon keys are public identifiers, not leaks. Debug manifests and `__DEV__` branches do not ship. Deep link → WebView → session token chains. OAuth without PKCE on a custom scheme. Expo projects whose native config is generated rather than committed.
- **A read-only scanner** (`scripts/scan.mjs`): zero dependencies, never executes project code, never touches the network, and masks every secret it prints. It profiles the project and emits leads, each with a note on what decides whether it is real.
- **Three honest verdicts.** `confirmed` (rated by impact), `needs_validation` (a specific fact outside the repo decides it; never rated), `rejected` (recorded so it is not rediscovered). Hardening notes are kept separate.
- **A validated report.** `findings.json` is checked by `scripts/validate-findings.mjs`: every cited file and line must exist, all nine domains must be accounted for, only confirmed findings carry a severity, and no unredacted credential may appear. `REPORT.md` is then rendered from the records, so the prose cannot disagree with the data.
- **OWASP MASVS v2 mapping** for every finding, plus a Mobile Top 10 (2024) cross-reference.
- **Fix patterns with code** for the common findings (backend proxy for bundled secrets, Keychain/Keystore storage, biometric-bound secrets, deep-link and WebView validation, PKCE, pinning, attestation), used when you ask how to fix something or ask the agent to apply fixes.
- **Safe by default.** The agent reads source; it does not build the app, install dependencies, call your backend, or test whether a discovered key works.

## Install

The skill follows the open Agent Skills format (`SKILL.md` plus `references/`, `scripts/` and `assets/`), so it works in any agent that supports skills. The only runtime requirement is Node.js 18+, which every React Native toolchain already has.

### Claude Code

**As a plugin (recommended).** This repository is also a Claude Code plugin marketplace. Inside Claude Code:

```text
/plugin marketplace add mdmush/react-native-security-audit-skill
/plugin install rn-security-audit@react-native-security-audit-skill
```

Or from your shell:

```bash
claude plugin marketplace add mdmush/react-native-security-audit-skill
claude plugin install rn-security-audit@react-native-security-audit-skill
```

Updates arrive through the marketplace. The skill is then available as `/rn-security-audit:react-native-security-audit`, and Claude loads it automatically when you ask for a security audit of a React Native or Expo app.

**As a plain skill.** If you prefer a file you can see and edit:

```bash
# this project only -> .claude/skills/react-native-security-audit/
npx skills add mdmush/react-native-security-audit-skill --skill react-native-security-audit -a claude-code

# all your projects -> ~/.claude/skills/react-native-security-audit/
npx skills add mdmush/react-native-security-audit-skill --skill react-native-security-audit -a claude-code -g
```

or without any installer:

```bash
git clone https://github.com/mdmush/react-native-security-audit-skill.git
mkdir -p ~/.claude/skills
cp -R react-native-security-audit-skill/skills/react-native-security-audit ~/.claude/skills/
```

Installed this way it is invoked as `/react-native-security-audit`. Commit `.claude/skills/react-native-security-audit/` to share it with your team.

**Try it without installing:** `claude --plugin-dir /path/to/react-native-security-audit-skill`.

Claude Code notes:

- In a full audit the skill uses sub-agents when they are available: one per domain for the hunt, and a fresh one to try to disprove each candidate finding. It works without them, just sequentially.
- The first run asks permission to execute the bundled Node scripts. They only read the project and write to the output directory you chose.

### Other coding agents

The [Skills CLI](https://skills.sh) installs into the right directory for each agent. Pick yours with `-a`, add `-g` for a user-level install, or omit `-a` to choose interactively:

```bash
npx skills add mdmush/react-native-security-audit-skill --skill react-native-security-audit -a <agent>
```

| Agent | `-a` value | Project location | User location (`-g`) |
|---|---|---|---|
| OpenAI Codex | `codex` | `.agents/skills/` | `~/.agents/skills/` |
| Cursor | `cursor` | `.agents/skills/` | `~/.cursor/skills/` |
| Gemini CLI | `gemini-cli` | `.agents/skills/` | `~/.gemini/skills/` |
| GitHub Copilot | `github-copilot` | `.agents/skills/` | `~/.copilot/skills/` |
| OpenCode | `opencode` | `.agents/skills/` | `~/.config/opencode/skills/` |
| Windsurf | `windsurf` | `.windsurf/skills/` | `~/.codeium/windsurf/skills/` |
| Cline | `cline` | `.agents/skills/` | `~/.agents/skills/` |
| Roo Code | `roo` | `.roo/skills/` | `~/.roo/skills/` |
| Amp | `amp` | `.agents/skills/` | `~/.config/agents/skills/` |
| Goose | `goose` | `.goose/skills/` | `~/.config/goose/skills/` |
| Kiro | `kiro-cli` | `.kiro/skills/` | `~/.kiro/skills/` |

These locations are the ones the Skills CLI used at the time of writing; the CLI is the source of truth and supports many more agents (`npx skills add --help`).

**Manual install for any of them.** Copy the skill folder into the agent's skills directory. `.agents/skills/` is the shared convention most agents read, so one copy usually serves several tools:

```bash
git clone https://github.com/mdmush/react-native-security-audit-skill.git
mkdir -p .agents/skills
cp -R react-native-security-audit-skill/skills/react-native-security-audit .agents/skills/
```

Keep the folder name `react-native-security-audit`: the specification requires it to match the skill's `name`.

**Agents without skill support.** Clone the repository anywhere and point the agent at the entry file from its rules file (`AGENTS.md`, `.cursorrules`, `CONVENTIONS.md`, or equivalent):

```markdown
For security audits, security reviews, or security questions about this
React Native / Expo app, read and follow
/absolute/path/to/react-native-security-audit-skill/skills/react-native-security-audit/SKILL.md
before answering. Its reference files and scripts are in the same directory.
```

The skill avoids agent-specific tool names and treats sub-agents as optional, so it degrades cleanly on simpler agents.

## Use

Open your agent in the app's repository and ask in plain language. The skill picks a mode from the request.

**Full audit** (runs the whole workflow and writes artifacts):

```text
Do a full security audit of this app before we ship 3.4.0
Pen-test the codebase and give me a report, output to ~/audits/shopmate
Audit just the android/ project and the deep link handling    <- scoped audit
```

**Focused guidance** (answers in the conversation, writes nothing):

```text
Is it OK to keep our refresh token in redux-persist?
Are any of these EXPO_PUBLIC_ keys a problem?
Review this PR for security impact
Is this WebView onMessage handler safe?
How should I fix the token storage finding?
```

A full audit writes to the directory you name, or by default to `~/rn-security-audits/<project>/<date>-<n>/`, outside the repository so that a document describing how to attack your app is not committed by accident:

| File | Content |
|---|---|
| `leads.json` | Raw scanner output: project profile and every lead |
| `findings.json` | The audit record: run facts, coverage, confirmed / needs-validation / rejected findings, hardening notes |
| `REPORT.md` | The human-readable report rendered from `findings.json` |

## How it works

```text
0 Setup      target, commit, output directory, scope
1 Recon      scan.mjs -> profile + leads; sketch the attack surface
2 Hunt       nine domains, each with its reference file
3 Refute     try to disprove every candidate (a fresh sub-agent where available)
4 Record     findings.json -> validate-findings.mjs
5 Report     render-report.mjs -> REPORT.md
```

**Domains:** secrets, storage, crypto, auth, network, platform (deep links, WebViews, native config), supply chain, privacy, resilience.

**Every finding names one attacker**, and the attacker drives the severity:

| Attacker | Starting capability |
|---|---|
| `binary-holder` | Downloads the app and unpacks it |
| `remote-content` | Gets the victim to open a link, scan a code, or view a page in a WebView |
| `local-app` | Another app on the same device |
| `network` | On the path between device and server |
| `device-access` | Has the device or its backups |
| `compromised-device` | Rooted or instrumented device, including its own user |
| `backend-peer` | Another logged-in user of the same backend |
| `supply-chain` | Controls a dependency, build step or update channel, or can read the repo |

**Severity** is assigned only to confirmed findings and only by demonstrated impact. A backend secret that every user can extract is critical. A one-tap session theft through a deep link is high. Plaintext tokens recoverable from a backup are medium. A value in the device log is low. No certificate pinning in an ordinary app is a hardening note, not a finding.

## Repository layout

```text
skills/react-native-security-audit/
├── SKILL.md                      modes, ground rules, workflow, severity anchors
├── references/                   loaded on demand, one topic each
│   ├── threat-model.md
│   ├── secrets-and-config.md     secret vs public identifier, and fixes that work
│   ├── data-storage-and-crypto.md
│   ├── network-and-auth.md
│   ├── platform-entry-points.md  deep links, WebViews, bridges
│   ├── android.md
│   ├── ios.md
│   ├── expo.md
│   ├── supply-chain-and-release.md
│   ├── validation-and-reporting.md
│   ├── masvs-mapping.md          MASVS v2, Mobile Top 10, pre-release questions
│   └── remediation.md            fix patterns with code
├── scripts/
│   ├── scan.mjs                  read-only recon scanner
│   ├── validate-findings.mjs     contract + evidence checks
│   ├── render-report.mjs         findings.json -> REPORT.md
│   └── lib/                      rules, secret patterns, contract
└── assets/
    ├── findings.schema.json
    └── findings.example.json
.claude-plugin/                   Claude Code plugin + marketplace manifests
evals/                            test cases with fixture apps and graders
tests/                            node:test suites for scripts and skill structure
```

`SKILL.md` stays under 200 lines; detail lives in the reference files, which the agent reads only when a domain calls for them.

## Using the scripts on their own

They are ordinary Node programs and are useful without an agent, for example in CI:

```bash
S=skills/react-native-security-audit/scripts

node $S/scan.mjs path/to/app                       # human-readable leads
node $S/scan.mjs path/to/app --json                # machine-readable
node $S/scan.mjs path/to/app --out leads.json --max-per-rule 20

node $S/validate-findings.mjs findings.json --target path/to/app
node $S/render-report.mjs findings.json --target path/to/app --out REPORT.md
```

The scanner always exits 0 when it runs: leads are not failures. The validator exits 1 on an invalid file.

## Limits

- This is a **source audit**. It does not replace dynamic testing of a built binary (MASTG test cases, Frida, a proxy), a backend penetration test, or a review of provider-console settings. The report says so and lists what it could not see.
- Server-side authorization is almost never in a mobile repository. The skill reports those questions as `needs_validation` with the exact endpoint and check to confirm, rather than guessing.
- One pass does not exhaust a codebase. Re-run before each release and after significant changes.
- Scanner rules are deliberately conservative heuristics. The real findings come from the agent reading code with the reference files, not from the patterns.

## Development

```bash
npm test                         # scripts, contract, and skill-structure checks (no dependencies)
claude plugin validate .         # Claude Code plugin + marketplace manifests
claude plugin eval . --scaffold --allow-tools Write,Edit,Bash   # run evals/ with and without the skill (billed model runs)
```

`tests/skill.test.mjs` enforces the Agent Skills specification and the conventions this repository relies on: name matches directory, description within 1024 characters, only portable frontmatter fields, `SKILL.md` under 500 lines, every link resolves, every reference is reachable from `SKILL.md`, and no provider-format credential is committed anywhere in the skill or the fixtures.

`evals/` holds three cases: a full audit of a fixture app with planted vulnerabilities and decoys, a focused question that must not trigger the full workflow, and an Expo key review that must tell a real secret from public identifiers. The fixture credentials are invented formats, not real provider keys.

Contributions are welcome, particularly new scanner rules with a triage line and a test, and corrections to the reference files as React Native, Expo and the platforms change.

## Acknowledgements

- [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT) for the methodology this skill adapts to mobile: guidance versus full-audit modes, the confirmed / needs-validation / rejected verdicts, severity from demonstrated impact, independent verification, and validated structured output.
- The `rn-security-audit` skill from [johanruttens/handla-shopping-list](https://github.com/johanruttens/handla-shopping-list) for its React Native checklist coverage, which informed the scanner's rule set.
- The `react-native-security` skill from [maikotrindade/awesome-react-native-skills](https://github.com/maikotrindade/awesome-react-native-skills), a build-time hardening guide that was used as a coverage checklist for this audit skill's topics.
- [OWASP MAS](https://mas.owasp.org/) for MASVS and MASTG.

These were used for ideas and coverage only. The text here is original, and code samples follow each library's own documented API.

## License

[MIT](LICENSE)
