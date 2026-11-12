# Validation and reporting

Read this before recording any finding. It holds the refutation checklist, the rules for each verdict, and the record format the validator and report renderer expect.

## Contents

- Why validate
- The refutation checklist
- Verdict rules
- Writing a record
- findings.json shape
- Coverage
- The final message

## Why validate

A candidate feels true to the person who found it. Most wrong findings in mobile audits come from the same few mistakes: the setting was in the debug variant, the "secret" was a public identifier, the code is never reached, a control one file away already handles it, or the deciding fact is on a server nobody looked at. A wrong finding costs the owner real time and costs the audit its credibility, so every candidate gets an honest attempt at disproof before it is written down.

If your platform has sub-agents, the attempt should come from a fresh agent that did not find the candidate. Give it only: the candidate record, read access to the target, this file, and the relevant domain reference. Ask it to refute the claim and return a verdict with reasons. Without sub-agents, do it yourself as a distinct pass after hunting is finished, re-reading the source rather than your notes.

## The refutation checklist

Run every step for every candidate. Stop at the first step that kills it and record it as rejected with that reason.

1. **Re-read the evidence.** Open each cited file at each cited line. Does the code do what the candidate says? Are the line numbers right? Scanner excerpts are single lines; the surrounding lines often change the meaning (a guard, a comment-out, a different variable).
2. **Release variant.** Is this compiled into the release build? Rule out `src/debug`, `#if DEBUG`, `BuildConfig.DEBUG`, `__DEV__` branches, test and story files, example configs, dev-only dependencies, build tooling. For Expo managed projects, is the setting what the app config and plugins will actually generate?
3. **Reachability.** Is the code used? Follow imports and call sites from a real entry point: a registered screen, a mounted component, a registered native module, an intent filter. Dead code is not a finding. If you were given a partial tree (no entry file or navigator, missing screens), do not demote everything: assume the modules present are part of the app, confirm on that basis, and state the assumption once in `run.limitations` and in the evidence of the findings that depend on it.
4. **Attacker and entry.** Name one attacker class from the table in `SKILL.md`. Write the exact thing they control (this URL parameter, this file in a backup, this network position, read access to this repository) and how it reaches the vulnerable code.
5. **Existing controls.** Look for what already stops it: validation or allowlists earlier in the flow, an auth guard on the layout, an OS default (cleartext blocked, sandboxing, scheme verification), library defaults (PKCE on by default, `originWhitelist` default), a server-side check visible in the repo.
6. **Concrete effect.** State in one sentence what the attacker ends up with: a specific token, a specific action performed as the victim, specific data read. "Could lead to compromise" is not an effect. If you cannot write the sentence, it is a hardening note or nothing.
7. **Outside facts.** An unknown that could only make a confirmed finding worse (for example whether logged tokens are also sent to a crash service) stays inside that record, in the severity rationale, not in a separate record. List everything the claim assumes that the repository does not show: server behaviour, provider-console settings, deployed rules, the merged manifest, whether a key is live, which CI path builds the release. If any of them could remove the finding, it is `needs_validation`, not `confirmed`.
8. **Duplicates and chains.** Is this the same root cause as another candidate? Merge them. Is it one link of a chain? Report the chain once, at the severity of its end result.
9. **Severity sanity.** Apply the anchors in `SKILL.md`. Does the rating match the *demonstrated* effect and the attacker's real preconditions, not the worst imaginable case?

## Verdict rules

**`confirmed`** requires all of: a complete source-visible path from the attacker's entry to the effect; presence in the release variant; no unresolved outside fact that could remove it; a concrete effect. Static evidence is enough for a mobile source audit: you do not need to exploit it, and you must not test against live systems. A safe local check can strengthen it when the user has agreed to run project code (a unit-level harness around a URL parser, `expo config` output, inspecting a build artifact they provide).

Conditional wording is allowed where it is honest and still useful: "this secret is in the bundle of every build made from this source" is confirmed without knowing whether the key is still live; say that liveness is for the owner to check.

**`needs_validation`** requires: a real source location and a specific claimed weakness; a named blocker that is genuinely outside the repository; a validation plan the owner can carry out safely. Good blockers: "whether `POST /refunds` checks the caller's role server-side", "whether the Maps key is restricted to this bundle id", "whether release builds are signed by EAS or by the Gradle config in the repo". Bad blockers: "might be exploitable", "needs further review", anything you could resolve by reading more code. No severity. An optional `fix` may say what to do if it holds.

The plan describes what the owner should look at or a test against their own non-production environment with their own accounts. It never instructs anyone to attack a deployment.

**`rejected`** requires the reason it failed, specific enough that a later reader would not reopen it: "only in `src/debug/AndroidManifest.xml`", "Supabase anon key (JWT role=anon), public by design", "`Math.random` generates a list key".

**Hardening notes** are for good practice with no boundary crossing: no pinning, permissive-but-unused settings, missing backup exclusions with nothing sensitive stored, absent resilience controls. Keep them few and specific. They carry no severity; if you feel one deserves a rating, it is a finding and must pass the checklist.

## Writing a record

- **Title**: what is wrong and where, in plain words. "Payment provider secret key shipped in the app bundle", not "Hardcoded secret" or "MASVS-AUTH-1 violation".
- **Description**: the trace, in order, as a reader could follow it in the code: entry → propagation → effect. Two to five sentences.
- **Locations**: every file and line the reader needs, each with a short `note` ("deep-link route", "token injected into page", "release manifest"). Paths relative to the audited project root. Lines must exist; the validator checks.
- **Preconditions**: what must be true for the attack (victim taps a link, attacker on the same network, backup enabled). They justify the severity.
- **Impact**: the concrete effect from checklist step 6.
- **Severity rationale**: one or two sentences tying attacker, preconditions and impact to the anchor.
- **Evidence**: how it was established ("source trace across the three cited files; setting is in the main manifest, no flavor overrides in build.gradle").
- **Fix**: the smallest change that enforces the missing rule at the right place, specific to this codebase: which file, what to add or move. Say "rotate the key" first when a secret was exposed. Do not recommend generic hardening as the fix for a specific flaw, and do not recommend an environment variable for a bundled secret.
- **MASVS**: one to three controls from [masvs-mapping.md](masvs-mapping.md).
- **Secrets**: never quote a credential. First four characters plus length, as the scanner prints them.

Write for a developer who will fix it and a manager who will prioritise it. No exploit code, no step-by-step attack instructions against deployed systems.

## findings.json shape

The authoritative example is `assets/findings.example.json`; `assets/findings.schema.json` is the JSON Schema. In outline:

```json
{
  "schema": "rn-security-audit/1",
  "run": {
    "target": "project name, not an absolute path",
    "source_ref": "commit hash, plus (dirty) if the worktree had changes",
    "date": "YYYY-MM-DD",
    "mode": "full | scoped",
    "scope": ["paths, required when scoped"],
    "profile": { "framework": "...", "react_native": "...", "expo": "..." },
    "limitations": ["what could not be examined and why"]
  },
  "summary": "Two to four sentences on the overall posture and what to fix first.",
  "coverage": [{ "domain": "secrets", "status": "reviewed | not_applicable | not_reviewed", "note": "..." }],
  "findings": [],
  "hardening": [{ "title": "...", "note": "...", "masvs": [], "locations": [] }]
}
```

Fields per finding:

| Field | confirmed | needs_validation | rejected |
|---|---|---|---|
| `id` (`RN-001`...), `title`, `verdict`, `domain`, `locations` | required | required | required |
| `masvs`, `attacker`, `description` | required | required | optional |
| `preconditions` | optional | optional | optional |
| `impact`, `severity`, `severity_rationale`, `evidence`, `fix` | required | `severity` and `severity_rationale` forbidden; `fix` optional | `severity`, `severity_rationale`, `fix` forbidden |
| `blocker`, `validation_plan` | forbidden | required | forbidden |
| `reason` | forbidden | forbidden | required |

Number ids in the order findings will be read: confirmed by severity, then needs_validation, then rejected.

Run `scripts/validate-findings.mjs` with `--target`. Errors must be fixed. Warnings are calibration prompts (for example a `high` rating on a `compromised-device` attacker): re-read the anchor and either adjust or make sure the severity rationale explains the exception.

## Coverage

All nine domains appear exactly once in `coverage`:

- `reviewed`: the reference was read, the leads were followed, and the non-pattern checks were done. A `note` summarising what was looked at is useful but optional.
- `not_applicable`: with the reason ("no WebView, no deep-link configuration, no exported components").
- `not_reviewed`: with the reason (out of scope, native project not present, time). This makes the report say "partial coverage" at the top, which is the honest outcome.

Put everything that limited the audit in `run.limitations`: generated native projects not available, server code not in the repository, dependency audit not run because it needs network access, git history not examined, a partial source tree. The renderer always appends two standard lines (static review cannot see server behaviour or provider settings; one pass is not exhaustive), so do not repeat those.

When the target is not a git repository, set `run.source_ref` to "not a git repository" and treat files as part of the source as provided: a credential in such a tree is still reported, with "confirm whether this file is committed" as the open question if the rating depends on it.

## The final message

After rendering the report, tell the user in a few lines:

1. What to fix first, including anything that needs rotating today.
2. The confirmed findings, most severe first, one line each, and where `REPORT.md`, `findings.json` and `leads.json` are.
3. What needs their validation, and that those items are unrated leads.
4. What was not covered.

Do not paste the report. Do not soften a critical finding or inflate a quiet result: an audit that confirms nothing is a legitimate outcome, stated together with its coverage and limits.
