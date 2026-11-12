---
tags: [rn-security-audit]
max_turns: 60
timeout_seconds: 1500
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

Someone on the team said anything with EXPO_PUBLIC_ in it is visible to users. Can you check whether any of the keys in this Expo app are actually a problem? I don't need a formal report, just tell me what to fix.

Input files: package.json, app.json, .env, lib
