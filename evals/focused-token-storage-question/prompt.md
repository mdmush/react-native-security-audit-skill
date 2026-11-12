---
tags: [rn-security-audit]
max_turns: 60
timeout_seconds: 1500
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

quick q - our react native app (food delivery, expo SDK 52) keeps the access + refresh token in a redux-persist slice backed by AsyncStorage. a contractor flagged it as a 'critical vulnerability' in a review. is that right or is it fine since the app sandbox is private anyway? refresh tokens last 60 days
