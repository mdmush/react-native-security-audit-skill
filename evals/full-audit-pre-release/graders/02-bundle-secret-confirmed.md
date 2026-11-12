---
type: llm
focus: trace
weight: 1
---

The PAYMENTS_API_SECRET in src/config/keys.ts, used by src/api/payments.ts, is reported as a confirmed finding rated high or critical, and the stated fix is to move the PayBridge calls behind a backend and rotate the key, not to move the value into an environment variable.
