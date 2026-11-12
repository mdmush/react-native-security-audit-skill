---
type: llm
focus: trace
weight: 1
---

The trust-all OkHttp client in StagingHttpClientFactory.kt, registered unconditionally in MainApplication.kt, is reported as a confirmed finding about disabled TLS certificate validation in release builds.
