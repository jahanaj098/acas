---
description: Review a diff for credential leaks and unsafe evidence handling
allowed-tools: Bash(git diff:*), Grep, Read
---

Review the current diff for security problems specific to ACAS:

- Any real credential, cookie, bearer token, webhook URL or bot token added to
  source, fixtures or docs. Demo data must stay `demo_*` / `*.example.test`.
- Evidence records being mutated in place instead of versioned.
- Credentials written to logs, export history, or registry keys unhashed.
- Redirects followed with credentials attached; actors used outside their origin.
- New network calls that bypass `RateLimiter` or `ReplayGate`.

Report findings with `file:line` and a one-line fix. Do not change code.
