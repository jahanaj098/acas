# ACAS - Authorization Consistency Testing Extension

ACAS is a Burp Suite extension for multi-user authenticated authorization
testing. It captures traffic per actor, replays mutated variants across actors,
and reports BOLA/IDOR, privilege escalation and parameter-tampering findings.

## What it does

- Captures requests and responses for each saved actor using isolated sessions.
- Replays each captured request with another actor's credentials, anonymously,
  and with mutated identifiers.
- Compares responses with the owner baseline to classify owner, blocked,
  leaked or ambiguous results.
- Exports immutable evidence (requests, responses, probes, actor context) as
  versioned JSON for the Hermes testing agent, over Telegram, Discord or a
  local directory.

## Requirements

- Java 21
- Burp Suite with the Montoya API (2023.12.1 or newer)

## Build

```
mvn package
```

The fat JAR is written to `target/ACASTOOL.jar`. Load it in Burp via
**Extensions -> Installed -> Add -> Java**.

## Intended use

Authorized security testing only. Use it against applications you own or have
explicit written permission to test. Demo fixtures under `demo/` are synthetic:
all credentials are fake and all hosts use `*.example.test`.

## License

MIT. See [LICENSE](LICENSE).
