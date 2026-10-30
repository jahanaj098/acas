# ACAS - Authorization Consistency Testing Extension

ACAS is a Burp Suite extension for multi-user authenticated authorization testing
(BOLA/IDOR, privilege escalation, parameter tampering). It captures traffic per
actor, replays mutated variants across actors, and exports evidence for the
Hermes testing agent.

## Build

- Java 21, Maven
- Build the fat JAR: `mvn package`
- Output: `target/ACASTOOL.jar`
- Load in Burp: Extensions -> Installed -> Add -> Java -> select the JAR

The repackaged Maven cache and toolchain under `hardening/` are local-only and
must not be committed.

## Architecture

```
src/main/java/com/acas/
  AcasExtension.java     Burp entry point (BurpExtender)
  engine/                capture, replay, mutation, comparison, classification
  export/                Hermes export, schemas, encryption, delivery
  harvest/               ID/resource discovery
  model/                 domain records
  store/                 persistence and workspace validation
  ui/                    Swing panels and dialogs
  util/                  HTTP, diffing, credential policy, reporting
src/main/resources/schemas/   JSON schemas for Hermes payloads
demo/                    synthetic fixtures (fake credentials, simulated responses)
```

## Conventions

- Never commit live credentials, cookies, tokens, webhook URLs or bot tokens.
- Demo fixtures use only `demo_*` values and `*.example.test` hosts.
- Keep exported evidence immutable; credential updates are separate revisions.
- Match existing style: no comments unless they explain non-obvious intent.

## Testing

- `mvn test` (surefire)
- Offline fixtures live under `demo/` and schema validation under `src/test`
  when present.
