---
description: Compile and package the ACAS Burp extension
allowed-tools: Bash(mvn:*)
---

Build the extension and report the resulting artifact.

1. Run `mvn -q clean package`.
2. Confirm `target/ACASTOOL.jar` exists and print its size.
3. If compilation fails, show the first compiler error and stop.
