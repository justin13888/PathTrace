# REQ-CLI: command-line interface

### REQ-CLI-001: Command set
- status: met
- spec: §6.9, §7.6, §7.7, §7.8
- design: docs/design/cli.md
- evidence: EXP-0006-r7, EXP-0007-r8

`pathtrace` provides `keygen`, `serve`, `probe`, `merge`, `fetch`, `derive`, `doctor`, `trace check|info|dump|load|redact`, `import mahimahi` and `export mahimahi|netem`.

### REQ-CLI-002: Stable interface
- status: planned
- spec: new

From 1.0, commands and flags are stable. Removing one requires a deprecation warning for at least one minor release, and every later release reads every older PTF file.

### REQ-CLI-003: Machine-readable output
- status: met
- spec: new
- evidence: EXP-0007-r8

`trace info`, `trace check` and `doctor` support `--json` output for scripting.

### REQ-CLI-004: Documented exit codes
- status: met
- spec: new
- design: docs/design/cli.md
- evidence: EXP-0002-r16, EXP-0007-r8

Exit codes are documented and stable: 0 success, 1 check failed or invalid input, 2 usage error, 3 partial result (for example, a session completed with failed phases).
