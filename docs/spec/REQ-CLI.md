# REQ-CLI: command-line interface

### REQ-CLI-001: Command set
- status: planned
- spec: §6.9, §7.6, §7.7, §7.8

`pathtrace` provides `keygen`, `serve`, `probe`, `merge`, `fetch`, `derive`, `doctor`, `trace check|info|dump|load|redact`, `import mahimahi` and `export mahimahi|netem`.

### REQ-CLI-002: Stable interface
- status: planned
- spec: new

From 1.0, commands and flags are stable. Removing one requires a deprecation warning for at least one minor release, and every later release reads every older PTF file.

### REQ-CLI-003: Machine-readable output
- status: planned
- spec: new

`trace info`, `trace check` and `doctor` support `--json` output for scripting.

### REQ-CLI-004: Documented exit codes
- status: planned
- spec: new

Exit codes are documented and stable: 0 success, 1 check failed or invalid input, 2 usage error, 3 partial result (for example, a session completed with failed phases).
