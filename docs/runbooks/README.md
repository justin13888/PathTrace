# docs/runbooks/

Step-by-step operational procedures for humans running PathTrace for real. Each runbook states prerequisites, exact commands, expected output, and what to do when a step fails.

- Naming: `kebab-task.md`.
- A runbook is updated in the same PR as any CLI or deployment change that affects it.

| Runbook | Purpose |
|---|---|
| [responder-deploy.md](responder-deploy.md) | Install the responder on a public VM, pair the laptop, verify with a smoke session |
| [field-session.md](field-session.md) | Capture traces on real networks: labels, profiles, exit codes, sampling plan, privacy |
| [release.md](release.md) | Cut a release: version bump, dry run, annotated tag, gated publish, release evidence |
