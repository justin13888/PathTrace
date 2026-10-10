# docs/

Every claim PathTrace makes is traceable down this hierarchy to evidence pinned on a git commit.

```
spec/       WHAT must hold      requirements REQ-<AREA>-NNN, status, coverage of the original spec
  └─ design/   HOW it is built     component designs: problem, constraints, alternatives, choice, rationale
      └─ adr/     WHY this choice     architecture decision records (immutable once accepted)
          └─ evidence/  PROOF            experiments EXP-NNNN pinned to a commit, with hashed artifacts
research/   external facts, verified first-hand (cited by design/ADRs)
runbooks/   operational procedures (deploy responder, run field sessions)
```

## How to audit a claim

1. Find the requirement in `spec/` (e.g. `REQ-FMT-004`). It lists its status, design section, ADRs and evidence IDs.
2. Read the design section for the reasoning and the ADR for the decision and rejected alternatives.
3. Open `evidence/EXP-NNNN-*/`. `manifest.toml` gives the exact commit (`pinned_commit`), command, host, and BLAKE3 of every artifact. Check out that commit and re-run the command to reproduce.
4. `cargo xtask audit` checks the whole chain mechanically: every `met` requirement has passing evidence, every pinned commit is an ancestor of `HEAD`, every artifact hash matches, and flags evidence whose covered code changed since it was pinned (stale).

## Rules

- Design precedes code: a PR's first commit is its design section.
- An ADR claiming one option is better cites research or evidence.
- Nothing is deleted to hide a result: failed experiments stay with `verdict = "fail"` and are superseded, not removed.
- Each subdirectory README defines its own naming, template and lifecycle.
