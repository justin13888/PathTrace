# R-0008: Can hk alone enforce semantic commits with a closed scope set?
- source: https://github.com/jdx/hk (v2.5.0: src/cli/util/check_conventional_commit.rs, pkl/builtins/*.pkl); https://github.com/convco/convco (v0.7.2)
- accessed: 2026-10-10
- claim-under-test: hk's native conventional-commit check is enough to enforce PathTrace's commit policy (closed types and closed, required scopes), so convco is unnecessary.
- verdict: refuted
- applicability: Decides the commit-msg hook design (REQ-REPO-003).
## Evidence
- hk builtin `check_conventional_commit` runs `hk util check-conventional-commit {{commit_msg_file}}`, which checks only the first non-comment line. The type must be in `--allowed-types`, an optional `!` is allowed, a scope must be a single non-empty `(...)` if present (any text is accepted), and a description must follow `: `. It cannot restrict scopes to a set.
- convco 0.7.2: `.convco` YAML `types:` (unlisted types rejected) and `scopeRegex`, applied only when a scope is present, so a scope stays optional. There is no `check-message` subcommand; a single message is checked with `convco check --from-stdin --strip < FILE`. Range check for CI: `convco check --ignore-reverts A..B`, which skips merge commits by default.
- Tested in a throwaway repo with hk 2.5.0 and git 2.55: `added stuff`, `style(core): x` and `feat(web): x` (scope outside the regex) were rejected; `feat(ebpf): ...` was accepted.
- git runs the commit-msg hook on `git merge --no-ff`. `--from-stdin` ignores `merges`/`ignoreMessagePattern`, so without a guard a local merge commit is blocked.
- `hk install` on git 2.54 or later writes config-based hooks (`hook.hk-commit-msg.command` in `.git/config`), not files in `.git/hooks`.
## Implications for PTF / probe
- Not applicable to the format. Repository decision: hk runs the hooks, and its commit-msg step (1) lets git-generated `Merge …`/`Revert "…"` titles through, (2) requires a scope with a regex `^[a-z]+\([a-z]+\)!?: .+` (convco treats scopes as optional), and (3) runs `convco check --from-stdin --strip` against `.convco` (closed types and scopes).
- CI repeats the check over the PR range and on the PR title, because the merge commit title is the PR title (`merge_commit_title=PR_TITLE`).
