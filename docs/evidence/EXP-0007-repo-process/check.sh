#!/bin/sh
# EXP-0007: mechanical checks of the repository process. Exit 0 = pass, 1 = fail.
set -u
out=${PT_EVIDENCE_OUT:?}
fail=0
say() { echo "$*" | tee -a "$out/checks.txt"; }
# 1. Conventional commits with the closed scope set (merges skipped, as in CI).
if mise exec -- convco check --ignore-reverts HEAD >"$out/convco.txt" 2>&1; then say "PASS convco: all non-merge commits conventional"; else say "FAIL convco"; fail=1; fi
bad=$(git log --no-merges --format=%s | grep -cvE '^[a-z]+\([a-z]+\)!?: ')
if [ "$bad" -eq 0 ]; then say "PASS every non-merge commit has a scope"; else say "FAIL $bad commits without scope"; fail=1; fi
# 2. GitHub merge settings and ruleset.
gh api repos/justin13888/PathTrace --jq '{allow_merge_commit,allow_squash_merge,allow_rebase_merge}' >"$out/merge_settings.json"
if grep -q '"allow_merge_commit":true' "$out/merge_settings.json" && grep -q '"allow_squash_merge":false' "$out/merge_settings.json" && grep -q '"allow_rebase_merge":false' "$out/merge_settings.json"; then say "PASS merge-commit-only repository settings"; else say "FAIL merge settings"; fail=1; fi
rid=$(gh api repos/justin13888/PathTrace/rulesets --jq '.[] | select(.name=="Protect main") | .id')
gh api "repos/justin13888/PathTrace/rulesets/$rid" --jq '{enforcement, bypass: .bypass_actors, rules: [.rules[].type], merge_methods: (.rules[] | select(.type=="pull_request") | .parameters.allowed_merge_methods)}' >"$out/ruleset.json"
if grep -q '"enforcement":"active"' "$out/ruleset.json" && grep -q 'non_fast_forward' "$out/ruleset.json" && grep -q 'deletion' "$out/ruleset.json" && grep -q '"merge_methods":\["merge"\]' "$out/ruleset.json"; then say "PASS ruleset active: no force-push, no deletion, merge only"; else say "FAIL ruleset"; fail=1; fi
# 3. License detection.
spdx=$(gh api repos/justin13888/PathTrace/license --jq .license.spdx_id)
echo "$spdx" >"$out/license_spdx.txt"
if [ "$spdx" = "Apache-2.0" ]; then say "PASS GitHub detects Apache-2.0"; else say "FAIL license detection: $spdx"; fail=1; fi
sha256sum LICENSE >"$out/license_sha256.txt"
# 4. Agent instructions.
if [ -L CLAUDE.md ] && [ "$(readlink CLAUDE.md)" = "AGENTS.md" ]; then say "PASS CLAUDE.md -> AGENTS.md"; else say "FAIL CLAUDE.md symlink"; fail=1; fi
# 5. Pinned tools.
if [ -s mise.lock ] && mise ls --current >"$out/mise_tools.txt" 2>&1; then say "PASS tools pinned (mise.lock present)"; else say "FAIL mise.lock"; fail=1; fi
# 6. Design-first PRs: first commit of each merged PR branch is docs/test of docs scopes.
git log --merges --first-parent --format='%H %s' HEAD >"$out/merges.txt"
while read -r m subject; do
  first=$(git log --reverse --format=%s "$m^1..$m^2" | head -1)
  case "$first" in
    docs\(*) say "PASS PR '$subject' starts with: $first" ;;
    *) say "FAIL PR '$subject' starts with: $first"; fail=1 ;;
  esac
done <"$out/merges.txt"
exit $fail
