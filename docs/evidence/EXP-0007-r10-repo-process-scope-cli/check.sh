#!/bin/sh
# EXP-0007-r10: repository process, scope, CLI surface, derivation purity, provenance. Exit 0 = pass, 1 = fail.
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
# 6. Design-first PRs (REQ-REPO-008: each change that adds or alters behaviour lands its design first):
# a merged PR that changes behaviour (code or deployed configuration) starts with a docs commit. A PR
# that changes no behaviour (release version bump, evidence run, docs) has no design to land first.
# Recorded exception: #77 (pt-sys macOS backend) landed its design in #74 (spec) and #76 (design) first.
behaviour='^(crates/[^/]+/src/|xtask/src/|tools/|fuzz/fuzz_targets/|bench/[^/]+/src/|deploy/)'
git log --merges --first-parent --format='%H %s' HEAD >"$out/merges.txt"
while read -r m subject; do
  first=$(git log --reverse --format=%s "$m^1..$m^2" | head -1)
  case "$first" in
    docs\(*) say "PASS PR '$subject' starts with: $first" ;;
    *)
      if ! git diff --name-only "$m^1" "$m" | grep -qE "$behaviour"; then say "PASS PR '$subject' changes no behaviour (starts with: $first)"
      else case "$subject" in
        *'(#77)') say "PASS PR '$subject' design landed first in #74 and #76 (starts with: $first)" ;;
        *) say "FAIL PR '$subject' starts with: $first"; fail=1 ;;
      esac; fi ;;
  esac
done <"$out/merges.txt"
# 7. Audit chain (non-release mode: pending/stale reported, not failing).
# An experiment cannot vouch for itself: requirements whose only evidence is this experiment's
# lineage (EXP-0007*) have no current pass until this run is committed. Any other error fails.
if cargo xtask audit >"$out/audit.txt" 2>&1; then say "PASS audit chain intact"
else
  others=0
  grep '^ERROR' "$out/audit.txt" | grep -oE 'REQ-[A-Z]+-[0-9]{3}' >"$out/audit_reqs.txt"
  while read -r r; do
    f=$(grep -l "^### $r:" docs/spec/REQ-*.md)
    awk -v r="### $r:" 'index($0, r) == 1 {p=1; next} p && /^### / {exit} p && /^- evidence:/ {print}' "$f" | grep -q 'EXP-0007' || others=$((others + 1))
  done <"$out/audit_reqs.txt"
  nonreq=$(grep '^ERROR' "$out/audit.txt" | grep -cv 'status met but no listed evidence')
  if [ "$others" -eq 0 ] && [ "$nonreq" -eq 0 ]; then say "PASS audit chain intact apart from requirements awaiting this experiment ($(grep -c '^ERROR' "$out/audit.txt"))"
  else say "FAIL audit ($others requirement errors outside this experiment, $nonreq other errors)"; fail=1; fi
fi
# 8. Scope.
# REQ-SCOPE-009: platform code only in pt-sys, behind cfg(target_os), for linux and macos only;
# no cfg for any other platform anywhere. Rust sources and manifests are both searched.
code() { grep -rnE --include='*.rs' --include='Cargo.toml' "$1" crates xtask bench Cargo.toml; }
code 'target_os' | grep -v '^crates/pt-sys/' >"$out/target_os_outside_pt_sys.txt"
if [ -s "$out/target_os_outside_pt_sys.txt" ]; then say "FAIL target_os outside pt-sys"; fail=1; else say "PASS target_os appears only in pt-sys"; fi
code 'target_os' | grep -oE 'target_os *= *"[^"]*"' | sed -E 's/.*"(.*)"/\1/' | sort | uniq -c >"$out/target_os_values.txt"
if awk '$2 != "linux" && $2 != "macos" {bad=1} END {exit !bad}' "$out/target_os_values.txt"; then say "FAIL target_os other than linux or macos"; fail=1
elif ! grep -qw linux "$out/target_os_values.txt"; then say "FAIL pt-sys has no linux backend"; fail=1
else say "PASS target_os names only linux and macos ($(awk '{printf "%s%s %s", sep, $2, $1; sep=", "}' "$out/target_os_values.txt"))"; fi
# windows/unix as a cfg predicate anywhere inside cfg(...), cfg_attr(...) or cfg!(...), including
# nested any/all/not and predicates rustfmt splits over several lines. Comments and string literals
# are blanked in the whole file first (newlines kept, so line numbers hold), so text such as
# "cfg(windows)" in a comment or a string is never a predicate. In Cargo.toml only comments are
# blanked: a [target.'cfg(...)'] table header carries its predicate inside a TOML string.
code 'target_family|target_vendor' >"$out/other_platform_cfg.txt"
# shellcheck disable=SC2016 # the single-quoted program is Perl, not shell
grep -rlE --include='*.rs' --include='Cargo.toml' 'cfg' crates xtask bench Cargo.toml | xargs perl -0777 -ne '
  my $nl = sub { "\n" x ($_[0] =~ tr/\n//) };
  if ($ARGV =~ /\.rs$/) {
    s{(//[^\n]*)|(/\*(?:[^/*]++|/(?!\*)|\*(?!/)|(?2))*\*/)|((?<!\w)b?r(#*)".*?"\4)|("(?:[^"\\]|\\.)*")|(\x27(?:[^\x27\\\n]|\\[^\n]{1,9}?)\x27)}{defined $1 || defined $2 ? $nl->($&) : defined $6 ? "\x27 \x27" : "\"\"" . $nl->($&)}gse;
  } else {
    s{("(?:[^"\\\n]|\\.)*"|\x27[^\x27\n]*\x27)|#[^\n]*}{defined $1 ? $1 : ""}ge;
  }
  while (/\b(cfg(?:_attr)?!?)\s*(\((?:[^()"]++|"(?:[^"\\]|\\.)*"|(?2))*\))/g) {
    my ($k, $m, $at) = ($1, $2, $-[0]); (my $p = $m) =~ s/"(?:[^"\\]|\\.)*"//g;
    if ($p =~ /(?<![\w"])(?:windows|unix)(?![\w"])/) { my $l = 1 + (substr($_, 0, $at) =~ tr/\n//); (my $s = $m) =~ s/\s+/ /g; print "$ARGV:$l:$k$s\n" }
  }' >>"$out/other_platform_cfg.txt"
if [ -s "$out/other_platform_cfg.txt" ]; then say "FAIL platform cfg other than target_os"; fail=1; else say "PASS no windows/unix/target_family/target_vendor cfg"; fi
roles=$(sed -n '/pub enum Role {/,/^}/p' crates/pt-probe/src/flows.rs | grep -cE '^\s+[A-Z],?$')
if [ "$roles" -eq 2 ]; then say "PASS exactly two endpoint roles (a, b): one path"; else say "FAIL role count $roles"; fail=1; fi
if grep -nE 'tcpinfo|"app\[' crates/pt-derive/src/dir.rs >"$out/protocol_in_path.txt"; then say "FAIL protocol results read by PATH derivation"; fail=1; else say "PASS PATH derivation never reads protocol results (tcpinfo/app only feed VALD)"; fi
if find crates -mindepth 1 -maxdepth 1 -type d | grep -qiE 'topolog|chaos|replay|emu'; then say "FAIL out-of-scope crate present"; fail=1; else say "PASS no topology/chaos/replay/emulator crates (excluded areas)"; fi
BIN=target/release/pathtrace
cargo build --release --locked -q -p pathtrace
if "$BIN" probe --help | grep -q 'default: 500000000' && "$BIN" serve --help | grep -q 'default: 500000000'; then say "PASS rate cap defaults to 500 Mbit/s (probe and serve)"; else say "FAIL rate cap default"; fail=1; fi
# 9. CLI surface, JSON, exit codes.
for c in keygen authorize responder serve probe merge derive export import fetch trace doctor; do
  if "$BIN" "$c" --help >/dev/null 2>&1; then :; else say "FAIL command $c missing"; fail=1; fi
done
for c in check info dump load redact; do "$BIN" trace "$c" --help >/dev/null 2>&1 || { say "FAIL trace $c missing"; fail=1; }; done
say "PASS documented commands present (checked $(echo keygen authorize responder serve probe merge derive export import fetch trace doctor | wc -w) + 5 trace subcommands)"
G=conformance/v1.0-real/smoke-ipv6-netns-anonymous.ptf
if "$BIN" trace info --json "$G" | python3 -c 'import sys,json; json.load(sys.stdin)' && "$BIN" trace check --json "$G" | python3 -c 'import sys,json; assert json.load(sys.stdin)["valid"]'; then say "PASS trace info/check --json parse"; else say "FAIL json output"; fail=1; fi
"$BIN" trace check conformance/v1.0/invalid-crc.ptf >/dev/null 2>&1; e1=$?
"$BIN" --no-such-flag >/dev/null 2>&1; e2=$?
"$BIN" trace check "$G" >/dev/null 2>&1; e0=$?
if [ "$e0" -eq 0 ] && [ "$e1" -eq 1 ] && [ "$e2" -eq 2 ]; then say "PASS exit codes 0 (ok) 1 (invalid) 2 (usage)"; else say "FAIL exit codes $e0 $e1 $e2"; fail=1; fi
# 10. Derivation purity and provenance.
tmp=$(mktemp -d)
"$BIN" derive "$G" -o "$tmp/d1.ptf" >/dev/null && "$BIN" derive "$tmp/d1.ptf" -o "$tmp/d2.ptf" >/dev/null
if cmp -s "$tmp/d1.ptf" "$tmp/d2.ptf"; then say "PASS derive is deterministic and idempotent (byte-identical)"; else say "FAIL derive not idempotent"; fail=1; fi
"$BIN" trace dump "$G" >"$tmp/g.jsonl"; "$BIN" trace dump "$tmp/d1.ptf" >"$tmp/d.jsonl"
if python3 - "$tmp/g.jsonl" "$tmp/d.jsonl" <<'PY'
import json, sys
# The first line is the file header, not a section: re-deriving raises its minor (ptf-format.md).
def raw(p):
    return [l for l in list(open(p))[1:] if json.loads(l).get("type") not in ("PATH", "SERS", "PLCY", "VALD")]
sys.exit(0 if raw(sys.argv[1]) == raw(sys.argv[2]) else 1)
PY
then say "PASS derive leaves raw sections byte-identical (JSON twin compared)"; else say "FAIL derive changed raw sections"; fail=1; fi
# The expected minor is the writer's own constant (one place), so a later minor bump moves it with the code.
wminor=$(sed -n 's/^pub const MINOR: u16 = \([0-9][0-9]*\);$/\1/p' crates/pt-format/src/container.rs)
if [ -z "$wminor" ] || [ "$wminor" -lt 1 ]; then say "FAIL writer minor not found in crates/pt-format/src/container.rs: '$wminor'"; fail=1
elif head -n1 "$tmp/g.jsonl" | grep -qx '{"ptf":{"major":1,"minor":0}}' && head -n1 "$tmp/d.jsonl" | grep -qx "{\"ptf\":{\"major\":1,\"minor\":$wminor}}"; then say "PASS derive raises a 1.0 file's header minor to the writer's 1.$wminor"
else say "FAIL header minor after derive: $(head -n1 "$tmp/d.jsonl") (writer minor $wminor)"; fail=1; fi
if python3 - "$tmp/d.jsonl" <<'PY'
import json, re, sys
meta = path = None
for l in open(sys.argv[1]):
    o = json.loads(l)
    if o.get("type") == "META": meta = o["head"]
    if o.get("type") == "PATH": path = o["head"]
assert re.fullmatch(r"[0-9a-f]{40}", meta["tool"]["git_commit"]) and "git_dirty" in meta["tool"]
assert all(re.fullmatch(r"[a-z0-9.-]+/[0-9]+", m) for m in path["derivation"]["methods"])
for d in ("a_to_b", "b_to_a"):
    for name, f in path["directions"][d].items():
        if isinstance(f, dict):
            assert re.fullmatch(r"[a-z0-9.-]+/[0-9]+", f["method"]), (d, name)
            assert f["status"] in ("known", "estimated", "unknown"), (d, name)
PY
then say "PASS trace provenance: tool commit, versioned methods, status on every PATH field"; else say "FAIL provenance"; fail=1; fi
# 11. doctor.
mkdir -p "$tmp/cfg" && "$BIN" --config-dir "$tmp/cfg" keygen >/dev/null 2>&1
if "$BIN" --config-dir "$tmp/cfg" doctor --json | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["ok"] and len(d["checks"]) >= 4'; then say "PASS doctor runs, reports JSON, local checks ok"; else say "FAIL doctor"; fail=1; fi
rm -rf "$tmp"
exit $fail
