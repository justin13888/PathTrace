#!/bin/sh
# EXP-0008-r2: the published release is complete, static, runnable and evidence-clean. Exit 0 = pass, 1 = fail.
# Run via `cargo xtask evidence run EXP-0008-r2`; TAG defaults to v1.0.1.
set -u
out=${PT_EVIDENCE_OUT:?}
tag=${TAG:-v1.0.1}
fail=0
say() { echo "$*" | tee -a "$out/checks.txt"; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# 1. Release exists, tag points at a merge commit on main, assets complete.
gh api "repos/justin13888/PathTrace/releases/tags/$tag" --jq '{tag_name, draft, prerelease, assets: [.assets[].name]}' >"$out/release.json" || { say "FAIL release $tag not found"; exit 1; }
sha=$(git rev-parse "$tag^{commit}")
echo "$sha" >"$out/tag_commit.txt"
if [ "$(git cat-file -t "$tag")" = tag ]; then say "PASS $tag is an annotated tag"; else say "FAIL $tag is not annotated"; fail=1; fi
if git merge-base --is-ancestor "$sha" origin/main && [ "$(git rev-list --parents -n1 "$sha" | wc -w)" -eq 3 ]; then say "PASS $tag is a merge commit on main"; else say "FAIL $tag is not a merge commit on main"; fail=1; fi
for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  if grep -q "pathtrace-$tag-$t.tar.gz\"" "$out/release.json"; then say "PASS asset for $t"; else say "FAIL no asset for $t"; fail=1; fi
done
if grep -q '"SHA256SUMS"' "$out/release.json"; then say "PASS SHA256SUMS published"; else say "FAIL no SHA256SUMS"; fail=1; fi
# 2. Checksums verify.
gh release download "$tag" --repo justin13888/PathTrace --dir "$tmp/dl" --pattern '*.tar.gz' --pattern SHA256SUMS
cp "$tmp/dl/SHA256SUMS" "$out/SHA256SUMS"
if (cd "$tmp/dl" && sha256sum -c SHA256SUMS) >"$out/sha256_check.txt" 2>&1; then say "PASS sha256sum -c SHA256SUMS"; else say "FAIL checksum mismatch"; fail=1; fi
# 3. Static binaries for the right architecture.
for pair in x86_64-unknown-linux-musl:x86-64 aarch64-unknown-linux-musl:aarch64; do
  t=${pair%%:*}; arch=${pair#*:}
  tar xzf "$tmp/dl/pathtrace-$tag-$t.tar.gz" -C "$tmp"
  d="$tmp/pathtrace-$tag-$t"
  ls "$d" >"$out/contents-$t.txt"
  f=$(file -b "$d/pathtrace"); echo "$f" >"$out/file-$t.txt"
  if echo "$f" | grep -q "$arch" && echo "$f" | grep -qE 'static(-pie)? linked|statically linked'; then say "PASS $t binary is static $arch"; else say "FAIL $t: $f"; fail=1; fi
  for x in pathtrace LICENSE README.md pathtrace-responder.service; do
    [ -e "$d/$x" ] || { say "FAIL $t archive lacks $x"; fail=1; }
  done
done
bin="$tmp/pathtrace-$tag-x86_64-unknown-linux-musl/pathtrace"
# 4. The released binary reports the tag version and passes doctor.
v=$("$bin" --version); echo "$v" >"$out/version.txt"
if [ "$v" = "pathtrace ${tag#v}" ]; then say "PASS --version = $v"; else say "FAIL --version: $v"; fail=1; fi
"$bin" --config-dir "$tmp/cfg" keygen >/dev/null 2>&1
if "$bin" --config-dir "$tmp/cfg" doctor --json >"$out/doctor.json" 2>"$out/doctor.err" && python3 -c 'import sys,json; d=json.load(open(sys.argv[1])); assert d["ok"]' "$out/doctor.json"; then say "PASS doctor ok from the released binary"; else say "FAIL doctor"; fail=1; fi
# The 1.0.1 fix: doctor's self-test warms up, so on this host (kernel RX stamps work in sessions)
# it must report them.
if python3 -c 'import sys,json; d=json.load(open(sys.argv[1])); c=[x for x in d["checks"] if x["check"]=="kernel timestamps"][0]; assert c["ok"], c' "$out/doctor.json" 2>>"$out/checks.txt"; then say "PASS doctor reports kernel RX and TX stamps"; else say "FAIL doctor kernel timestamps"; fail=1; fi
# 5. A smoke session through the namespace harness with the released binary, then trace check.
mkdir -p "$tmp/s"
BIN="$bin" OUT="$tmp/s" PROFILE=smoke unshare -Urnm sh tools/netns/session.sh >"$out/session.log" 2>&1
pe=$(cat "$tmp/s/probe.exit" 2>/dev/null); echo "$pe" >"$out/probe.exit"
trace=$(find "$tmp/s" -maxdepth 1 -name "*.ptf" | head -1)
if [ "$pe" = 0 ] && [ -n "$trace" ] && "$bin" trace check "$trace" >"$out/trace_check.txt" 2>&1; then say "PASS smoke session complete, trace valid"; else say "FAIL smoke session (probe exit $pe)"; fail=1; fi
[ -n "$trace" ] && "$bin" trace dump "$trace" 2>/dev/null | python3 -c 'import sys,json,re; m=re.search(r"\"tool\":(\{[^}]*\})", sys.stdin.read()); print(json.dumps({"tool": json.loads(m.group(1))}))' >"$out/trace_tool.json"
if python3 -c 'import sys,json; d=json.load(open(sys.argv[1]))["tool"]; assert d["version"]==sys.argv[2] and d["git_commit"]==sys.argv[3] and d["git_dirty"] is False, d' "$out/trace_tool.json" "${tag#v}" "$sha" 2>>"$out/checks.txt"; then say "PASS trace META: version ${tag#v}, commit of $tag, clean build"; else say "FAIL trace META provenance"; fail=1; fi
# 6. Release-mode audit passes at the tag.
if git worktree add -q --detach "$tmp/wt" "$tag" && (root=$(pwd); cd "$tmp/wt" && CARGO_TARGET_DIR="$root/target" cargo xtask audit --release) >"$out/audit_release.txt" 2>&1; then say "PASS audit --release at $tag"; else say "FAIL audit --release at $tag"; fail=1; fi
git worktree remove --force "$tmp/wt" 2>/dev/null
exit $fail
