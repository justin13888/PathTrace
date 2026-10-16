#!/bin/sh
# Overlay ground truth, initiator side (docs/design/overlay-ground-truth.md). Runs on macOS or
# Linux, unprivileged, while `sudo tools/overlay-gt/impair.sh` waits on the responder.
#
# Usage:
#   tools/overlay-gt/run.sh --ssh <user@responder> --control <dir on the responder> \
#     --responder <pathtrace probe target> --out <dir> [--profile standard] [--class home] \
#     [--schedule FILE] [--bin pathtrace] [--remote-state DIR] [--ack-timeout 60]
# Environment: TAILSCALE (tailscale CLI, default `tailscale`), TS_PEER (address for
#   `tailscale ping`, default the host part of --ssh).
#
# Per schedule step NN: creates NN.step over ssh, waits for impair.sh's NN.ack, runs
# `pathtrace probe` into a scratch directory, creates NN.end, fetches NN.ack and NN.stats, and
# copies into OUT/NN-<name>/ the .ptf, .a.ptflog and .b.ptflog, the probe's output and exit
# code, and tailscale ping/status snapshots. The scratch directory keeps the probe's .session
# file (it holds the fetch token) out of OUT; OUT never receives key files or pairing strings.
# A .b.ptflog the probe could not fetch is copied from --remote-state/sessions/<id>/ when given.
# Check the result with `cargo xtask overlay-gt check OUT`.
set -eu

SSH_HOST=
CTL=
RESPONDER=
OUT=
PROFILE=standard
CLASS=home
SCHEDULE=$(dirname "$0")/schedule
BIN=pathtrace
REMOTE_STATE=
ACK_TIMEOUT=60
TAILSCALE=${TAILSCALE:-tailscale}

die() {
	echo "run: $*" >&2
	exit 1
}

usage() {
	sed -n '5,10p' "$0" >&2
	exit 2
}

while [ $# -gt 0 ]; do
	case $1 in
	--ssh) SSH_HOST=${2-} ;;
	--control) CTL=${2-} ;;
	--responder) RESPONDER=${2-} ;;
	--out) OUT=${2-} ;;
	--profile) PROFILE=${2-} ;;
	--class) CLASS=${2-} ;;
	--schedule) SCHEDULE=${2-} ;;
	--bin) BIN=${2-} ;;
	--remote-state) REMOTE_STATE=${2-} ;;
	--ack-timeout) ACK_TIMEOUT=${2-} ;;
	-h | --help) usage ;;
	*) usage ;;
	esac
	[ $# -ge 2 ] || usage
	shift 2
done

[ -n "$SSH_HOST" ] && [ -n "$CTL" ] && [ -n "$RESPONDER" ] && [ -n "$OUT" ] || usage
case $CTL in *[!A-Za-z0-9._/~-]*) die "--control must be a plain path" ;; esac
case $REMOTE_STATE in *[!A-Za-z0-9._/~-]*) die "--remote-state must be a plain path" ;; esac
case $ACK_TIMEOUT in '' | *[!0-9]*) die "--ack-timeout must be whole seconds" ;; esac
[ -f "$SCHEDULE" ] || die "no schedule at $SCHEDULE"
command -v "$BIN" >/dev/null 2>&1 || [ -x "$BIN" ] || die "no pathtrace binary ($BIN)"
TS_PEER=${TS_PEER:-${SSH_HOST#*@}}

mkdir -p "$OUT"
[ -z "$(ls -A "$OUT")" ] || die "$OUT is not empty"
SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/overlay-gt.XXXXXX")
echo "run: probe scratch (session files, kept for pathtrace fetch --resume): $SCRATCH" >&2

sed -e 's/#.*//' -e 's/[[:space:]]*$//' "$SCHEDULE" | grep -v '^[[:space:]]*$' >"$OUT/schedule" || true
STEPS=$(wc -l <"$OUT/schedule" | tr -d ' ')
[ "$STEPS" -gt 0 ] || die "schedule has no steps"
{
	echo "pathtrace $("$BIN" --version 2>&1 | head -n1)"
	echo "host $(uname -srm)"
	echo "started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "responder $RESPONDER"
	echo "profile $PROFILE"
	echo "class $CLASS"
} >"$OUT/env.txt"

# rsh CMD: run CMD on the responder (CMD is built from validated words only).
rsh() {
	ssh -o BatchMode=yes "$SSH_HOST" "$1"
}

# wait_remote FILE: until CONTROL/FILE exists on the responder, at most ACK_TIMEOUT seconds.
wait_remote() {
	deadline=$(($(date +%s) + ACK_TIMEOUT))
	until rsh "test -f $CTL/$1"; do
		[ "$(date +%s)" -lt "$deadline" ] || die "no $1 from impair.sh within ${ACK_TIMEOUT}s"
		sleep 1
	done
}

snapshot() {
	if command -v "$TAILSCALE" >/dev/null 2>&1; then
		"$TAILSCALE" ping -c 5 "$TS_PEER" >"$1/tailscale-ping.txt" 2>&1 || true
		"$TAILSCALE" status --json >"$1/tailscale-status.json" 2>/dev/null || true
	else
		echo "tailscale CLI not found ($TAILSCALE)" >"$1/tailscale-ping.txt"
	fi
}

failed=0
i=0
while [ "$i" -lt "$STEPS" ]; do
	i=$((i + 1))
	nn=$(printf '%02d' "$i")
	name=$(sed -n "${i}p" "$OUT/schedule" | awk '{print $1}')
	case $name in '' | *[!A-Za-z0-9._-]*) die "schedule line $i: bad step name" ;; esac
	dir=$OUT/$nn-$name
	scratch=$SCRATCH/$nn-$name
	mkdir -p "$dir" "$scratch"
	echo "run: step $nn $name" >&2
	rsh "printf '%s\n' $name >$CTL/.$nn.step.tmp && mv -f $CTL/.$nn.step.tmp $CTL/$nn.step"
	wait_remote "$nn.ack"
	scp -q -o BatchMode=yes "$SSH_HOST:$CTL/$nn.ack" "$dir/ack.txt"
	snapshot "$dir"
	set +e
	"$BIN" probe "$RESPONDER" --class "$CLASS" --profile "$PROFILE" --out "$scratch" \
		>"$dir/probe.out" 2>"$dir/probe.err"
	echo $? >"$dir/probe.exit"
	set -e
	rsh "touch $CTL/$nn.end"
	wait_remote "$nn.stats"
	scp -q -o BatchMode=yes "$SSH_HOST:$CTL/$nn.stats" "$dir/stats.txt"
	a_log=$(find "$scratch" -name '*.a.ptflog' | head -n1)
	if [ -n "$a_log" ]; then
		id=$(basename "$a_log" .a.ptflog)
		b_log=$scratch/$id.b.ptflog
		if [ ! -f "$b_log" ] && [ -n "$REMOTE_STATE" ]; then
			sess=$(sed -n 's/.*session: \([0-9a-f][0-9a-f]*\).*/\1/p' "$dir/probe.err" | head -n1)
			if [ -n "$sess" ]; then
				scp -q -o BatchMode=yes "$SSH_HOST:$REMOTE_STATE/sessions/$sess/b.ptflog" "$b_log" ||
					echo "run: step $nn: could not copy the responder log" >&2
			fi
			[ ! -f "$b_log" ] || "$BIN" merge "$a_log" "$b_log" -o "$scratch/$id.ptf" >>"$dir/probe.err" 2>&1 || true
		fi
		for f in "$scratch/$id.ptf" "$a_log" "$b_log"; do
			[ ! -f "$f" ] || cp "$f" "$dir/"
		done
	fi
	mkdir -p "$dir/after"
	snapshot "$dir/after"
	[ "$(cat "$dir/probe.exit")" = 0 ] || {
		echo "run: step $nn: probe exited $(cat "$dir/probe.exit") (see $dir/probe.err)" >&2
		failed=1
	}
done
rsh "touch $CTL/done" || true
echo "finished $(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$OUT/env.txt"
echo "run: done; check with: cargo xtask overlay-gt check $OUT" >&2
exit "$failed"
