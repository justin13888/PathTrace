#!/bin/sh
# Overlay ground truth, responder side (docs/design/overlay-ground-truth.md): runs on the Linux
# responder (tc); the initiator side, run.sh, runs on macOS or Linux.
#
# Run once, as root, for a whole schedule:
#   sudo tools/overlay-gt/impair.sh --dev tailscale0 --peer <initiator tailnet IP> \
#     --control <dir> --timeout <seconds> [--schedule FILE] [--ports "4433 443 80"]
#
# Installs on DEV's egress a prio qdisc whose u32 filters send to a netem child only packets to
# PEER from the responder's PORTS (UDP and TCP); everything else (ssh, other peers) passes
# untouched. Then, per schedule step NN (01, 02, ...), it waits for the initiator to create
# CONTROL/NN.step holding the step's name, applies that step's netem arguments from the
# schedule (never from the step file), writes CONTROL/NN.ack, waits for CONTROL/NN.end and
# writes CONTROL/NN.stats. CONTROL/done ends the run early. The qdisc is removed on every exit
# path (EXIT, INT, TERM, HUP) and when --timeout expires.
set -eu

DEV=
PEER=
CTL=
TIMEOUT=
SCHEDULE=$(dirname "$0")/schedule
PORTS="4433 443 80"
INSTALLED=0
SCHED_COPY=

die() {
	echo "impair: $*" >&2
	exit 1
}

usage() {
	sed -n '5,7p' "$0" >&2
	exit 2
}

while [ $# -gt 0 ]; do
	case $1 in
	--dev) DEV=${2-} ;;
	--peer) PEER=${2-} ;;
	--control) CTL=${2-} ;;
	--timeout) TIMEOUT=${2-} ;;
	--schedule) SCHEDULE=${2-} ;;
	--ports) PORTS=${2-} ;;
	-h | --help) usage ;;
	*) usage ;;
	esac
	[ $# -ge 2 ] || usage
	shift 2
done

[ -n "$DEV" ] && [ -n "$PEER" ] && [ -n "$CTL" ] && [ -n "$TIMEOUT" ] || usage
[ "$(id -u)" = 0 ] || die "run with sudo (tc needs root)"
case $DEV in *[!A-Za-z0-9._-]*) die "bad device name" ;; esac
case $PEER in
*[!0-9A-Fa-f:.]*) die "--peer must be an IPv4 or IPv6 address" ;;
*:*) FAMILY=ipv6 ;;
*.*.*.*) FAMILY=ip ;;
*) die "--peer must be an IPv4 or IPv6 address" ;;
esac
case $TIMEOUT in '' | *[!0-9]*) die "--timeout must be whole seconds" ;; esac
[ "$TIMEOUT" -gt 0 ] || die "--timeout must be positive"
for p in $PORTS; do
	case $p in *[!0-9]*) die "bad port $p" ;; esac
	[ "$p" -ge 1 ] && [ "$p" -le 65535 ] || die "bad port $p"
done
[ -d "$CTL" ] && [ ! -L "$CTL" ] || die "--control must be an existing directory (not a link)"
[ -f "$SCHEDULE" ] || die "no schedule at $SCHEDULE"
for f in "$CTL"/*.step "$CTL"/*.ack "$CTL"/*.end "$CTL"/*.stats "$CTL"/done; do
	[ -e "$f" ] && die "$CTL holds files of an earlier run ($f); use an empty directory"
done

# Schedule entries without comments or blank lines, copied so edits during the run do not apply.
SCHED_COPY=$(mktemp)
sed -e 's/#.*//' -e 's/[[:space:]]*$//' "$SCHEDULE" | grep -v '^[[:space:]]*$' >"$SCHED_COPY" || true
STEPS=$(wc -l <"$SCHED_COPY" | tr -d ' ')
[ "$STEPS" -gt 0 ] || die "schedule $SCHEDULE has no steps"

# entry N: sets NAME and SPEC from schedule line N.
entry() {
	line=$(sed -n "$1p" "$SCHED_COPY")
	set -f
	# shellcheck disable=SC2086 # split the line into name and netem words
	set -- $line
	set +f
	NAME=$1
	shift
	SPEC=$*
}

i=0
while [ "$i" -lt "$STEPS" ]; do
	i=$((i + 1))
	entry "$i"
	case $NAME in '' | *[!A-Za-z0-9._-]*) die "schedule line $i: bad step name" ;; esac
	case $SPEC in '' | *[!A-Za-z0-9.%[:space:]]*) die "schedule step $NAME: bad netem arguments" ;; esac
	if [ "$i" = 1 ] && [ "$SPEC" != none ]; then
		die "the first schedule step must be 'none' (the baseline)"
	fi
done

# Refuse anything but the kernel's default root qdisc (handle 0:): never delete what we did not add.
root=$(tc qdisc show dev "$DEV" | grep ' root' | head -n1) || die "cannot read qdiscs of $DEV"
# shellcheck disable=SC2086 # "qdisc <kind> <handle> root ..."
set -- $root
[ "${3-}" = "0:" ] || die "$DEV already has a configured root qdisc ($root); remove it first"

cleanup() {
	status=$?
	trap - EXIT INT TERM HUP
	if [ "$INSTALLED" = 1 ]; then
		tc qdisc del dev "$DEV" root 2>/dev/null || true
		echo "impair: removed the impairment; $DEV now has:" >&2
		tc qdisc show dev "$DEV" >&2 || true
	fi
	[ -z "$SCHED_COPY" ] || rm -f "$SCHED_COPY"
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

DEADLINE=$(($(date +%s) + TIMEOUT))

INSTALLED=1
tc qdisc add dev "$DEV" root handle 1: prio bands 3 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
tc qdisc add dev "$DEV" parent 1:1 handle 10: netem limit 100000
if [ "$FAMILY" = ip ]; then
	sel=ip
	prefix=$PEER/32
else
	sel=ip6
	prefix=$PEER/128
fi
for proto in 17 6; do
	for port in $PORTS; do
		tc filter add dev "$DEV" parent 1: protocol "$FAMILY" prio 1 u32 \
			match "$sel" dst "$prefix" match "$sel" protocol "$proto" 0xff \
			match "$sel" sport "$port" 0xffff flowid 1:1
	done
done

# wait_for FILE: 0 when FILE appears, 1 when CONTROL/done does; exits at the deadline.
wait_for() {
	while [ ! -e "$1" ]; do
		[ ! -e "$CTL/done" ] || return 1
		[ "$(date +%s)" -lt "$DEADLINE" ] || die "timeout: ${TIMEOUT}s elapsed"
		sleep 1
	done
}

# put NAME: stdin to CONTROL/NAME through a fresh file, renamed over whatever is there.
put() {
	tmp=$(mktemp "$CTL/.impair.XXXXXX")
	cat >"$tmp"
	chmod 0644 "$tmp"
	mv -fT "$tmp" "$CTL/$1"
}

qdisc_state() {
	echo "--- tc -s qdisc show dev $DEV"
	tc -s qdisc show dev "$DEV"
	echo "--- tc filter show dev $DEV parent 1:"
	tc filter show dev "$DEV" parent 1:
}

echo "impair: $STEPS steps on $DEV for $PEER, ports $PORTS; waiting for $CTL/01.step (timeout ${TIMEOUT}s)" >&2
i=0
while [ "$i" -lt "$STEPS" ]; do
	i=$((i + 1))
	nn=$(printf '%02d' "$i")
	entry "$i"
	wait_for "$CTL/$nn.step" || break
	[ -f "$CTL/$nn.step" ] && [ ! -L "$CTL/$nn.step" ] || die "$nn.step is not a regular file"
	got=$(head -n1 "$CTL/$nn.step" | tr -d '\r')
	[ "$got" = "$NAME" ] || die "step $nn: the initiator asked for another step than schedule entry $nn ($NAME)"
	if [ "$SPEC" = none ]; then
		args="limit 100000"
	else
		args=$SPEC
	fi
	set -f
	# shellcheck disable=SC2086 # netem arguments are words
	tc qdisc replace dev "$DEV" parent 1:1 handle 10: netem $args
	set +f
	{
		echo "step $nn $NAME"
		echo "netem $SPEC"
		echo "applied $(date -u +%Y-%m-%dT%H:%M:%SZ)"
		qdisc_state
	} | put "$nn.ack"
	echo "impair: step $nn $NAME applied (netem $SPEC)" >&2
	wait_for "$CTL/$nn.end" || break
	{
		echo "step $nn $NAME"
		echo "ended $(date -u +%Y-%m-%dT%H:%M:%SZ)"
		qdisc_state
	} | put "$nn.stats"
done
echo "impair: schedule finished" >&2
