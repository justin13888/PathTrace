#!/bin/sh
# Ground-truth network harness: initiator (ns pa) <-> middlebox (ns pm) <-> responder (ns pb).
# Runs unprivileged inside `unshare -Urnm` (user + net + mount namespaces). Impairments are applied
# on the middlebox egress in each direction with tc, so they are known exactly.
#
# Usage: unshare -Urnm sh tools/netns/session.sh
# Environment:
#   BIN        path to the pathtrace binary (required)
#   OUT        output directory (required)
#   PROFILE    probe profile (default smoke)
#   QDISC_AB   tc qdisc spec for a->b on the middlebox, e.g. "netem delay 10ms rate 20mbit limit 100"
#   QDISC_BA   tc qdisc spec for b->a
#   SETUP_PM   extra shell commands run in the middlebox namespace after setup (e.g. nft rules)
#   SETUP_PA   extra shell commands run in the initiator namespace after setup (e.g. a qdisc on va)
#   SERVE_ENV  environment assignments for `pathtrace serve` (e.g. PATHTRACE_RECV_BUF=8192)
#   PROBE_ENV  environment assignments for `pathtrace probe`
#   PROBE_ARGS extra arguments for `pathtrace probe`
#   SERVE_ARGS extra arguments for `pathtrace serve`
#   RESP_ADDR  responder address the initiator uses (default 10.0.2.2; fd00:2::2 for IPv6)
#   SCRIPT_PM  shell commands run in the middlebox namespace in the background during the probe
#              (e.g. scripted `tc qdisc change` for time-varying capacity)
#   PROBE_SIGNAL_AFTER  send SIGINT to the probe after this many seconds (interruption tests)
#   SERVE_SIGNAL_AFTER  send SERVE_SIGNAL (default TERM) to the responder after this many
#              seconds; independent of PROBE_SIGNAL_AFTER, both count from the probe's start
#   SERVE_RESTART  if non-empty, start the responder again after the probe exits (when the
#              first one has exited), keep it running during POST_PA, then stop it with SIGTERM;
#              its output goes to serve2.log
#   POST_PA    shell commands run in the initiator namespace after the probe exits, with
#              BIN, OUT and CFG (the initiator config dir) set; output in post_pa.log
set -eu
: "${BIN:?BIN must point at the pathtrace binary}"
: "${OUT:?OUT must be an output directory}"
PROFILE=${PROFILE:-smoke}
QDISC_AB=${QDISC_AB:-netem delay 10ms rate 20mbit limit 100}
QDISC_BA=${QDISC_BA:-netem delay 10ms rate 20mbit limit 100}
SETUP_PM=${SETUP_PM:-}
SETUP_PA=${SETUP_PA:-}
SERVE_ENV=${SERVE_ENV:-}
PROBE_ENV=${PROBE_ENV:-}
SCRIPT_PM=${SCRIPT_PM:-}
PROBE_ARGS=${PROBE_ARGS:-}
SERVE_ARGS=${SERVE_ARGS:-}
PROBE_SIGNAL_AFTER=${PROBE_SIGNAL_AFTER:-}
SERVE_SIGNAL_AFTER=${SERVE_SIGNAL_AFTER:-}
SERVE_SIGNAL=${SERVE_SIGNAL:-TERM}
SERVE_RESTART=${SERVE_RESTART:-}
POST_PA=${POST_PA:-}
RESP_ADDR=${RESP_ADDR:-10.0.2.2}
IP=ip

mount -t tmpfs none /run
for n in pa pm pb; do $IP netns add "$n"; done
$IP link add name va type veth peer name ma0
$IP link set va netns pa
$IP link set ma0 netns pm
$IP link add name vb type veth peer name mb0
$IP link set vb netns pb
$IP link set mb0 netns pm
$IP -n pa addr add 10.0.1.2/24 dev va
$IP -n pa addr add fd00:1::2/64 dev va nodad
$IP -n pa link set va up
$IP -n pa link set lo up
$IP -n pa route add default via 10.0.1.1
$IP -n pa -6 route add default via fd00:1::1
$IP -n pm addr add 10.0.1.1/24 dev ma0
$IP -n pm addr add fd00:1::1/64 dev ma0 nodad
$IP -n pm addr add 10.0.2.1/24 dev mb0
$IP -n pm addr add fd00:2::1/64 dev mb0 nodad
$IP -n pm link set ma0 up
$IP -n pm link set mb0 up
$IP -n pm link set lo up
$IP netns exec pm sysctl -qw net.ipv4.ip_forward=1
$IP netns exec pm sysctl -qw net.ipv6.conf.all.forwarding=1
$IP -n pb addr add 10.0.2.2/24 dev vb
$IP -n pb addr add fd00:2::2/64 dev vb nodad
$IP -n pb link set vb up
$IP -n pb link set lo up
$IP -n pb route add default via 10.0.2.1
$IP -n pb -6 route add default via fd00:2::1
# Real on-wire packet sizes: no segmentation or receive offloads anywhere (ethtool may be absent).
for pair in pa:va pm:ma0 pm:mb0 pb:vb; do
  ns=${pair%%:*}; dev=${pair#*:}
  $IP netns exec "$ns" ethtool -K "$dev" gso off tso off gro off >/dev/null 2>&1 || true
done
# shellcheck disable=SC2086
$IP netns exec pm tc qdisc add dev mb0 root $QDISC_AB
# shellcheck disable=SC2086
$IP netns exec pm tc qdisc add dev ma0 root $QDISC_BA
if [ -n "$SETUP_PM" ]; then $IP netns exec pm sh -c "$SETUP_PM"; fi
if [ -n "$SETUP_PA" ]; then $IP netns exec pa sh -c "$SETUP_PA"; fi
$IP netns exec pa sysctl -qw net.ipv4.ip_unprivileged_port_start=0
$IP netns exec pb sysctl -qw net.ipv4.ip_unprivileged_port_start=0

mkdir -p "$OUT/r" "$OUT/i" "$OUT/state"
$IP netns exec pb "$BIN" --config-dir "$OUT/r" keygen >/dev/null
IPUB=$($IP netns exec pa "$BIN" --config-dir "$OUT/i" keygen)
PAIR=$($IP netns exec pb "$BIN" --config-dir "$OUT/r" authorize "$IPUB" --name harness 2>/dev/null)
$IP netns exec pa "$BIN" --config-dir "$OUT/i" responder add vm "$RESP_ADDR" "$PAIR" 2>/dev/null
# shellcheck disable=SC2086
$IP netns exec pb env $SERVE_ENV "$BIN" --config-dir "$OUT/r" serve --state-dir "$OUT/state" --max-sessions 1 $SERVE_ARGS >"$OUT/serve.log" 2>&1 &
SERVE=$!
sleep 1
PM_PID=
if [ -n "$SCRIPT_PM" ]; then
  $IP netns exec pm sh -c "$SCRIPT_PM" >"$OUT/script_pm.log" 2>&1 &
  PM_PID=$!
fi
set +e
# shellcheck disable=SC2086
$IP netns exec pa env $PROBE_ENV "$BIN" --config-dir "$OUT/i" probe vm --class lab --profile "$PROFILE" --out "$OUT" $PROBE_ARGS >"$OUT/probe.out" 2>"$OUT/probe.err" &
PROBE=$!
if [ -n "$SERVE_SIGNAL_AFTER" ]; then
  (sleep "$SERVE_SIGNAL_AFTER" && kill -"$SERVE_SIGNAL" "$SERVE" 2>/dev/null) &
fi
if [ -n "$PROBE_SIGNAL_AFTER" ]; then
  (sleep "$PROBE_SIGNAL_AFTER" && kill -INT "$PROBE" 2>/dev/null) &
fi
wait "$PROBE"
echo "$?" >"$OUT/probe.exit"
SERVE2=
if [ -n "$SERVE_RESTART" ]; then
  wait "$SERVE"
  echo "$?" >"$OUT/serve.exit"
  # shellcheck disable=SC2086
  $IP netns exec pb env $SERVE_ENV "$BIN" --config-dir "$OUT/r" serve --state-dir "$OUT/state" $SERVE_ARGS >"$OUT/serve2.log" 2>&1 &
  SERVE2=$!
  sleep 1
fi
if [ -n "$POST_PA" ]; then
  $IP netns exec pa env BIN="$BIN" OUT="$OUT" CFG="$OUT/i" sh -c "$POST_PA" >"$OUT/post_pa.log" 2>&1
  echo "$?" >"$OUT/post_pa.exit"
fi
if [ -n "$SERVE2" ]; then
  kill -TERM "$SERVE2" 2>/dev/null
  wait "$SERVE2"
  echo "$?" >"$OUT/serve2.exit"
else
  wait "$SERVE"
  echo "$?" >"$OUT/serve.exit"
fi
if [ -n "$PM_PID" ]; then kill "$PM_PID" 2>/dev/null; fi
$IP netns exec pm tc -s qdisc show >"$OUT/qdisc_stats.txt" 2>&1
exit 0
