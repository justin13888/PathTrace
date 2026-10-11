# R-0015: OPT_ID on send errors, socket receive drops, qdisc and UDP drop counters
- source: torvalds/linux v6.1 and v6.13 `net/ipv4/ip_output.c` (`__ip_append_data`); v6.13 `net/core/sock.c` (`__sock_cmsg_send`); v6.13 `Documentation/networking/timestamping.rst`; v6.1 `net/socket.c` (`sock_recv_drops`), `include/net/sock.h` (`sock_skb_set_dropcount`), `net/ipv4/udp.c` (`__udp_enqueue_schedule_skb`); v6.1 `include/uapi/linux/gen_stats.h`, `include/uapi/linux/rtnetlink.h`; Fedora 44 `/usr/include/asm-generic/socket.h`
- accessed: 2026-10-11
- claim-under-test: (1) A UDP datagram whose send fails does not consume an OPT_ID, so a user-space counter advanced only on success predicts every TX timestamp id. (2) Drops at the receiving socket and in the local egress qdisc are observable without privileges.
- verdict: partially-confirmed ((1) is refuted below 6.13 and holds only for errors before the append stage from 6.13; (2) is confirmed)
- applicability: TX stamps are joined to transmissions by OPT_ID (probe.md §5), so a wrong prediction silently attaches wrong `tx_sched` values. Host drops that are not recorded are indistinguishable from path loss in the raw layer, which cannot be corrected later (ADR 0008).
## Evidence

### 1. OPT_ID on failed sends
v6.1 `__ip_append_data` takes the key before any check that can fail:
```c
if (cork->tx_flags & SKBTX_ANY_SW_TSTAMP &&
    sk->sk_tsflags & SOF_TIMESTAMPING_OPT_ID)
	tskey = atomic_inc_return(&sk->sk_tskey) - 1;
```
The EMSGSIZE return and the `error:` label (reached on `sock_alloc_send_skb` failure: EAGAIN when the send buffer is full, or a pending `sk_err` from an earlier ICMP error, which `sock_error()` returns once) never decrement `sk_tskey`. So on 6.1–6.12 every append-stage error consumes a key.

v6.13 restores it:
```c
	} else {
		tskey = atomic_inc_return(&sk->sk_tskey) - 1;
		hold_tskey = true;
	...
	if (hold_tskey)
		atomic_dec(&sk->sk_tskey);
```
Errors after the append stage still consume the key on every kernel. For example, a qdisc drop returns ENOBUFS when `IP_RECVERR` is set, and a netfilter drop returns EPERM. The SCHED stamp is taken before the qdisc enqueue, so a dropped datagram can still produce one.

v6.13 also adds `SCM_TS_OPT_ID` (value 81 in asm-generic `socket.h`). `__sock_cmsg_send` accepts it only for non-TCP sockets that have `SOF_TIMESTAMPING_OPT_ID` set, and only when `cmsg_len == CMSG_LEN(sizeof(u32))`. The `default:` case returns `-EINVAL`, so older kernels reject the cmsg before any key is taken. timestamping.rst: "The process can optionally override the default generated ID, by passing a specific ID with control message SCM_TS_OPT_ID". R-0010 tested the override on 7.2.

`sendmmsg` returns the number of datagrams sent before the first failure. It reports an errno only when the first datagram fails, so after a partial return the errno of the failed datagram is unknown.

### 2. Socket receive drops (SO_RXQ_OVFL = 40)
```c
SOCK_SKB_CB(skb)->dropcount = sock_flag(sk, SOCK_RXQ_OVFL) ?
					atomic_read(&sk->sk_drops) : 0;
```
`__udp_enqueue_schedule_skb` calls this. Its `drop:` path, taken when `rmem > sk->sk_rcvbuf`, does `atomic_inc(&sk->sk_drops)`. `sock_recv_drops` emits the cmsg only `if (sock_flag(sk, SOCK_RXQ_OVFL) && skb && SOCK_SKB_CB(skb)->dropcount)`. The value is the socket's cumulative drop count when the datagram was queued; when the option is on, a missing cmsg means 0. `SO_RCVBUF` is capped by `net.core.rmem_max`; `SO_RCVBUFFORCE` (33) bypasses the cap with CAP_NET_ADMIN.

### 3. Qdisc and stack counters
`RTM_GETQDISC` = 38, with a `struct tcmsg` header (family, pad, ifindex, handle, parent, info). Attributes: `TCA_KIND` = 1 (string) and `TCA_STATS2` = 7, which nests `TCA_STATS_BASIC` = 1 (`struct gnet_stats_basic { __u64 bytes; __u32 packets; }`) and `TCA_STATS_QUEUE` = 3 (`struct gnet_stats_queue { __u32 qlen, backlog, drops, requeues, overlimits; }`). A dump is unprivileged. `/proc/net/snmp` (`Udp:` InErrors, RcvbufErrors, SndbufErrors, InCsumErrors) and `/proc/net/snmp6` (`Udp6RcvbufErrors` …) are per network namespace. `/proc/net/softnet_stat` column 2 counts backlog drops per CPU.

## Implications for PTF / probe
- On kernels ≥ 6.13, set the id of every datagram with `SCM_TS_OPT_ID`. A failed attempt burns its own id, and the join is exact. Detect support from the kernel version, and fall back if the first send returns EINVAL.
- On older kernels, predict ids and treat every send error as having consumed a key, except errors raised before the append stage (route lookup or argument errors). Record each failure, with its assumed id, as an event, so that a later merge can re-anchor ids using timestamps. Keep TX stamps that match no transmission.
- Record the socket drop count per received datagram (`rxq_drops`) so that derivation can exclude losses at the receiver's host. Sample UDP stack, softnet and egress qdisc counters on both endpoints.
