# R-0016: Reading NIC offload features unprivileged, and which offloads reach the probe's sockets
- source: net/ethtool/ioctl.c, net/ipv4/udp_offload.c, net/core/skbuff.c (Linux v7.2, https://github.com/torvalds/linux/tree/v7.2); ethtool(8) 7.1; local experiment (unprivileged uid 2001)
- accessed: 2026-10-12
- claim-under-test: `SIOCETHTOOL` with `ETHTOOL_GSSET_INFO`, `ETHTOOL_GSTRINGS` and `ETHTOOL_GFEATURES` reads every interface feature without CAP_NET_ADMIN, matching `ethtool -k`; of the receive offloads, only fraglist GRO (`rx-gro-list`) coalesces datagrams delivered to a local UDP socket without `UDP_GRO`, and the datagrams it coalesces share one receive timestamp.
- verdict: confirmed
- applicability: `pathtrace doctor` offload check (REQ-PRB-025); the probe's per-packet RX stamps (REQ-PRB-008, REQ-PRB-017, R-0011).
## Evidence

### Unprivileged read **[source + tested]**
`net/ethtool/ioctl.c`, `dev_ethtool_locked`: a switch headed `/* Allow some commands to be done by anyone */`
lists the read commands, including `ETHTOOL_GSSET_INFO`, `ETHTOOL_GSTRINGS` and `ETHTOOL_GFEATURES`; any other
command reaches `default: if (!ns_capable(net->user_ns, CAP_NET_ADMIN)) return -EPERM;`.
`ethtool_get_features` fills one `{available, requested, active, never_changed}` block per 32 features from
`hw_features`, `wanted_features`, `features` and `NETIF_F_NEVER_CHANGE`, and clamps the caller's `size`:
`if (copy_size > ETHTOOL_DEV_FEATURE_WORDS) copy_size = ETHTOOL_DEV_FEATURE_WORDS;`.

Tested with `crates/pt-sys/src/ethtool.rs` (Fedora 44, kernel 7.2.4, uid 2001, no capabilities) on `lo`, a
Wi-Fi interface (`wlp13s0`), an Intel Ethernet interface (`enp8s0`) and `tailscale0` (tun): 192 feature lines,
names, `on`/`off`, `[fixed]` (= not available, or never changed) and `[requested on]` identical to `ethtool -k`
(which prints aliases such as `generic-receive-offload` for the kernel name `rx-gro`). `enp8s0` had
`rx-lro: on` by default.

### Which receive offloads reach a local UDP socket **[source]**
`net/ipv4/udp_offload.c`, `udp_gro_receive`, for a socket that is not a tunnel:
```
if (skb->dev->features & NETIF_F_GRO_FRAGLIST)
	NAPI_GRO_CB(skb)->is_flist = sk ? !udp_test_bit(GRO_ENABLED, sk) : 1;
if ((!sk && (skb->dev->features & NETIF_F_GRO_UDP_FWD)) ||
    (sk && udp_test_bit(GRO_ENABLED, sk)) || NAPI_GRO_CB(skb)->is_flist)
	return call_gro_receive(udp_gro_receive_segment, head, skb);
```
* `rx-udp-gro-forwarding` (`NETIF_F_GRO_UDP_FWD`) applies only with no local socket (`!sk`): forwarded traffic.
* `rx-gro-list` (`NETIF_F_GRO_FRAGLIST`) applies to a local socket *without* `UDP_GRO`, which is the probe's.
* Plain `rx-gro` does not coalesce UDP for such a socket (R-0011: one datagram per recv).

### Coalesced datagrams share the head's timestamp **[source]**
`net/core/skbuff.c`, `skb_segment_list` (splitting a fraglist GRO packet before delivery) calls
`__copy_skb_header(nskb, skb);` for every segment, and `__copy_skb_header` starts with
`new->tstamp = old->tstamp;`. So every datagram of one fraglist-GRO batch carries the batch head's software RX
timestamp: inter-arrival times inside the batch read as zero.

### TCP
`rx-gro`, `rx-gro-hw` and `rx-lro` merge TCP segments before the receiving socket sees them, so the receiver
acknowledges per merged packet (stretch ACKs), which the sender's `TCP_INFO` (RTT samples, delivery rate)
reflects. The probe records TCP class probes and reference flows through `TCP_INFO` only (probe.md), not per
segment. GRO is on by default on every interface tested; LRO was on for one.

## Implications for PTF / probe
- `pt-sys` reads offloads with the ioctl: no capability, no generic-netlink family lookup, no new dependency.
- `doctor` warns on `rx-gro-list` (it changes the probe's UDP RX stamps) and on `rx-lro` (the NIC merges TCP
  segments without keeping each one's headers, unlike GRO and `rx-gro-hw`, which are built to be reversible, so
  the TCP the reference flows measure is not the one a host normally runs). `rx-gro`,
  `rx-gro-hw`, `rx-udp-gro-forwarding` and the segmentation offloads are reported, not warned: they leave the
  probe's UDP 1:1 (the probe never sets `UDP_GRO` or `UDP_SEGMENT`) and are what a deployed TCP stack runs with.
- Nothing in PTF changes.
