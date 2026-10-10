# R-0010: Kernel packet timestamps (SO_TIMESTAMPING) and their clock
- source: https://docs.kernel.org/networking/timestamping.html ; include/uapi/linux/net_tstamp.h and include/linux/skbuff.h (torvalds/linux v7.2); local experiments (kernel 7.2.4, veth in unprivileged netns, ath12k Wi-Fi)
- accessed: 2026-10-10
- claim-under-test: SO_TIMESTAMPING gives per-packet kernel TX and RX stamps for UDP, usable unprivileged, in a monotonic clock.
- verdict: partially-confirmed
- applicability: Core to probe accuracy (REQ-PRB-008) and to PTF clock-domain design (ADR 0012). Refutes the monotonic part: software stamps are CLOCK_REALTIME only.
## Evidence

Tested on Fedora 44, kernel 7.2.4, rustc 1.99; experiment programs were throwaway (not committed).

### 1. SO_TIMESTAMPING on UDP

#### Flags (uapi `linux/net_tstamp.h`, kernel 7.2)

| Flag | Bit | Meaning | Since |
|---|---|---|---|
| TX_HARDWARE | 1<<0 | generate HW TX stamp | 2.6.30 |
| TX_SOFTWARE | 1<<1 | generate SW TX stamp at driver xmit (`skb_tx_timestamp()`), reported as `SCM_TSTAMP_SND` | 2.6.30 |
| RX_HARDWARE | 1<<2 | | |
| RX_SOFTWARE | 1<<3 | generate SW RX stamp (early in `netif_receive_skb`) | |
| SOFTWARE | 1<<4 | *report* SW stamps (in ts[0]); needed with both RX_SOFTWARE and TX_* | |
| RAW_HARDWARE | 1<<6 | report HW stamps (ts[2]) | |
| OPT_ID | 1<<7 | put a per-socket counter in `ee_data` (UDP: +1 per sendmsg/datagram) | 3.17 |
| TX_SCHED | 1<<8 | stamp at qdisc enqueue (`SCM_TSTAMP_SCHED`) | 3.17 |
| TX_ACK | 1<<9 | TCP only | 3.17 |
| OPT_CMSG | 1<<10 | IPv4 errqueue: add IP_PKTINFO (needs the payload, so it is **useless with TSONLY**; tested, no pktinfo appeared) | 4.0 |
| OPT_TSONLY | 1<<11 | errqueue skb has no payload (len 0); avoids copying the packet back and lets unprivileged code read stamps without `sysctl net.core.tstamp_allow_data` | 4.1 |
| OPT_STATS | 1<<12 | TCP | 4.10 |
| OPT_PKTINFO | 1<<13 | RX: SCM_TIMESTAMPING_PKTINFO (HW only) | 4.13 |
| OPT_TX_SWHW | 1<<14 | both SW and HW TX | 4.13 |
| BIND_PHC | 1<<15 | PTP vclock binding (`struct so_timestamping{flags,bind_phc}`); **irrelevant** | 5.14/5.15 |
| OPT_ID_TCP | 1<<16 | TCP | 6.2-ish (present in v6.6 tag) |
| OPT_RX_FILTER | 1<<17 | only report RX stamps if this socket asked for RX generation (stops "spurious" RX stamps that appear because another socket enabled RX stamping). Harmless; **irrelevant** for us since we request RX | 6.12 |
| TX_COMPLETION | 1<<18 | stamp at driver TX-completion report; **veth: no stamps produced [tested]** | 6.15 |

Related control messages: `SCM_TS_OPT_ID` (81, kernel 6.13) on `sendmsg` overrides the ID for that
packet (not TCP). An `SO_TIMESTAMPING` cmsg on sendmsg carrying TX_* generation flags
asks for a stamp on that one packet. **[tested]** On loopback, with socket-level flags set to
`SOFTWARE|OPT_ID|OPT_TSONLY` only, a TX_SOFTWARE cmsg on packets 0 and 2 and SCM_TS_OPT_ID=1000+i produced exactly
two stamps with ids 1000 and 1002. `recvmmsg(..., MSG_ERRQUEUE|MSG_DONTWAIT)` drains several
stamps per syscall **[tested]**.

#### Reading TX stamps

* `poll()` reports `POLLERR` when the error queue is non-empty. Then
  `recvmsg(fd, MSG_ERRQUEUE|MSG_DONTWAIT)`; `msg_flags` has `MSG_ERRQUEUE` (0x2000). Payload length
  is 0 with TSONLY.
* cmsgs: `SOL_SOCKET/SCM_TIMESTAMPING` (`struct scm_timestamping { struct timespec ts[3]; }`,
  ts[0]=SW, ts[2]=HW raw), plus `SOL_IP/IP_RECVERR` (or `SOL_IPV6/IPV6_RECVERR`) carrying
  `struct sock_extended_err` with `ee_errno=ENOMSG(42)`, `ee_origin=SO_EE_ORIGIN_TIMESTAMPING(4)`,
  `ee_info=SCM_TSTAMP_SND(0)|SCHED(1)|ACK(2)|COMPLETION(3)`, `ee_data=OPT_ID`.
* You do **not** need `IP_RECVERR` enabled to receive timestamp errqueue entries (tested: the
  timestamping client never set it). You do need it for ICMP errors (see section 4).
* Order observed: SCHED arrives before SND for each packet.

Verbose trace (veth, two netns) **[tested]**:
```
SO_TIMESTAMPING readback=0x99a
errq pkt i=0 len=0 flags=0x2000
  ee errno=42 origin=4 info=1 data=0      <- SCHED
errq pkt i=0 len=0 flags=0x2000
  ee errno=42 origin=4 info=0 data=0      <- SND
```

#### Which devices produce SND stamps (`ethtool -T`, plus experiment)

| Device | software-transmit | Observed |
|---|---|---|
| veth | yes | SND+SCHED for 2000/2000 packets |
| lo | yes | SND+SCHED |
| enp14s0 (r8169) | yes | (link down, not tested) |
| enp8s0 (atlantic) | yes, plus HW PHC (RX filters ptpv2 only, so no HW RX for arbitrary UDP) | (link down) |
| **wlp13s0 (ath12k_wifi7_pci)** | **no** | **SCHED only, 0/10 SND** (UDP to 192.0.2.1 via WiFi) |
| tailscale0 (tun) | yes | |

So the probe must treat SND as optional. Order of preference: SND, then SCHED, then the userspace
pre-send clock. Record which source was used for each sample.

#### netem on egress shows SND is post-qdisc **[tested]**
With `tc qdisc add dev v0 root netem delay 5ms` on the sender side:
```
TX SCHED - user_before_send  p50=3730 ns
TX SND   - user_before_send  p50=5007657 ns      <- includes the 5 ms qdisc delay
RTT kernel (rx - snd)        p50=23680 ns         <- excludes local qdisc
RTT user                     p50=5042367 ns
```

#### Measured distributions (N=2000, 1 ms spacing, idle desktop) **[tested]**
Values are ns. "user_after_recv - RX stamp" = `clock_gettime(REALTIME)` right after `recvmsg` returns,
minus the kernel RX stamp.

veth between two netns, SO_TIMESTAMPING:
```
TX SCHED - user_before_send  min=1050 p50=1390 p90=3140 p99=4630 max=24220
TX SND - user_before_send    min=1360 p50=1790 p90=4060 p99=5870 max=25080
user_after_recv - RX stamp   min=3010 p50=6760 p90=9130 p99=13640 max=146510
RTT kernel (rx-snd)          min=6510 p50=8960 p90=13490 p99=19700 max=413860
RTT user                     min=12830 p50=17940 p90=24980 p99=34640 max=430230
```
veth, `SO_TIMESTAMPNS` fallback (RX only):
```
user_after_recv - RX stamp   min=4820 p50=7810 p90=9770 p99=14860 max=976019
```
loopback (no netns):
```
TX SND - user_before_send    p50=5050 p99=8470
user_after_recv - RX stamp   min=5160 p50=10150 p99=17800 max=620080
RTT kernel p50=17650 p99=58970   RTT user p50=32710 p99=109410
```
Takeaway: kernel stamps cut about 9 µs median and about 15-50 µs p99 off the userspace RTT. Userspace
wakeup tails reach 0.1-2 ms; kernel stamps remove them. SO_TIMESTAMPNS gives the same RX
stamp quality (same `skb->tstamp`) but has no TX side.

#### Hardware stamps
* `SIOCGHWTSTAMP` works unprivileged (returns EOPNOTSUPP where unsupported; `ok` on atlantic).
* `SIOCSHWTSTAMP` returns **EPERM** unprivileged **[tested]**. Source `net/core/dev_ioctl.c`:
  `case SIOCSHWTSTAMP: if (!ns_capable(net->user_ns, CAP_NET_ADMIN)) return -EPERM;`. Configuring
  it is also global for the NIC, and most NICs only filter PTP. Not worth pursuing for v1.

#### C core (from `ts.c`, tested)
```c
unsigned fl = SOF_TIMESTAMPING_RX_SOFTWARE|SOF_TIMESTAMPING_TX_SOFTWARE|SOF_TIMESTAMPING_TX_SCHED|
              SOF_TIMESTAMPING_SOFTWARE|SOF_TIMESTAMPING_OPT_ID|SOF_TIMESTAMPING_OPT_TSONLY;
setsockopt(s, SOL_SOCKET, SO_TIMESTAMPING, &fl, sizeof fl);
/* ... after POLLERR: */
struct msghdr em = {.msg_iov=&iov,.msg_iovlen=1,.msg_control=cb,.msg_controllen=sizeof cb};
recvmsg(s, &em, MSG_ERRQUEUE|MSG_DONTWAIT);
for (c = CMSG_FIRSTHDR(&em); c; c = CMSG_NXTHDR(&em, c)) {
  if (c->cmsg_level==SOL_SOCKET && c->cmsg_type==SO_TIMESTAMPING)
      t = ((struct scm_timestamping*)CMSG_DATA(c))->ts[0];
  if (c->cmsg_level==IPPROTO_IP && c->cmsg_type==IP_RECVERR) {   /* IPV6_RECVERR on v6 */
      struct sock_extended_err *e = (void*)CMSG_DATA(c);
      kind = e->ee_info; id = e->ee_data; }
}
```

#### Rust with nix 0.31.3 (tested, loopback)
```rust
use nix::sys::socket::*;
let flags = TimestampingFlag::from_bits_retain(   // nix lacks TX_SCHED etc. as named flags
    libc::SOF_TIMESTAMPING_TX_SOFTWARE | libc::SOF_TIMESTAMPING_TX_SCHED | libc::SOF_TIMESTAMPING_RX_SOFTWARE
  | libc::SOF_TIMESTAMPING_SOFTWARE | libc::SOF_TIMESTAMPING_OPT_ID | libc::SOF_TIMESTAMPING_OPT_TSONLY);
setsockopt(&cli, sockopt::Timestamping, &flags)?;
let tos: u8 = (34 << 2) | 1;                       // AF41 + ECT(1), per packet
sendmsg::<()>(fd, &[IoSlice::new(&buf)], &[ControlMessage::Ipv4Tos(&tos)], MsgFlags::empty(), None)?;
let mut cbuf = nix::cmsg_space!([libc::timespec; 3], libc::sock_extended_err, libc::sockaddr_in);
let msg = recvmsg::<()>(fd, &mut iov, Some(&mut cbuf), MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT)?;
for c in msg.cmsgs()? { match c {
    ControlMessageOwned::ScmTimestampsns(t) => ts = Some(t.system),
    ControlMessageOwned::Ipv4RecvErr(e, _) => { kind = e.ee_info; id = e.ee_data; } // origin == SO_EE_ORIGIN_TIMESTAMPING
    _ => {} } }
```
Output: `errqueue stamp kind=1 opt_id=0`, then `kind=0 opt_id=0`. Server side cmsgs:
`[ScmTimestampsns(..), Ipv4Ttl(64), Ipv4Tos(137)]` (137 = 0x89 = AF41|ECT(1)).

libc 0.2.190 has every `SOF_TIMESTAMPING_*` except `TX_COMPLETION`, and has `sock_extended_err`
and `SO_EE_ORIGIN_TIMESTAMPING`. It does **not** have `struct scm_timestamping`, the `SCM_TSTAMP_*`
enum, or `SCM_TS_OPT_ID` (generic arch). Define these yourself: `[timespec;3]`, 0/1/2/3, 81.

---

### 2. Clock correlation (CLOCK_REALTIME stamps -> CLOCK_MONOTONIC_RAW)

* Software stamps come from `ktime_get_real()`: `include/linux/skbuff.h` v7.2
  `__net_timestamp(){ skb->tstamp = ktime_get_real(); skb->tstamp_type = SKB_CLOCK_REALTIME; }`.
  `__skb_tstamp_tx()` (net/core/skbuff.c) calls `__net_timestamp()` for TX. Empirically the stamps
  sit within a few µs of userspace `CLOCK_REALTIME` (section 1 tables).
* SO_TIMESTAMPING has **no** clock selector. Only HW stamps (PHC clock, optional `BIND_PHC`) differ.
  `SO_TXTIME` takes a `clockid` (`CLOCK_TAI`/`MONOTONIC`), but that sets the departure time for the
  ETF/FQ qdiscs, not the reported stamps. The internal `skb->tstamp_type` MONO/TAI applies only to
  forwarding and EDT and never reaches sockets. **Verified: no monotonic or TAI software stamps.**
* Technique: sandwich `raw0 = MONO_RAW; real = REALTIME; raw1 = MONO_RAW`, keep the sample with the
  smallest `raw1-raw0`, and set `offset = real - (raw0+raw1)/2`. **[tested]** (clocksource tsc, vDSO):
  * clock_gettime cost: REALTIME 17.0 ns, MONO_RAW 17.7 ns
  * sandwich width: min 29-30 ns, max 40 ns (K=1); K=64 always gives 29-30 ns. So K=8 is plenty.
  * REALTIME-MONO_RAW offset drifts **+3.64 ppm** linearly (chrony was disciplining the frequency,
    `Frequency: 3.430 ppm slow`). Over a 1 s RTT window that is under 4 µs. For long sessions,
    re-sample the offset every second or so and interpolate. Treat jumps much larger than the ppm
    slope as clock steps and flag the affected samples.
* Practical rule: compute kernel-to-kernel intervals (rx_stamp - snd_stamp) directly in REALTIME;
  the error is ppm-level slew. Convert to MONO_RAW only to line samples up with other monotonic data.
* `CLOCK_TAI - CLOCK_REALTIME` read **36 s** on this host (chrony's TAI offset; should be 37).
  Do not rely on it.

---

## Implications for PTF / probe
- Store kernel stamps raw in the REALTIME domain and log MONO_RAW/REALTIME pairs (~1 Hz, min-width sandwich of 8) to undo slews and steps later (ADR 0012).
- Log both SCHED and SND TX stamps when present; Wi-Fi often gives SCHED only. Record per packet which is present.
- OPT_ID + OPT_TSONLY lets unprivileged code match TX stamps to packets.
- Hardware stamps require CAP_NET_ADMIN: optional only.
