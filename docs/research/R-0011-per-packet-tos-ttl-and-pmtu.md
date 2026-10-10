# R-0011: Per-packet ECN/DSCP/TTL via sendmmsg/recvmmsg cmsgs; path MTU signalling
- source: ip(7), ipv6(7), udp(7) man pages; net/ipv4/ip_sockglue.c (v7.2); local experiments (client-router-server namespaces, router MTU 1300)
- accessed: 2026-10-10
- claim-under-test: Per-packet TOS/TCLASS and TTL can be set and observed with mmsg cmsgs; ICMP Packet Too Big is observable per probe via the error queue; GSO/GRO can be kept off.
- verdict: confirmed
- applicability: ECN/DSCP handling, hop count, PMTU and black-hole detection (REQ-PRB-015, REQ-PRB-017).
## Evidence

Tested on Fedora 44, kernel 7.2.4, rustc 1.99; experiment programs were throwaway (not committed).

### 3. sendmmsg/recvmmsg with per-message cmsgs (ECN/DSCP/TTL) **[tested]**

Topology: client netns, then router (outer netns), then server netns. Server uses `recvmmsg` (batch 8) on
v4 and v6 sockets with `IP_RECVTOS`, `IP_RECVTTL`, `IPV6_RECVTCLASS`, `IPV6_RECVHOPLIMIT`. Client uses `sendmmsg` with 4
messages, each with its own TOS/TCLASS cmsg `(46<<2)|i` (EF + ECN i) and TTL/HOPLIMIT cmsg `10+i`:
```
recvmmsg fam=v4 got 4 msgs
  msg 0 len=100 tos/tclass=0xb8 (dscp=46 ecn=0) ttl/hlim=9      <- router decremented 10 -> 9
  msg 1 len=100 tos/tclass=0xb9 (dscp=46 ecn=1) ttl/hlim=10
  msg 2 len=100 tos/tclass=0xba (dscp=46 ecn=2) ttl/hlim=11
  msg 3 len=100 tos/tclass=0xbb (dscp=46 ecn=3) ttl/hlim=12
recvmmsg fam=v4 got 1 msgs
  msg 0 len=1 tos/tclass=0xb9 (dscp=46 ecn=1) ttl/hlim=63      <- per-socket IP_TOS=0xb9
recvmmsg fam=v6 got 5 msgs   (identical pattern for IPV6_TCLASS / IPV6_HOPLIMIT)
```
Notes:
* RX `IP_TOS` cmsg payload is **1 byte** (`u8`). `IP_TTL`, `IPV6_TCLASS` and `IPV6_HOPLIMIT` payloads are `int`.
* TX `IP_TOS` cmsg accepts `int` or `u8`. ECN bits pass through for UDP: CE (3) was sent and
  received unchanged on veth/forwarding. Per-socket `IP_TOS`/`IPV6_TCLASS` also keep ECN bits for UDP.
  (TCP masks the ECN bits itself.)
* Per-packet ECN cycling 0..3 via cmsg on veth (single hop) matched 8/8 **[tested]**.
* Echo design: the reflector should report what it **received** (TOS byte, TTL) in the reply
  payload. That gives forward-path ECN bleaching/remarking and hop count. The client's own RX cmsgs
  give the same for the reverse path.

---

### 4. Path MTU

Setup: client -> router (rs link MTU 1300) -> server. Socket connected, `IP_RECVERR`/`IPV6_RECVERR`=1,
payload 1450. **[tested]** output:
```
[v4 do]    iter 0: IP_MTU before=1500 send(1450)=1450
  errqueue: payload_len=520 ee_errno=90(EMSGSIZE) origin=2(ICMP) type=3 code=4 ee_info(mtu)=1300 offender=10.1.0.1
[v4 do]    iter 1: IP_MTU before=1300 send(1450)=-1 Message too long
  errqueue: payload_len=0 ee_errno=90 origin=1(LOCAL) ee_info(mtu)=1300      <- local error is ALSO queued
[v4 probe] iter 0..3: IP_MTU before=1300 send(1450)=1450 (every time)
  errqueue: ... origin=2 type=3 code=4 ee_info(mtu)=1300 offender=10.1.0.1  (every time)
  send(3000 > dev mtu)=-1 EMSGSIZE ; errqueue origin=1 ee_info=1500 (device MTU)
[v6 do]    iter 0: IPV6_MTU before=1500 send=1450 ; errqueue origin=3(ICMP6) type=2 code=0 ee_info=1300 offender=fd01::1
[v6 probe] same as v4 probe (ICMPv6 PTB every time)
```
Semantics:
* `IP_PMTUDISC_DO`: DF set, the kernel enforces the cached PMTU, and sends above it fail locally with EMSGSIZE.
  Each failure also queues a LOCAL errqueue entry that you must drain.
* `IP_PMTUDISC_PROBE`: DF set, but the cached PMTU is **ignored** (only the device MTU applies). This is the right
  mode for active PLPMTUD-style probing: each oversize probe reaches the bottleneck, and you get a fresh
  ICMP error each time (subject to router ICMP rate limiting). `IP_MTU` still reports the cached PMTU.
* The kernel PMTU cache is per-destination (a route exception) and **shared across sockets/processes**.
  The v4 probe run started with `IP_MTU=1300`, learned by the previous socket. It expires after
  `net.ipv4.route.mtu_expires` (600 s default).
* `IP_MTU`/`IPV6_MTU` getsockopt works only on **connected** sockets (ENOTCONN otherwise).
* The ICMP-quoted payload comes back in the errqueue data (v4: 520 bytes here; v6: 1184). Use it to match
  the probe (sequence number in the first bytes). `SO_EE_OFFENDER(ee)` gives the router address.
* IPv6: `IPV6_MTU_DISCOVER` with `IPV6_PMTUDISC_DO/PROBE` (same values 2/3), plus `IPV6_DONTFRAG=1`
  for unconnected/cmsg use. Errors arrive with cmsg level `SOL_IPV6`, type `IPV6_RECVERR`.
* Also: `IP_PMTUDISC_INTERFACE` (4) / `OMIT` (5) exist (for DNS servers); we do not need them.
* Black-hole paths (no ICMP) are handled only by search with timeouts: send sizes, see which
  echoes come back. PROBE mode allows this.
* GSO/GRO: `getsockopt(UDP_GRO)` = 0 by default on v4 and v6 **[tested]**. Without `UDP_GRO` on the socket,
  the kernel segments any GRO'd UDP before delivery, so one datagram = one recv. Never set `UDP_SEGMENT`
  (send-side GSO); then each `sendmmsg` entry is one wire datagram, and per-packet TX stamps and IDs stay 1:1.

---

## Implications for PTF / probe
- Light-flow packets cycle the TOS byte per packet (cmsg); the receiver logs received TOS and TTL per packet.
- PMTU search uses IP_PMTUDISC_PROBE + IP_RECVERR; each oversize probe yields an ICMP error carrying the MTU and quoted payload (match by sequence number). No ICMP + no echo = black hole.
- Never set UDP_SEGMENT/UDP_GRO, so one sendmmsg entry is one datagram, keeping TX stamps 1:1.
