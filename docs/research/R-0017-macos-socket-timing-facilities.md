# R-0017: macOS socket, timing and host facilities for an initiator
- source: macOS SDK 27.0 headers (`sys/socket.h`, `netinet/in.h`, `netinet6/in6.h`, `netinet/tcp.h`, `netinet/udp_var.h`, `net/if_var.h`, `sys/timex.h`, `_time.h`, `sys/qos.h`, `sys/syscall.h`, IOKit `pwr_mgt/IOPMLib.h`); clock_gettime(3) and ip(4) (macOS 26.6); XNU xnu-12377.121.6 (https://github.com/apple-oss-distributions/xnu/tree/xnu-12377.121.6): `bsd/netinet/ip_input.c`, `bsd/netinet/udp_usrreq.c`, `bsd/net/if_var.h`, `bsd/sys/socket_private.h`; Linux v6.1 `include/uapi/asm-generic/socket.h`; Apple Energy Efficiency Guide for Mac Apps, https://developer.apple.com/library/archive/documentation/Performance/Conceptual/power_efficiency_guidelines_osx/Timers.html and .../PrioritizeWorkAtTheTaskLevel.html; local experiments (macOS 26.6.1, Darwin 25.6.0 arm64, uid 501, no privileges)
- accessed: 2026-10-13
- claim-under-test: macOS gives an initiator kernel RX stamps (`SO_TIMESTAMP`, `SO_TIMESTAMP_MONOTONIC`) but no kernel TX stamps; `IP_DONTFRAG`/`IPV6_DONTFRAG` but no `MSG_ERRQUEUE`/`IP_RECVERR`; `TCP_CONNECTION_INFO`; unprivileged `ntp_adjtime`; `mach_continuous_time` and `CLOCK_MONOTONIC_RAW`; timer coalescing and thread QoS; IOPM power assertions; host drop counters `udps_fullsock` and `if_data.ifi_oqdrops`; and its `SOL_SOCKET` option numbers differ from Linux (`SO_SNDBUFFORCE`=32 is `SO_BROADCAST`).
- verdict: partially-confirmed
- applicability: ADR 0014 (macOS initiator), REQ-SCOPE-009, REQ-PRB-033; the macOS backend of `pt-sys`. Refutes `ifi_oqdrops`; refines the clock claim.
## Evidence

### RX stamps, no TX stamps **[headers + source + tested]**
`sys/socket.h`: `#define SO_TIMESTAMP 0x0400 /* timestamp received dgram traffic */` and
`#define SO_TIMESTAMP_MONOTONIC 0x0800 /* Monotonically increasing timestamp on rcvd dgram */`. No
`SO_TIMESTAMPING`, `MSG_ERRQUEUE` or `IP_RECVERR` exists anywhere in the SDK's `usr/include`.
`ip_input.c`, `ip_savecontrol`: `SO_TIMESTAMP` → `getmicrotime(&tv)` (`struct timeval`, wall clock, µs);
`SO_TIMESTAMP_MONOTONIC` → `time = mach_absolute_time();` (`SCM_TIMESTAMP_MONOTONIC`, `uint64_t` ticks).
`udp_usrreq.c`, `udp_input` calls `ip_savecontrol` (line 990) just before `sbappendaddr` (line 1012): the stamp is
taken at socket enqueue in the UDP input path, not at the driver as Linux's `SOF_TIMESTAMPING_RX_SOFTWARE`.
`socket_private.h:95`: `#define SO_TIMESTAMP_CONTINUOUS 0x40000` (`mach_continuous_time`) is private, not in the SDK.
Tested: loopback UDP with both options set returned cmsgs `(SOL_SOCKET, 2, 16 B)` and `(SOL_SOCKET, 4, 8 B)`;
taking `t0 = mach_absolute_time()` after `sendto` and `t1` after `recvmsg`, the monotonic stamp was `t0 + 753`
and `t1` was `t0 + 1541` ticks.

### Clocks **[man page + headers]**
clock_gettime(3): `CLOCK_MONOTONIC` "will continue to increment while the system is asleep";
`CLOCK_MONOTONIC_RAW` tracks time "like CLOCK_MONOTONIC. However, this clock is unaffected by frequency or time
adjustments"; `CLOCK_UPTIME_RAW` "does not increment while the system is asleep. The returned value is identical
to the result of mach_absolute_time()". `mach/mach_time.h`: `mach_continuous_time` is "like mach_absolute_time,
but advances during sleep". So `SO_TIMESTAMP_MONOTONIC` is in `CLOCK_UPTIME_RAW`, and macOS
`CLOCK_MONOTONIC_RAW` (counts sleep) is not the same clock as Linux `CLOCK_MONOTONIC_RAW` (stops in suspend).
`sys/timex.h:192`: `int ntp_adjtime(struct timex *);`. Tested unprivileged with `modes = 0`: returned `TIME_OK`,
`status = 0x2081` (`STA_PLL|STA_FREQHOLD|STA_NANO`, `STA_UNSYNC` clear), `esterror`, `maxerror` and `offset` filled.

### Path MTU and per-packet IP fields **[headers + man page]**
`netinet/in.h:436` `#define IP_DONTFRAG 28`; `netinet6/in6.h:494` `#define IPV6_DONTFRAG 62`. `IP_RECVTOS` (27),
`IP_RECVTTL` (24), `IPV6_RECVTCLASS` (35) and `IPV6_RECVHOPLIMIT` (37) exist; ip(4): with `IP_RECVTOS`
"the recvmsg call will return the TOS (type of service) field of the IP header". With no error queue there is no
asynchronous per-socket ICMP "fragmentation needed" report to read.

### Batching syscalls **[headers]**
No `sendmmsg`/`recvmmsg` in the SDK; `sys/syscall.h` lists only `SYS_recvmsg_x 480` and `SYS_sendmsg_x 481`,
with no public prototype.

### TCP state **[headers]**
`netinet/tcp.h:242` `#define TCP_CONNECTION_INFO 0x106`; `struct tcp_connection_info` has `tcpi_rttcur`,
`tcpi_srtt` (ms), `tcpi_snd_cwnd`, `tcpi_txpackets`, `tcpi_txretransmitpackets`, `tcpi_rxoutoforderbytes`, flags
`TCPCI_OPT_ECN` and `TCPCI_FLAG_REORDERING_DETECTED`. Units and fields differ from Linux `TCP_INFO` (R-0012).

### Scheduling and power **[Apple docs + headers]**
Timers.html: the system will "shift the execution of timers by small amounts of time—within their tolerances";
"The system may apply a small amount of tolerance even to timers that aren't given a specified amount".
PrioritizeWorkAtTheTaskLevel.html: "The system uses QoS information to adjust priorities such as scheduling, CPU
and I/O throughput, and timer latency." `sys/qos.h:131` `QOS_CLASS_USER_INTERACTIVE = 0x21`.
`IOPMLib.h:285`: with `kIOPMAssertPreventUserIdleSystemSleep` "the system may not idle sleep. The system may still
sleep for lid close, Apple menu, low battery, or other sleep reasons."

### Host drop counters **[headers + source + tested]**
`netinet/udp_var.h:98` `u_int32_t udps_fullsock; /* not delivered, input socket full */`, incremented in
`udp_input` when `sbappendaddr` fails; read via sysctl `net.inet.udp.stats` (listed by `sysctl -N net.inet.udp`;
`netstat -s -p udp` prints it as "dropped due to full socket buffers"). It is host-wide, not per socket.
`ifi_oqdrops` is **refuted**: XNU `bsd/net/if_var.h` `struct if_data64` has `ifi_iqdrops` ("dropped on input")
and `ifi_oerrors`, but no output-queue drop field; nor does the SDK.

### SOL_SOCKET numbering **[headers + source + tested]**
macOS `SOL_SOCKET` is `0xffff`, `SO_BROADCAST 0x0020`, `SO_SNDBUF 0x1001`. Linux v6.1 asm-generic:
`SO_BROADCAST 6`, `SO_SNDBUFFORCE 32`. Tested: `setsockopt(SOL_SOCKET, 32, 1)` on macOS succeeds and
`getsockopt(SOL_SOCKET, SO_BROADCAST)` then reads 32: a Linux option number passed through enables broadcast.

## Implications for PTF / probe
- TX times on macOS are user-space stamps next to the send call; RX times are kernel stamps taken at socket
  enqueue (`SO_TIMESTAMP` wall clock, or `SO_TIMESTAMP_MONOTONIC` in `CLOCK_UPTIME_RAW`). PTF already keeps the
  user-space TX time (`tx_intended`, `tx_user_lag`) beside nullable kernel TX stamps (`tx_sched`), records the RX
  stamp source per packet (`rx_src`) and declares each time column's clock domain (ptf-format.md §6), so the
  per-packet timestamp columns need no format change.
- Not observable on macOS, so recorded as unknown, never zero: kernel TX stamps, error-queue PMTU and send-error
  reports, per-socket receive drops (only host-wide `udps_fullsock`), egress qdisc and output-queue drops.
- `pt-sys` must use the platform's own constants (from `libc`), never Linux numbers, behind `cfg(target_os)`.
- The pacer thread needs `QOS_CLASS_USER_INTERACTIVE` and a power assertion; lid-close sleep is still possible
  and must be detected as a suspend (REQ-PRB-032).
