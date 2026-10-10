# R-0012: TCP_INFO layout across kernels, TCP_CONGESTION, TCP_SAVED_SYN
- source: include/uapi/linux/tcp.h diffed across tags v4.9 … v7.2; net/ipv4/tcp.c do_tcp_setsockopt; libc 0.2.190 source; local experiments
- accessed: 2026-10-10
- claim-under-test: TCP_INFO can be read via libc::tcp_info; TCP_SAVED_SYN needs privileges.
- verdict: refuted
- applicability: Reference flows record TCP_INFO every 10 ms (REQ-PRB-012); proxy detection compares SYNs (REQ-DRV-015).
## Evidence

Tested on Fedora 44, kernel 7.2.4, rustc 1.99; experiment programs were throwaway (not committed).

### 5. TCP

#### struct tcp_info: field and kernel version (diffed from `include/uapi/linux/tcp.h` at tags)

| Fields | Type | Since |
|---|---|---|
| state, ca_state, retransmits, probes, backoff, options, snd_wscale:4/rcv_wscale:4 | u8 | 2.6 |
| rto, ato, snd_mss, rcv_mss, unacked, sacked, lost, retrans, fackets, last_data_sent, last_ack_sent, last_data_recv, last_ack_recv, pmtu, rcv_ssthresh, rtt, rttvar, snd_ssthresh, **snd_cwnd**, advmss, reordering, rcv_rtt, rcv_space, **total_retrans** | u32 | 2.6 |
| pacing_rate, max_pacing_rate | u64 | 3.15 |
| **bytes_acked**, bytes_received | u64 | 4.1 |
| segs_out, segs_in | u32 | 4.2 |
| notsent_bytes, **min_rtt**, data_segs_in, data_segs_out | u32 | 4.6 |
| **delivery_rate** (u64), delivery_rate_app_limited:1 (bitfield in byte 7) | | 4.9 |
| **busy_time, rwnd_limited, sndbuf_limited** (µs) | u64 | 4.10 |
| delivered, delivered_ce | u32 | 4.18 |
| bytes_sent, **bytes_retrans** (u64), **dsack_dups**, **reord_seen** (u32) | | 4.19 |
| **rcv_ooopack**, **snd_wnd** | u32 | 5.4 |
| fastopen_client_fail:2 (byte 7 bitfield) | | 5.5 |
| **rcv_wnd**, **rehash** | u32 | **6.2** |
| **total_rto**, total_rto_recoveries (u16), total_rto_time (u32 ms) | | **6.7** |
| received_ce, delivered_e1/e0/ce_bytes, received_e1/e0/ce_bytes (u32); accecn_fail_mode, accecn_opt_seen (**u16 each**) | | 6.18 |
| last word redefined as `ecn_mode:2, accecn_opt_seen:2, accecn_fail_mode:4, options2:24` (u32 bitfield) | | **7.0** |

`tcpi_options` bits: TIMESTAMPS 1, SACK 2, WSCALE 4, ECN 8, ECN_SEEN 16, SYN_DATA 32,
USEC_TS 64 (6.7), TFO_CHILD 128 (6.18).

* sizeof = **280** on 7.2. The kernel copies `min(optlen, sizeof)` and writes back the length (tested:
  104 in, 104 out). **Always zero the struct and check the returned optlen.** On 6.1 you get a
  shorter struct, and fields past it stay 0.
* `libc::tcp_info` (gnu, libc 0.2.190) = glibc 2.43 layout = **6.18 layout** (u16 accecn fields, 280
  bytes). It packs `snd_wscale/rcv_wscale` into `tcpi_snd_rcv_wscale` and does **not expose** the
  `delivery_rate_app_limited`/`fastopen_client_fail` byte (it becomes padding). The musl variant stops at
  `tcpi_snd_wnd`. Recommendation: define your own `#[repr(C)] struct TcpInfo` up to
  `tcpi_total_rto_time` (6.7) or `received_ce_bytes`, expose byte 7 as a raw u8, and record
  the returned optlen so consumers know which fields are valid.
* glibc's `<netinet/tcp.h>` and `<linux/tcp.h>` conflict in C (redefinition errors). Include only one.

Tested (loopback, 32 MB transfer, Rust via libc):
```
size_of::<libc::tcp_info>() = 280
getsockopt r=0 optlen=280 rtt=11us min_rtt=7us cwnd=10 delivery_rate=13096600000B/s busy=2000us
  bytes_acked=6553601 snd_wnd=340992 rcv_wnd=65536 total_rto=0
TCP_CONGESTION = "cubic"
```

#### TCP_CONGESTION
* getsockopt returns a NUL-padded name (16 bytes, `TCP_CA_NAME_MAX`). setsockopt "reno" worked unprivileged;
  "bbr"/"dctcp" returned **ENOENT** because they were not loaded (`tcp_available_congestion_control = reno cubic`).
  Unprivileged users can pick only algorithms in `net.ipv4.tcp_allowed_congestion_control`. Module
  autoload and non-allowed algorithms need `CAP_NET_ADMIN`.
* nix has `sockopt::TcpCongestion`, and socket2 has `tcp_congestion()`.

#### TCP_SAVE_SYN / TCP_SAVED_SYN
* `setsockopt(listen_fd, IPPROTO_TCP, TCP_SAVE_SYN, 1|2)`: 1 = save IP+TCP headers of incoming SYNs,
  2 = also the link-layer header (since 5.10; source comment "2: start from ether_header"). There is no
  capability check in `do_tcp_setsockopt` (`if (val < 0 || val > 2) -EINVAL else tp->save_syn = val`).
* `getsockopt(accepted_fd, IPPROTO_TCP, TCP_SAVED_SYN, buf, &len)` returns the headers **once** and
  then frees them (second read: len=0). If the buffer is too small: ENOSPC, with the needed len written back.
* **[tested] unprivileged, uid 2001, no namespaces**:
  * v4, mode 1: len=60 (`45 00 00 3c ...` = 20-byte IPv4 + 40-byte TCP with options)
  * v6, mode 2: len=94 (14-byte Ethernet header, zeros on lo, `86 dd`, then 40 IPv6 + 40 TCP)
* Server-side only. It shows the client's SYN as it arrived: TOS/ECN bits, TTL (hop count), options
  (MSS, wscale, SACK, TS, TFO) as remarked or stripped by middleboxes.

---

## Implications for PTF / probe
- Define our own #[repr(C)] tcp_info up to the 6.7 fields, zero it, and record the kernel-returned optlen so readers know which fields are valid; libc::tcp_info misreads the 7.0+ tail.
- TCP_SAVE_SYN/TCP_SAVED_SYN works unprivileged on the responder: store the SYN headers seen by the responder for proxy/middlebox detection.
- Congestion control: record the algorithm used (TCP_CONGESTION) and the available list; unprivileged users cannot load new ones.
