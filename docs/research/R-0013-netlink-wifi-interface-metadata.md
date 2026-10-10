# R-0013: rtnetlink events, nl80211 station info, interface classification, metered state
- source: rtnetlink(7), include/uapi/linux/nl80211.h (v7.2), drivers/net/usb/usbnet.c (v7.2), NetworkManager D-Bus API docs; local experiments (unprivileged)
- accessed: 2026-10-10
- claim-under-test: Address/route change events, Wi-Fi link stats and interface type are readable unprivileged; metered state needs NetworkManager.
- verdict: confirmed
- applicability: Context capture that cannot be recovered later (REQ-PRB-019) and mobility events (REQ-PRB-022).
## Evidence

Tested on Fedora 44, kernel 7.2.4, rustc 1.99; experiment programs were throwaway (not committed).

### 6. Netlink

#### rtnetlink change events **[tested]**
Bind a `NETLINK_ROUTE` socket with groups
`RTMGRP_LINK|RTMGRP_IPV4_IFADDR|RTMGRP_IPV6_IFADDR|RTMGRP_IPV4_ROUTE|RTMGRP_IPV6_ROUTE` (0x551).
Unprivileged. Dump with `RTM_GETLINK`+`NLM_F_DUMP` first, then read events. Also consider
`setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, RTNLGRP_*)` for groups above 32. Handle ENOBUFS
(overrun) by re-dumping. Sync code with `netlink-sys` 0.9 + `netlink-packet-route` 0.33:
```rust
let mut sock = Socket::new(NETLINK_ROUTE)?;
sock.bind(&SocketAddr::new(0, groups))?;
let mut hdr = NetlinkHeader::default(); hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
let mut req = NetlinkMessage::new(hdr, NetlinkPayload::from(RouteNetlinkMessage::GetLink(LinkMessage::default())));
req.finalize(); let mut buf = vec![0; req.buffer_len()]; req.serialize(&mut buf); sock.send(&buf, 0)?;
let mut rx = Vec::with_capacity(65536);
let n = sock.recv(&mut rx, 0)?;                       // BufMut; clear() before each recv
let msg = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&rx[off..n])?; off += msg.header.length as usize;
```
Events seen while adding/removing a veth with v4/v6 addresses in a netns: NewLink, NewAddress(Inet),
NewRoute(local/table 255), NewLink(Up), NewRoute(254), NewAddress(Inet6), ..., DelRoute, DelAddress, DelLink.

#### nl80211 **[tested, unprivileged uid 2001]**
Generic netlink: resolve the family via `CTRL_CMD_GETFAMILY` (id was 43), then:
* `NL80211_CMD_GET_INTERFACE`(5) doit with `NL80211_ATTR_IFINDEX`(3) returns IFTYPE(5) (2=station),
  WIPHY_FREQ(38) MHz, CHANNEL_WIDTH(159), CENTER_FREQ1(160), SSID(52, raw bytes), MAC(6) (own).
* `NL80211_CMD_GET_STATION`(**17**) **dump** with IFINDEX gives one entry per peer (the AP when in managed
  mode). Attributes: MAC(6)=BSSID, STA_INFO(21, nested): SIGNAL(7, s8 dBm), SIGNAL_AVG(13),
  BEACON_SIGNAL_AVG(30), TX_BITRATE(8)/RX_BITRATE(14) nested with RATE_INFO_BITRATE32(5, u32 in
  100 kbit/s) plus MCS/width attrs, TX_RETRIES(11), TX_FAILED(12), RX/TX_BYTES64, etc.
* `NL80211_CMD_GET_SCAN`(**32**) dump gives cached BSS list. The associated BSS carries BSS_STATUS(9).
  It also has BSS_BSSID(1), BSS_FREQUENCY(2), BSS_SIGNAL_MBM(7, s32 mBm). (This is what `iw link` uses.)
* `NL80211_CMD_TRIGGER_SCAN` needs CAP_NET_ADMIN (`iw scan`: "Operation not permitted"). We don't need it.
* Watch out for the enum values. Commands enum has aliases (`NEW_BEACON = START_AP`, etc.), so
  counting lines gives wrong numbers. Use values from a C program or bindgen:
  GET_STATION=17, GET_SCAN=32.
* Observed output (BSSID redacted):
```
nl80211 family id = 43
GET_INTERFACE: iftype=Some(2) freq=Some(5745)MHz chan_width_enum=Some(3) ssid=<8 bytes>
GET_STATION: sta=28:87:ba:xx:xx:xx signal=-30dBm beacon_avg=-28dBm tx_bitrate=1200.9Mbit/s rx_bitrate=1200.9Mbit/s
GET_SCAN (associated BSS): bssid=28:87:ba:xx:xx:xx freq=5745 signal_mbm=-2900
```
* ath12k reports `signal avg: 0 dBm` (iw), so it is broken on this driver. Prefer SIGNAL plus BEACON_SIGNAL_AVG.
* Privacy: SSID/BSSID are personal data. Hash or omit by default.

Hand-rolled genl core (tested; about 150 lines total in the probe project, `libc` only):
```rust
let fd = libc::socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_GENERIC);
// msg = nlmsghdr{len,type=family,flags=REQUEST|ACK|[DUMP],seq,pid=0} + genlmsghdr{cmd,version=1,0,0} + NLAs (4-byte aligned)
// read until NLMSG_DONE or NLMSG_ERROR (error==0 is the ACK); nested NLA type &= 0x3fff
```

#### Crates (crates.io, 2026-10-10)
| Crate | Version | Sync? | Notes |
|---|---|---|---|
| netlink-sys | 0.9.0 | yes (default features empty; tokio/smol/mio optional) | thin socket wrapper; deps bytes, libc, log |
| netlink-packet-core | 0.9.0 | n/a | |
| netlink-packet-route | 0.33.0 | n/a (pure types) | deps bitflags, libc, log, zerocopy. **Recommended for rtnetlink.** |
| netlink-packet-generic | 0.5.0 | n/a | CTRL family resolution types |
| wl-nl80211 | 0.8.0 | types usable sync with `default-features=false` (tokio optional), but non-optional deps include futures, genetlink, netlink-proto | typed `Nl80211Attr`/`Nl80211StationInfo::Signal(i8)` etc. Its request API is async-only, so you hand-feed messages to netlink-sys. |
| genetlink | 0.3.0 | async (tokio default) | skip |
| neli | 0.7.4 | yes (`default=["sync"]`) | generic netlink and rtnetlink, but you define nl80211 constants yourself |
| nl80211 | 0.0.2 (2019) | | abandoned |

Recommendation: netlink-sys + netlink-packet-route for rtnl. For nl80211, the hand-rolled libc
version is fewer deps than wl-nl80211's futures/netlink-proto tree and only about 30 constants.

---

### 8. Interface metadata

#### Metered (NetworkManager)
* No kernel/sysfs/proc notion of metered exists. NM's runtime files `/run/NetworkManager/devices/<ifindex>`
  hold dhcp and connection-uuid but **no metered key** (checked). The setting is NM-internal.
* `nmcli -t -g GENERAL.METERED device show wlp13s0` gives `no (guessed)` (rc 0). With `-f` instead of `-g`:
  `GENERAL.METERED:no (guessed)`. Possible values: `yes`, `no`, `yes (guessed)`, `no (guessed)`, `unknown`.
  Unknown device: `Error: Device 'nosuchif' not found.` rc=10. nmcli 1.56.1.
* Connection-level setting: `nmcli -t -f connection.metered connection show <uuid>` gives `connection.metered:unknown`
  (= auto/guess).
* Without nmcli: `busctl get-property org.freedesktop.NetworkManager <devpath> org.freedesktop.NetworkManager.Device Metered`
  gives `u 4`. Enum NMMetered: 0 UNKNOWN, 1 YES, 2 NO, 3 GUESS_YES, 4 GUESS_NO. Get devpath via
  `busctl call org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager GetDeviceByIpIface s wlp13s0`
  (`o "/org/freedesktop/NetworkManager/Devices/4"`). Global property on `/org/freedesktop/NetworkManager`: `Metered` gives `u 4`.
* Recommendation: run `nmcli` with a timeout. Missing binary, non-zero exit or timeout means "unknown". Map
  "(guessed)" separately. "yes (guessed)" usually comes from DHCP option 43 ANDROID_METERED (phone hotspot).

#### Interface type from /sys/class/net/<if>/ **[tested on host]**
| Signal | Meaning |
|---|---|
| `type` (ARPHRD) | 1 = Ethernet-like (eth **and** wifi), 772 = loopback, 65534 = none (tun/wireguard), 768/769 = ipip/tunnel6, 776 = sit, 519 = rawip (some WWAN) |
| `uevent` `DEVTYPE=` | `wlan` (cfg80211 and usbnet FLAG_WLAN), `wwan` (usbnet FLAG_WWAN, e.g. qmi_wwan, cdc_mbim; also the wwan subsystem), `bridge`, `bond`, `vlan`, `wireguard`, `gadget`, `dsa`, ... Absent for plain Ethernet. Verified `wwan_type`/`wlan_type` in drivers/net/usb/usbnet.c v7.2 |
| `wireless/` dir, `phy80211` link | WiFi (cfg80211) |
| `tun_flags` file | tun/tap (tailscale0 is tun) |
| `device` link | missing means virtual (`/sys/devices/virtual/net/...`) |
| `device/driver` basename / `device/uevent DRIVER=` | `rndis_host`, `cdc_ether`, `cdc_ncm`, `ipheth` (iPhone) mean **USB tethering**. `qmi_wwan`, `cdc_mbim`, `mhi_net`, `ipa` mean WWAN. Host: atlantic, r8169 (eth), ath12k_wifi7_pci (wifi) |
| `readlink -f device` contains `/usb` | USB-attached (with Ethernet type plus tether driver, assume phone tether) |
| `device/uevent PCI_CLASS` | 0x20000 Ethernet controller, 0x28000 network controller (wifi) |

Observed on this host:
```
wlp13s0: DEVTYPE=wlan type=1 driver=ath12k_wifi7_pci wireless=y phy80211=y PCI_CLASS=28000
enp8s0:  type=1 driver=atlantic PCI_CLASS=20000  (no DEVTYPE)
enp14s0: type=1 driver=r8169    PCI_CLASS=20000
tailscale0: type=65534 virtual (tun)
lo: type=772 virtual
```
Suggested classifier: loopback (772) -> `wireless/` or DEVTYPE=wlan -> DEVTYPE=wwan or WWAN drivers ->
tether drivers / `/usb` path -> `tun_flags` / virtual -> type 1 with a PCI/platform device = ethernet -> other.
`nmcli -t -f DEVICE,TYPE device` gives `wlp13s0:wifi`, `tailscale0:tun`, `enp8s0:ethernet` and can confirm.

---

## Implications for PTF / probe
- rtnetlink groups 0x551 for link/address/route events, unprivileged.
- nl80211 GET_INTERFACE(5) and GET_STATION(17) dump: frequency, signal, beacon signal, tx/rx bitrate, retries, failures. Hash BSSID/SSID by default (pii).
- Interface type from sysfs (DEVTYPE, wireless/, driver names for USB tethering and WWAN).
- Metered: nmcli -t -g GENERAL.METERED with a timeout; failure = unknown.
