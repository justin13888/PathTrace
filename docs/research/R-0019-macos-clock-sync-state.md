# R-0019: macOS clock sync state visible to an unprivileged process
- source: XNU xnu-12377.121.6 `bsd/kern/kern_ntptime.c` (https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_ntptime.c); ntp_adjtime(2) (NetBSD, https://man.netbsd.org/NetBSD-2.1/ntp_adjtime.2); timed(8) (macOS 26.6.1); local experiments (macOS 26.6.1 25G76, Darwin 25.6.0 xnu-12377.161.13 arm64, uid 501, no privileges, up 5 days, "Set time and date automatically" on)
- accessed: 2026-10-16
- claim-under-test: on macOS, `ntp_adjtime` (`modes = 0`) reports whether the clock is synchronised (`STA_UNSYNC`) and how well (`esterror`, `maxerror`), as `adjtimex` does on Linux; or some other unprivileged interface, read without shelling out, reports `timed`'s sync state.
- verdict: refuted
- applicability: `doctor`'s `clock sync` row on macOS (cli.md "`doctor` on macOS", REQ-PRB-033, REQ-SCOPE-009). Refines R-0017's clock finding, which showed only that the call works unprivileged. Traces do not read these fields.
## Evidence

### Kernel side **[source]**
`kern_ntptime.c` initialises `int time_status = STA_UNSYNC;`, `static long time_maxerror = MAXPHASE / 1000;`
and `long time_esterror = MAXPHASE / 1000;` (`MAXPHASE` is 500 ms, so both start at 500000 us). They change
only through `ntp_adjtime` with `modes` set, which requires `SETTIME_ENTITLEMENT` or `PRIV_ADJTIME`:
`MOD_MAXERROR` → `time_maxerror = ntv.maxerror;`, `MOD_ESTERROR` → `time_esterror = ntv.esterror;`,
`MOD_STATUS` → `time_status |= ntv.status & ~STA_RONLY;`. `ntp_update_second` only grows the bound:
`time_maxerror += (MAXFREQ / 1000) * (secs - last_time_maxerror_update);` and never sets `STA_UNSYNC`.
ntp_adjtime(2): `esterror` is "set and read by the ntp_adjtime() call, but otherwise unused by the kernel".

### What `timed` writes **[tested]**
Two reads 47 s apart, `modes = 0`: `status=0x2081 maxerror=279339 esterror=500000` at t=1792178717, then
`status=0x2081 maxerror=303339 esterror=500000` at t=1792178764. A read on the same host days earlier (#93)
gave `maxerror 372053`. So `esterror` is still the boot value after 5 days: `timed` never writes it.
`maxerror` grows at the kernel's 500 us/s and was lowered between the reads of #93 and these, so `timed` does
reset it, but neither timed(8) nor any header says what value it writes or when. `STA_UNSYNC` was cleared once
(`STA_PLL` set, a `MOD_STATUS` write) and nothing in the kernel sets it again, so a clear bit says the clock was
disciplined at some point since boot, not that it is synchronised now.

### Other signals **[man page + tested]**
timed(8): "Inputs are merged inside of timed, where it calculates uncertainty"; its state is
"/var/db/timed/com.apple.timed.plist The cached state of timed". Tested: `ls /var/db/timed/` as uid 501 →
"Permission denied". `systemsetup -getusingnetworktime` → "You need administrator access to run this tool".
`sntp` and `systemsetup` would also be shelling out. No public header or framework exposes `timed`'s
uncertainty or last sync time.

## Implications for PTF / probe
- On macOS `doctor` cannot attribute a sync state: it must not print `esterror`/`maxerror` (meaningless or
  undocumented) nor call a clear `STA_UNSYNC` synchronised. The fact is unknown, never a number.
- `clock sync` on macOS is a `warn` "sync state unknown" with the "Set time and date automatically"
  (System Settings > General > Date & Time) advice the user can check by hand.
- Linux `adjtimex` is out of scope here and its `doctor` row is unchanged (EXP-0008-r3 recorded
  `estimated error 503 us` from a disciplined Linux host, so its daemon does write `esterror`).
