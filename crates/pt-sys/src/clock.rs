//! Clocks (R-0010, R-0017, ADR 0012, docs/design/probe.md §9.1).
//!
//! Scheduling and intended send times use a monotonic clock that is not slewed and stops during
//! suspend: CLOCK_MONOTONIC_RAW on Linux, `mach_absolute_time` (CLOCK_UPTIME_RAW) on macOS.
//! Kernel packet timestamps are CLOCK_REALTIME, so [`pair`] samples both clocks with a
//! minimum-width sandwich to map between them at derivation time. A clock that keeps counting
//! during suspend (CLOCK_BOOTTIME on Linux, `mach_continuous_time` on macOS) is read inside the
//! same sandwich, so a suspend shows as a jump of boot − mono.

use std::io;
use std::time::Duration;

/// How far before a deadline the pacer stops sleeping and starts spinning (probe.md §1, §9.4):
/// 200 µs on Linux, 500 µs on macOS, where a coalesced timer can wake a thread later.
#[cfg(target_os = "linux")]
pub const SPIN_NS: u64 = 200_000;
/// How far before a deadline the pacer stops sleeping and starts spinning (probe.md §1, §9.4):
/// 200 µs on Linux, 500 µs on macOS, where a coalesced timer can wake a thread later.
#[cfg(target_os = "macos")]
pub const SPIN_NS: u64 = 500_000;

fn now(clock: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec; every clock id passed here exists on the
    // platform this is compiled for.
    let r = unsafe { libc::clock_gettime(clock, &mut ts) };
    debug_assert_eq!(r, 0);
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// The scheduling clock in ns: CLOCK_MONOTONIC_RAW on Linux. On macOS it is
/// `mach_absolute_time` converted to ns, which like Linux MONO_RAW is not slewed and stops while
/// the system sleeps (macOS's own CLOCK_MONOTONIC_RAW counts sleep, R-0017).
#[cfg(target_os = "linux")]
#[inline]
pub fn mono_raw() -> u64 {
    now(libc::CLOCK_MONOTONIC_RAW)
}

/// The scheduling clock in ns: CLOCK_MONOTONIC_RAW on Linux. On macOS it is
/// `mach_absolute_time` converted to ns, which like Linux MONO_RAW is not slewed and stops while
/// the system sleeps (macOS's own CLOCK_MONOTONIC_RAW counts sleep, R-0017).
#[cfg(target_os = "macos")]
#[inline]
pub fn mono_raw() -> u64 {
    mach::ticks_to_ns(mach::mach_absolute_time())
}

/// CLOCK_REALTIME in ns since the Unix epoch.
#[inline]
pub fn realtime() -> u64 {
    now(libc::CLOCK_REALTIME)
}

/// A clock like [`mono_raw`] that keeps counting during suspend, in ns: CLOCK_BOOTTIME on
/// Linux, `mach_continuous_time` on macOS.
#[cfg(target_os = "linux")]
#[inline]
pub fn boottime() -> u64 {
    now(libc::CLOCK_BOOTTIME)
}

/// A clock like [`mono_raw`] that keeps counting during suspend, in ns: CLOCK_BOOTTIME on
/// Linux, `mach_continuous_time` on macOS.
#[cfg(target_os = "macos")]
#[inline]
pub fn boottime() -> u64 {
    mach::ticks_to_ns(mach::mach_continuous_time())
}

/// Mach time: ticks of `mach_absolute_time` and their conversion to ns (24 MHz on Apple
/// silicon, timebase 125/3, R-0017).
#[cfg(target_os = "macos")]
mod mach {
    use std::sync::OnceLock;

    /// `mach_timebase_info_data_t` (fields named in full here; the C names are abbreviated).
    #[repr(C)]
    struct Timebase {
        numerator: u32,
        denominator: u32,
    }

    // SAFETY: the signatures match <mach/mach_time.h>. The clock reads take no arguments and
    // cannot fail, and `mach_wait_until` only blocks the calling thread, so those are safe to
    // call.
    unsafe extern "C" {
        pub safe fn mach_absolute_time() -> u64;
        pub safe fn mach_continuous_time() -> u64;
        pub safe fn mach_wait_until(deadline: u64) -> libc::c_int;
        fn mach_timebase_info(info: *mut Timebase) -> libc::c_int;
    }

    /// (numerator, denominator) of the timebase, read once. Panics if `mach_timebase_info`
    /// fails or reports a zero field: no fallback ratio is right on every Mac (Apple silicon
    /// is 125/3), and a wrong one would scale every recorded time silently.
    fn timebase() -> (u64, u64) {
        static TB: OnceLock<(u64, u64)> = OnceLock::new();
        *TB.get_or_init(|| {
            let mut tb = Timebase {
                numerator: 0,
                denominator: 0,
            };
            // SAFETY: `tb` is a valid, writable mach_timebase_info_data_t.
            let r = unsafe { mach_timebase_info(&raw mut tb) };
            assert!(
                r == 0 && tb.numerator != 0 && tb.denominator != 0,
                "mach_timebase_info failed (kern_return {r}, {}/{})",
                tb.numerator,
                tb.denominator
            );
            (u64::from(tb.numerator), u64::from(tb.denominator))
        })
    }

    pub fn ticks_to_ns(ticks: u64) -> u64 {
        let (n, d) = timebase();
        (u128::from(ticks) * u128::from(n) / u128::from(d)) as u64
    }

    pub fn ns_to_ticks(ns: u64) -> u64 {
        let (n, d) = timebase();
        (u128::from(ns) * u128::from(d) / u128::from(n)) as u64
    }
}

/// One clock pair: REALTIME sampled between two [`mono_raw`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockPair {
    /// Midpoint of the two [`mono_raw`] reads.
    pub mono: u64,
    pub real: u64,
    /// [`boottime`], read inside the same sandwich: boot − mono jumps by the time the system
    /// spent suspended.
    pub boot: u64,
    /// Width of the sandwich (uncertainty), ns.
    pub width: u64,
}

/// Minimum-width sandwich over `tries` attempts (8 suffices: R-0010 measured ~30 ns).
pub fn pair(tries: usize) -> ClockPair {
    let mut best = ClockPair {
        mono: 0,
        real: 0,
        boot: 0,
        width: u64::MAX,
    };
    for _ in 0..tries.max(1) {
        let m0 = mono_raw();
        let r = realtime();
        let b = boottime();
        let m1 = mono_raw();
        let w = m1 - m0;
        if w < best.width {
            best = ClockPair {
                mono: m0 + w / 2,
                real: r,
                boot: b,
                width: w,
            };
        }
    }
    best
}

/// The kernel's NTP discipline state, as an NTP daemon (chrony, ntpd, systemd-timesyncd) sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpState {
    /// The kernel considers CLOCK_REALTIME synchronised: the clock state is not `TIME_ERROR`
    /// and `STA_UNSYNC` is clear.
    pub synced: bool,
    /// Estimated error, µs.
    pub esterror_us: i64,
    /// Maximum error, µs.
    pub maxerror_us: i64,
}

/// Read the kernel NTP state without changing anything (`modes = 0`, which needs no privilege):
/// `adjtimex(2)` on Linux, `ntp_adjtime(2)` on macOS (R-0017).
pub fn ntp_state() -> io::Result<NtpState> {
    // SAFETY: `timex` is plain old data, for which all-zero bytes are a valid value.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: `tx` is a valid, writable timex; `modes` is 0, so the call only reads state.
    #[cfg(target_os = "linux")]
    let state = unsafe { libc::adjtimex(&mut tx) };
    // SAFETY: as above.
    #[cfg(target_os = "macos")]
    let state = unsafe { libc::ntp_adjtime(&mut tx) };
    if state < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(NtpState {
        synced: state != libc::TIME_ERROR && tx.status & libc::STA_UNSYNC == 0,
        esterror_us: tx.esterror as i64,
        maxerror_us: tx.maxerror as i64,
    })
}

/// Sleep until [`mono_raw`] reaches `deadline`: coarse sleep until `spin` before it, then spin.
/// The coarse sleep is `mach_wait_until` on macOS (probe.md §9.4). Returns the lateness (ns) at
/// wakeup.
pub fn sleep_until(deadline: u64, spin: Duration) -> u64 {
    let spin = spin.as_nanos() as u64;
    loop {
        let t = mono_raw();
        if t >= deadline {
            return t - deadline;
        }
        let left = deadline - t;
        if left > spin {
            coarse_sleep(t, deadline - spin);
        } else {
            std::hint::spin_loop();
        }
    }
}

/// Sleep from [`mono_raw`] time `now` until about `until`.
#[cfg(target_os = "linux")]
fn coarse_sleep(now: u64, until: u64) {
    std::thread::sleep(Duration::from_nanos(until - now));
}

/// Sleep from [`mono_raw`] time `now` until about `until`.
#[cfg(target_os = "macos")]
fn coarse_sleep(_now: u64, until: u64) {
    mach::mach_wait_until(mach::ns_to_ticks(until));
}

/// Give the calling thread the scheduling class the pacer and receiver threads need: on macOS
/// `QOS_CLASS_USER_INTERACTIVE`, the class with the least timer coalescing (probe.md §9.4,
/// R-0017). Linux has no such class; there this does nothing.
pub fn set_pacing_qos() -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        /// <sys/qos.h> `QOS_CLASS_USER_INTERACTIVE`.
        const QOS_CLASS_USER_INTERACTIVE: libc::c_uint = 0x21;
        // SAFETY: the signature matches <pthread/qos.h>; the call only changes the calling
        // thread's own QoS class, so it is safe to call with any arguments.
        unsafe extern "C" {
            safe fn pthread_set_qos_class_self_np(
                qos_class: libc::c_uint,
                relative_priority: libc::c_int,
            ) -> libc::c_int;
        }
        let r = pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
        if r != 0 {
            return Err(io::Error::from_raw_os_error(r));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_and_pair() {
        let a = mono_raw();
        let b = mono_raw();
        assert!(b >= a);
        let p = pair(8);
        assert!(p.width < 1_000_000, "sandwich width {} ns", p.width);
        assert!(p.real > 1_600_000_000_000_000_000);
        // BOOTTIME ≥ the monotonic clocks' origin and advances with them while awake.
        let q = pair(8);
        assert!(q.boot >= p.boot && q.boot - p.boot < 1_000_000_000);
    }

    #[test]
    fn ntp_state_reads_without_privilege() {
        let s = ntp_state().expect("adjtimex read-only");
        assert!(s.esterror_us >= 0 && s.maxerror_us >= 0, "{s:?}");
    }

    // On macOS this measures the host as much as the code: a process launched under a QoS
    // clamp (`taskpolicy -c utility`, as a CI runner's service may be) cannot raise its threads
    // above the clamp, and there both the coarse wakeup and the spin run milliseconds late
    // (2-5 ms in local runs under the clamp, 1.7-2.5 ms on the macos-15 runner). Run it on a
    // Mac from a terminal: `cargo nextest run -p pt-sys --run-ignored all sleep_until`.
    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "host timing check; QoS-clamped CI runners cannot meet it"
    )]
    fn sleep_until_is_accurate() {
        // On a loaded host the scheduler can delay any single wakeup; the function must be
        // accurate when it gets the CPU, so judge the best of a few tries. The pacer sleeps in
        // the pacing QoS class (probe.md §9.4); a test thread's default class lets macOS shift
        // the coarse wakeup by more than SPIN_NS, so measure under the class the pacer runs in.
        set_pacing_qos().expect("unprivileged");
        let best = (0..5)
            .map(|_| sleep_until(mono_raw() + 2_000_000, Duration::from_nanos(SPIN_NS)))
            .min()
            .unwrap();
        assert!(best < 1_000_000, "late by {best} ns at best");
    }

    #[test]
    fn sleep_until_spins_accurately() {
        // With a spin window longer than the wait there is no coarse sleep, so the host's timer
        // plays no part and only the spin loop is measured; this runs on every platform.
        let best = (0..5)
            .map(|_| sleep_until(mono_raw() + 2_000_000, Duration::from_millis(10)))
            .min()
            .unwrap();
        assert!(best < 1_000_000, "late by {best} ns at best");
    }

    #[test]
    fn pacing_qos_is_settable() {
        set_pacing_qos().expect("unprivileged");
    }

    /// probe.md §9.1: mono and boot are monotonic, boot − mono stays constant within 1 ms over
    /// 1 s awake, and a clock pair is narrower than 1 µs.
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_clocks_match_the_linux_roles() {
        let p = pair(8);
        assert!(p.width < 1_000, "sandwich width {} ns", p.width);
        let (m0, b0) = (mono_raw(), boottime());
        std::thread::sleep(Duration::from_secs(1));
        let (m1, b1) = (mono_raw(), boottime());
        assert!(m1 > m0 && b1 > b0);
        assert!(m1 - m0 >= 1_000_000_000, "mono advanced {} ns", m1 - m0);
        let drift = (b1 - b0).abs_diff(m1 - m0);
        assert!(
            drift < 1_000_000,
            "boot - mono moved {drift} ns while awake"
        );
        // The conversion round-trips within one tick (41.67 ns on Apple silicon).
        let ns = mono_raw();
        assert!(mach::ticks_to_ns(mach::ns_to_ticks(ns)).abs_diff(ns) < 100);
    }
}
