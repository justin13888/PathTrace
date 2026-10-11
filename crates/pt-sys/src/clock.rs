//! Clocks (R-0010, ADR 0012).
//!
//! Scheduling and intended send times use CLOCK_MONOTONIC_RAW. Kernel packet timestamps are
//! CLOCK_REALTIME, so [`pair`] samples both clocks with a minimum-width sandwich to map between
//! them at derivation time.

use std::time::Duration;

fn now(clock: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec; both clock ids used here always exist on Linux.
    let r = unsafe { libc::clock_gettime(clock, &mut ts) };
    debug_assert_eq!(r, 0);
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// CLOCK_MONOTONIC_RAW in ns.
#[inline]
pub fn mono_raw() -> u64 {
    now(libc::CLOCK_MONOTONIC_RAW)
}

/// CLOCK_REALTIME in ns since the Unix epoch.
#[inline]
pub fn realtime() -> u64 {
    now(libc::CLOCK_REALTIME)
}

/// CLOCK_BOOTTIME in ns: like MONO_RAW's monotonic clock, but it keeps counting during suspend.
#[inline]
pub fn boottime() -> u64 {
    now(libc::CLOCK_BOOTTIME)
}

/// One clock pair: REALTIME sampled between two MONO_RAW reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockPair {
    /// Midpoint of the two MONO_RAW reads.
    pub mono: u64,
    pub real: u64,
    /// CLOCK_BOOTTIME, read inside the same sandwich: BOOTTIME − MONO_RAW jumps by the time
    /// the system spent suspended.
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

/// Sleep until MONO_RAW reaches `deadline`: coarse sleep until `spin` before it, then spin.
/// Returns the lateness (ns) at wakeup.
pub fn sleep_until(deadline: u64, spin: Duration) -> u64 {
    let spin = spin.as_nanos() as u64;
    loop {
        let t = mono_raw();
        if t >= deadline {
            return t - deadline;
        }
        let left = deadline - t;
        if left > spin {
            std::thread::sleep(Duration::from_nanos(left - spin));
        } else {
            std::hint::spin_loop();
        }
    }
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
    fn sleep_until_is_accurate() {
        // On a loaded host the scheduler can delay any single wakeup; the function must be
        // accurate when it gets the CPU, so judge the best of a few tries.
        let best = (0..5)
            .map(|_| sleep_until(mono_raw() + 2_000_000, Duration::from_micros(200)))
            .min()
            .unwrap();
        assert!(best < 1_000_000, "late by {best} ns at best");
    }
}
