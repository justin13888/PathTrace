//! Graceful stop on SIGINT/SIGTERM (docs/design/probe.md §8).
//!
//! The first signal only sets a flag that sessions poll; the handler is installed with
//! `SA_RESETHAND`, so a second signal gets the default action and terminates at once.

use std::io;
use std::sync::atomic::{AtomicI32, Ordering};

/// Number of the first stop signal received, or 0.
static STOP: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(sig: libc::c_int) {
    // Only an atomic compare-and-swap: async-signal-safe. The first signal wins, so a SIGINT
    // followed by a SIGTERM records SIGINT.
    let _ = STOP.compare_exchange(0, sig, Ordering::SeqCst, Ordering::SeqCst);
}

/// Install the stop handler for SIGINT and SIGTERM.
pub fn install_stop_handler() -> io::Result<()> {
    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: zeroed sigaction is a valid initial value; the fields are set below.
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        sa.sa_flags = libc::SA_RESETHAND | libc::SA_RESTART;
        // SAFETY: `sa.sa_mask` is a valid sigset_t to initialise.
        unsafe { libc::sigemptyset(&raw mut sa.sa_mask) };
        // SAFETY: valid signal number and a fully initialised sigaction; the handler only
        // performs an atomic store, which is async-signal-safe.
        crate::cvt(unsafe { libc::sigaction(sig, &raw const sa, std::ptr::null_mut()) })?;
    }
    Ok(())
}

/// The stop signal received so far (SIGINT or SIGTERM), if any.
pub fn stop_requested() -> Option<i32> {
    match STOP.load(Ordering::SeqCst) {
        0 => None,
        s => Some(s),
    }
}

/// Name of a stop signal for records.
pub fn name(sig: i32) -> &'static str {
    match sig {
        libc::SIGINT => "SIGINT",
        libc::SIGTERM => "SIGTERM",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_sets_flag_once() {
        install_stop_handler().unwrap();
        assert_eq!(stop_requested(), None);
        // SAFETY: raising a signal whose handler we just installed.
        unsafe { libc::raise(libc::SIGTERM) };
        assert_eq!(stop_requested(), Some(libc::SIGTERM));
        assert_eq!(name(libc::SIGTERM), "SIGTERM");
        // SA_RESETHAND restored the default disposition for the next one: put ours back so the
        // test process is not killed by a stray signal.
        install_stop_handler().unwrap();
        // A later, different signal does not replace the first one.
        // SAFETY: raising a signal whose handler we just installed.
        unsafe { libc::raise(libc::SIGINT) };
        assert_eq!(stop_requested(), Some(libc::SIGTERM));
        install_stop_handler().unwrap();
    }
}
