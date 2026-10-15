//! A power assertion that keeps an idle system awake for a probe session (probe.md §9.4,
//! R-0017).
//!
//! On macOS this is an IOKit assertion of type `kIOPMAssertPreventUserIdleSystemSleep`, held
//! until the [`PowerAssertion`] is dropped. It does not prevent sleep on lid close, from the
//! Apple menu or on low battery; such a sleep is a suspend (probe.md §4.3). Linux has no
//! equivalent that needs no privilege: [`prevent_idle_sleep`] fails there with
//! [`std::io::ErrorKind::Unsupported`] and [`crate::PLATFORM`]`.power_assertion` is false.

use std::io;

/// The assertion name a session holds (probe.md §9.4).
pub const SESSION_ASSERTION_NAME: &str = "pathtrace probe session";

/// A held power assertion; dropping it releases the assertion.
#[derive(Debug)]
pub struct PowerAssertion {
    #[cfg(target_os = "macos")]
    id: u32,
}

/// Keep the system from idle-sleeping until the returned assertion is dropped: unsupported on
/// Linux.
#[cfg(target_os = "linux")]
pub fn prevent_idle_sleep(_name: &str) -> io::Result<PowerAssertion> {
    Err(crate::unsupported("a power assertion"))
}

/// Keep the system from idle-sleeping until the returned assertion is dropped. `name` is shown
/// by `pmset -g assertions`.
#[cfg(target_os = "macos")]
pub fn prevent_idle_sleep(name: &str) -> io::Result<PowerAssertion> {
    iokit::create(name).map(|id| PowerAssertion { id })
}

#[cfg(target_os = "macos")]
impl Drop for PowerAssertion {
    fn drop(&mut self) {
        iokit::release(self.id);
    }
}

/// IOKit power management and the CoreFoundation strings it takes (`IOKit/pwr_mgt/IOPMLib.h`).
#[cfg(target_os = "macos")]
mod iokit {
    use std::ffi::{CString, c_void};
    use std::io;

    type CFStringRef = *const c_void;
    /// `kCFStringEncodingUTF8`.
    const UTF8: u32 = 0x0800_0100;
    /// `kIOPMAssertionLevelOn`.
    const LEVEL_ON: u32 = 255;
    /// `kIOReturnSuccess`.
    const SUCCESS: i32 = 0;
    /// `kIOPMAssertPreventUserIdleSystemSleep`.
    const PREVENT_USER_IDLE_SYSTEM_SLEEP: &str = "PreventUserIdleSystemSleep";

    #[link(name = "CoreFoundation", kind = "framework")]
    // SAFETY: the signatures match CoreFoundation's CFString.h and CFBase.h.
    unsafe extern "C" {
        fn CFStringCreateWithCString(
            alloc: *const c_void,
            c_str: *const libc::c_char,
            encoding: u32,
        ) -> CFStringRef;
        fn CFRelease(cf: *const c_void);
    }

    #[link(name = "IOKit", kind = "framework")]
    // SAFETY: the signatures match IOKit's IOPMLib.h (`IOPMAssertionID` is a u32, `IOReturn`
    // an i32).
    unsafe extern "C" {
        fn IOPMAssertionCreateWithName(
            assertion_type: CFStringRef,
            level: u32,
            name: CFStringRef,
            id: *mut u32,
        ) -> i32;
        fn IOPMAssertionRelease(id: u32) -> i32;
    }

    /// An owned CFString, released on drop.
    struct CfString(CFStringRef);

    impl CfString {
        fn new(s: &str) -> io::Result<CfString> {
            let c = CString::new(s).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            // SAFETY: `c` is a NUL-terminated UTF-8 string that outlives the call, which copies
            // it; a null allocator selects the default one.
            let r = unsafe { CFStringCreateWithCString(std::ptr::null(), c.as_ptr(), UTF8) };
            if r.is_null() {
                return Err(io::Error::other("CFStringCreateWithCString failed"));
            }
            Ok(CfString(r))
        }
    }

    impl Drop for CfString {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a CFString this value created and owns exactly one reference
            // to.
            unsafe { CFRelease(self.0) };
        }
    }

    pub fn create(name: &str) -> io::Result<u32> {
        let ty = CfString::new(PREVENT_USER_IDLE_SYSTEM_SLEEP)?;
        let name = CfString::new(name)?;
        let mut id = 0u32;
        // SAFETY: both CFStrings are live for the call, which retains what it keeps; `id` is a
        // valid, writable IOPMAssertionID.
        let r = unsafe { IOPMAssertionCreateWithName(ty.0, LEVEL_ON, name.0, &raw mut id) };
        if r != SUCCESS {
            return Err(io::Error::other(format!(
                "IOPMAssertionCreateWithName returned {r:#x}"
            )));
        }
        Ok(id)
    }

    pub fn release(id: u32) {
        // SAFETY: `id` came from a successful IOPMAssertionCreateWithName and is released
        // exactly once, by the owning PowerAssertion's drop.
        unsafe { IOPMAssertionRelease(id) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn assertion_is_held_and_released() {
        let a = prevent_idle_sleep("pathtrace pt-sys test").expect("unprivileged assertion");
        assert!(a.id != 0);
        drop(a);
        assert!(prevent_idle_sleep("bad\0name").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unsupported_on_linux() {
        let e = prevent_idle_sleep(SESSION_ASSERTION_NAME).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    }
}
