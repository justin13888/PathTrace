//! A power assertion that keeps an idle system awake for a probe session (probe.md §9.4,
//! R-0017).
//!
//! On macOS this is an IOKit assertion of type `kIOPMAssertPreventUserIdleSystemSleep`, held
//! until the [`PowerAssertion`] is dropped. It does not prevent sleep on lid close, from the
//! Apple menu or on low battery; such a sleep is a suspend (probe.md §4.3). Linux has no
//! equivalent that needs no privilege: [`prevent_idle_sleep`] fails there with
//! [`std::io::ErrorKind::Unsupported`] and [`crate::PLATFORM`]`.power_assertion` is false.
//!
//! [`power_state`] reads the providing power source and Low Power Mode on macOS for `doctor`'s
//! `power` check (cli.md, "`doctor` on macOS"). Linux reads `/sys/class/power_supply` instead,
//! so it fails there with [`std::io::ErrorKind::Unsupported`].

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

/// The power source the system is drawing from (`IOPSGetProvidingPowerSourceType`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PowerSource {
    /// `kIOPMACPowerKey` ("AC Power"): external power, including USB-C power delivery.
    Ac,
    /// `kIOPMBatteryPowerKey` ("Battery Power"): the internal battery.
    Battery,
    /// `kIOPMUPSPowerKey` ("UPS Power"): an attached UPS.
    Ups,
    /// Any other string IOKit returns, verbatim; empty when it returns none.
    Other(String),
}

impl PowerSource {
    /// Classify the string `IOPSGetProvidingPowerSourceType` returns.
    pub fn from_iokit(s: &str) -> PowerSource {
        match s {
            "AC Power" => PowerSource::Ac,
            "Battery Power" => PowerSource::Battery,
            "UPS Power" => PowerSource::Ups,
            s => PowerSource::Other(s.to_string()),
        }
    }
}

/// What the system's power state is, as far as it affects timing noise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerState {
    /// The providing power source.
    pub source: PowerSource,
    /// Low Power Mode (`NSProcessInfo.isLowPowerModeEnabled`).
    pub low_power_mode: bool,
}

/// The providing power source and Low Power Mode: unsupported on Linux, whose power supplies
/// are files under `/sys/class/power_supply` that need no system call.
#[cfg(target_os = "linux")]
pub fn power_state() -> io::Result<PowerState> {
    Err(crate::unsupported("the IOKit power source"))
}

/// The providing power source (IOKit power sources) and Low Power Mode (`NSProcessInfo`,
/// through the Objective-C runtime). Unprivileged.
#[cfg(target_os = "macos")]
pub fn power_state() -> io::Result<PowerState> {
    Ok(PowerState {
        source: PowerSource::from_iokit(&iokit::providing_source()?),
        low_power_mode: objc::low_power_mode()?,
    })
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
        fn CFStringGetCString(
            s: CFStringRef,
            buf: *mut libc::c_char,
            size: isize,
            encoding: u32,
        ) -> u8;
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

    #[link(name = "IOKit", kind = "framework")]
    // SAFETY: the signatures match IOKit's IOPowerSources.h (`CFTypeRef` and `CFStringRef` are
    // pointers).
    unsafe extern "C" {
        fn IOPSCopyPowerSourcesInfo() -> *const c_void;
        fn IOPSGetProvidingPowerSourceType(snapshot: *const c_void) -> CFStringRef;
    }

    /// The string `IOPSGetProvidingPowerSourceType` returns for a fresh snapshot ("AC Power",
    /// "Battery Power", "UPS Power"); empty when it returns none.
    pub fn providing_source() -> io::Result<String> {
        // SAFETY: no arguments; the call returns a snapshot the caller owns (Copy rule), or
        // null.
        let snapshot = unsafe { IOPSCopyPowerSourcesInfo() };
        if snapshot.is_null() {
            return Err(io::Error::other("IOPSCopyPowerSourcesInfo returned null"));
        }
        // SAFETY: `snapshot` is a live power sources snapshot. The returned string follows the
        // Get rule: it is owned by the snapshot and is only read before the snapshot is
        // released below.
        let ty = unsafe { IOPSGetProvidingPowerSourceType(snapshot) };
        let s = cf_to_string(ty);
        // SAFETY: `snapshot` came from a Copy function and is released exactly once, after its
        // last use.
        unsafe { CFRelease(snapshot) };
        Ok(s)
    }

    /// A CFString's contents as UTF-8; empty for a null string or one longer than the buffer.
    fn cf_to_string(s: CFStringRef) -> String {
        if s.is_null() {
            return String::new();
        }
        let mut buf = [0 as libc::c_char; 128];
        // SAFETY: `s` is a live CFString; `buf` is writable for its full length, which is the
        // size passed, and the call NUL-terminates what it writes.
        let ok = unsafe { CFStringGetCString(s, buf.as_mut_ptr(), buf.len() as isize, UTF8) };
        if ok == 0 {
            return String::new();
        }
        // SAFETY: on success `buf` holds a NUL-terminated string within its bounds.
        unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned()
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

/// Low Power Mode through the Objective-C runtime's C API (`objc/runtime.h`, `objc/message.h`),
/// so no binding crate is needed.
#[cfg(target_os = "macos")]
mod objc {
    use std::ffi::{CStr, c_void};
    use std::io;

    type Id = *mut c_void;
    type Sel = *const c_void;

    // Foundation registers the NSProcessInfo class; nothing is called from it directly.
    #[link(name = "Foundation", kind = "framework")]
    unsafe extern "C" {}

    #[link(name = "objc")]
    // SAFETY: the signatures match objc/runtime.h; `objc_msgSend` is declared without
    // arguments and is only called through a pointer cast to the method's exact signature.
    unsafe extern "C" {
        fn objc_getClass(name: *const libc::c_char) -> Id;
        fn sel_registerName(name: *const libc::c_char) -> Sel;
        fn objc_msgSend();
    }

    /// `objc_msgSend` cast to a method taking no arguments and returning an object.
    type MsgSendId = unsafe extern "C" fn(Id, Sel) -> Id;
    /// `objc_msgSend` cast to a method taking no arguments and returning a `BOOL` (a signed
    /// char on x86_64, a C bool on arm64; either is one byte, 0 for NO).
    type MsgSendBool = unsafe extern "C" fn(Id, Sel) -> i8;

    fn sel(name: &CStr) -> Sel {
        // SAFETY: `name` is a NUL-terminated string; selectors are registered for the life of
        // the process.
        unsafe { sel_registerName(name.as_ptr()) }
    }

    /// `[[NSProcessInfo processInfo] isLowPowerModeEnabled]` (macOS 12 and later).
    pub fn low_power_mode() -> io::Result<bool> {
        // SAFETY: a NUL-terminated class name; the result is the class or null.
        let class = unsafe { objc_getClass(c"NSProcessInfo".as_ptr()) };
        if class.is_null() {
            return Err(io::Error::other("NSProcessInfo is not loaded"));
        }
        // SAFETY: casting objc_msgSend to the exact signature of the method sent is how the
        // runtime is meant to be called from C.
        let send_id: MsgSendId =
            unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
        // SAFETY: as above.
        let send_bool: MsgSendBool =
            unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
        // SAFETY: `+[NSProcessInfo processInfo]` takes no arguments and returns the shared
        // process info object, which is never deallocated (no ownership is taken).
        let info = unsafe { send_id(class, sel(c"processInfo")) };
        if info.is_null() {
            return Err(io::Error::other(
                "+[NSProcessInfo processInfo] returned nil",
            ));
        }
        // SAFETY: `-isLowPowerModeEnabled` takes no arguments and returns a BOOL; `info` is a
        // live NSProcessInfo.
        Ok(unsafe { send_bool(info, sel(c"isLowPowerModeEnabled")) } != 0)
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
        assert_eq!(
            power_state().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn iokit_source_strings() {
        assert_eq!(PowerSource::from_iokit("AC Power"), PowerSource::Ac);
        assert_eq!(
            PowerSource::from_iokit("Battery Power"),
            PowerSource::Battery
        );
        assert_eq!(PowerSource::from_iokit("UPS Power"), PowerSource::Ups);
        assert_eq!(
            PowerSource::from_iokit(""),
            PowerSource::Other(String::new())
        );
    }

    /// The reader returns on any Mac, CI runners included: a VM or a desktop reports AC power,
    /// never an unrecognised string.
    #[cfg(target_os = "macos")]
    #[test]
    fn power_state_reads() {
        let s = power_state().expect("unprivileged power state");
        assert!(
            matches!(
                s.source,
                PowerSource::Ac | PowerSource::Battery | PowerSource::Ups
            ),
            "{s:?}"
        );
    }
}
