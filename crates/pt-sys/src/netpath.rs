//! The cost the system assigns the current network path: expensive (cellular, Personal
//! Hotspot, a network the user marked as expensive) or constrained (Low Data Mode). It is the
//! metered state of `--profile auto`, `doctor` and META on macOS (cli.md, "Metered state on
//! macOS"; probe.md §9.11).
//!
//! On macOS [`path_cost`] reads Network.framework: it starts an `nw_path_monitor` on a private
//! dispatch queue, takes its first update (the current default path) and cancels it. The
//! framework delivers paths only to blocks, so the handlers are global block literals built to
//! the Blocks ABI, which hand the update to the calling thread through a static slot. Linux has
//! no such flag in the kernel (NetworkManager holds it, read by `pt-probe`), so it fails there
//! with [`std::io::ErrorKind::Unsupported`].

use std::io;
use std::time::Duration;

/// The cost flags of the path through an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathCost {
    /// `nw_path_is_expensive`: cellular, Personal Hotspot, or a network marked as expensive.
    pub expensive: bool,
    /// `nw_path_is_constrained`: Low Data Mode.
    pub constrained: bool,
}

/// The cost of the current path through `iface`: unsupported on Linux.
#[cfg(target_os = "linux")]
pub fn path_cost(_iface: &str, _timeout: Duration) -> io::Result<Option<PathCost>> {
    Err(crate::unsupported("the Network.framework path cost"))
}

/// The cost of the system's current path when it is satisfied and uses `iface`, else `None`
/// (no route, or a route through another interface). Waits at most `timeout` for the path
/// update and fails with [`io::ErrorKind::TimedOut`] when none arrives. Unprivileged.
#[cfg(target_os = "macos")]
pub fn path_cost(iface: &str, timeout: Duration) -> io::Result<Option<PathCost>> {
    let u = nw::current_path(timeout)?;
    Ok(
        (u.satisfied && u.ifaces.iter().any(|n| n == iface)).then_some(PathCost {
            expensive: u.expensive,
            constrained: u.constrained,
        }),
    )
}

/// Network.framework's path monitor (`Network/path_monitor.h`, `Network/path.h`) and the
/// Blocks ABI it is called with.
#[cfg(target_os = "macos")]
mod nw {
    use std::cell::RefCell;
    use std::ffi::{CStr, c_void};
    use std::io;
    use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
    use std::time::Duration;

    type Obj = *mut c_void;

    /// `nw_path_status_satisfied`.
    const STATUS_SATISFIED: libc::c_int = 1;
    /// `BLOCK_IS_GLOBAL`: the block lives in static storage, so `Block_copy` returns it as is
    /// and `Block_release` does nothing.
    const BLOCK_IS_GLOBAL: libc::c_int = 1 << 28;

    /// Opaque type of the block class symbols.
    #[repr(C)]
    struct BlockClass {
        _private: [u8; 0],
    }

    // SAFETY: `_NSConcreteGlobalBlock` is the class object libclosure (in libSystem) exports
    // for global blocks; only its address is used.
    unsafe extern "C" {
        static _NSConcreteGlobalBlock: BlockClass;
    }

    /// `struct Block_descriptor_1` of the Blocks ABI.
    #[repr(C)]
    struct Descriptor {
        reserved: libc::c_ulong,
        size: libc::c_ulong,
    }

    /// `struct Block_layout` of the Blocks ABI, without captured variables.
    #[repr(C)]
    struct Block<F> {
        isa: *const BlockClass,
        flags: libc::c_int,
        reserved: libc::c_int,
        invoke: F,
        descriptor: *const Descriptor,
    }

    // SAFETY: a global block is immutable: the runtime never writes to one (no reference
    // count, no copy), and its pointers are to statics.
    unsafe impl<F> Sync for Block<F> {}

    static DESCRIPTOR: Descriptor = Descriptor {
        reserved: 0,
        size: size_of::<Block<unsafe extern "C" fn()>>() as libc::c_ulong,
    };

    const fn global<F>(invoke: F) -> Block<F> {
        Block {
            isa: &raw const _NSConcreteGlobalBlock,
            flags: BLOCK_IS_GLOBAL,
            reserved: 0,
            invoke,
            descriptor: &raw const DESCRIPTOR,
        }
    }

    /// `void (^)(nw_path_t)`, the update handler.
    static ON_UPDATE: Block<unsafe extern "C" fn(*const c_void, Obj)> = global(on_update);
    /// `void (^)(void)`, the cancel handler.
    static ON_CANCEL: Block<unsafe extern "C" fn(*const c_void)> = global(on_cancel);
    /// `bool (^)(nw_interface_t)`, the interface enumerator.
    static ON_IFACE: Block<unsafe extern "C" fn(*const c_void, Obj) -> bool> = global(on_iface);

    #[link(name = "Network", kind = "framework")]
    // SAFETY: the signatures match Network.framework's path_monitor.h, path.h, interface.h and
    // object.h; every `nw_*_t` is an object pointer and every block parameter a pointer to a
    // block literal.
    unsafe extern "C" {
        fn nw_path_monitor_create() -> Obj;
        fn nw_path_monitor_set_queue(monitor: Obj, queue: Obj);
        fn nw_path_monitor_set_update_handler(monitor: Obj, handler: *const c_void);
        fn nw_path_monitor_set_cancel_handler(monitor: Obj, handler: *const c_void);
        fn nw_path_monitor_start(monitor: Obj);
        fn nw_path_monitor_cancel(monitor: Obj);
        fn nw_path_get_status(path: Obj) -> libc::c_int;
        fn nw_path_is_expensive(path: Obj) -> bool;
        fn nw_path_is_constrained(path: Obj) -> bool;
        fn nw_path_enumerate_interfaces(path: Obj, handler: *const c_void);
        fn nw_interface_get_name(interface: Obj) -> *const libc::c_char;
        fn nw_release(obj: Obj);
    }

    // SAFETY: the signatures match libdispatch's queue.h and object.h (in libSystem).
    unsafe extern "C" {
        fn dispatch_queue_create(label: *const libc::c_char, attr: *const c_void) -> Obj;
        fn dispatch_release(obj: Obj);
    }

    /// What the monitor's first update said.
    #[derive(Debug, Clone, Default)]
    pub struct Update {
        pub satisfied: bool,
        pub expensive: bool,
        pub constrained: bool,
        /// Names of the interfaces the path uses, in the framework's order.
        pub ifaces: Vec<String>,
    }

    #[derive(Debug, Default)]
    struct Slot {
        update: Option<Update>,
        cancelled: bool,
    }

    /// Serialises queries: the handlers have no captures, so one query owns [`SLOT`] at a time.
    static QUERY: Mutex<()> = Mutex::new(());
    static SLOT: Mutex<Slot> = Mutex::new(Slot {
        update: None,
        cancelled: false,
    });
    static CHANGED: Condvar = Condvar::new();

    thread_local! {
        /// Interface names collected by [`ON_IFACE`], which the framework calls synchronously
        /// inside `nw_path_enumerate_interfaces` on the queue's thread.
        static IFACES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    /// A lock that survives a panic elsewhere: the handlers run on the framework's thread and
    /// must never unwind.
    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        m.lock().unwrap_or_else(PoisonError::into_inner)
    }

    unsafe extern "C" fn on_update(_block: *const c_void, path: Obj) {
        IFACES.with_borrow_mut(Vec::clear);
        // SAFETY: `path` is the live nw_path_t the framework passes for the duration of this
        // call; the enumerator is a global block, called synchronously.
        let u = unsafe {
            nw_path_enumerate_interfaces(path, (&raw const ON_IFACE).cast());
            Update {
                satisfied: nw_path_get_status(path) == STATUS_SATISFIED,
                expensive: nw_path_is_expensive(path),
                constrained: nw_path_is_constrained(path),
                ifaces: IFACES.with_borrow_mut(std::mem::take),
            }
        };
        let mut s = lock(&SLOT);
        if s.update.is_none() {
            s.update = Some(u);
        }
        CHANGED.notify_all();
    }

    unsafe extern "C" fn on_cancel(_block: *const c_void) {
        lock(&SLOT).cancelled = true;
        CHANGED.notify_all();
    }

    unsafe extern "C" fn on_iface(_block: *const c_void, interface: Obj) -> bool {
        // SAFETY: `interface` is a live nw_interface_t for this call; its name is a
        // NUL-terminated string it owns, copied before returning.
        let name = unsafe { nw_interface_get_name(interface) };
        if !name.is_null() {
            // SAFETY: as above.
            let name = unsafe { CStr::from_ptr(name) }
                .to_string_lossy()
                .into_owned();
            IFACES.with_borrow_mut(|v| v.push(name));
        }
        true
    }

    /// Wait on [`CHANGED`] until `done` holds or `timeout` passes; returns whether it held.
    fn wait(timeout: Duration, done: impl Fn(&Slot) -> bool) -> bool {
        let s = lock(&SLOT);
        let (s, _) = CHANGED
            .wait_timeout_while(s, timeout, |s| !done(s))
            .unwrap_or_else(PoisonError::into_inner);
        done(&s)
    }

    /// The first update of a fresh path monitor.
    pub fn current_path(timeout: Duration) -> io::Result<Update> {
        let _q = lock(&QUERY);
        *lock(&SLOT) = Slot::default();
        // SAFETY: a NUL-terminated label; a null attribute makes a serial queue. The result is
        // owned here and released below.
        let queue =
            unsafe { dispatch_queue_create(c"pathtrace.netpath".as_ptr(), std::ptr::null()) };
        if queue.is_null() {
            return Err(io::Error::other("dispatch_queue_create returned null"));
        }
        // SAFETY: no arguments; the monitor is owned here and released below.
        let monitor = unsafe { nw_path_monitor_create() };
        if monitor.is_null() {
            // SAFETY: `queue` is owned here and released once.
            unsafe { dispatch_release(queue) };
            return Err(io::Error::other("nw_path_monitor_create returned null"));
        }
        // SAFETY: `monitor` and `queue` are live; the handlers are global blocks that outlive
        // the monitor (the framework's Block_copy of a global block is the block itself).
        unsafe {
            nw_path_monitor_set_queue(monitor, queue);
            nw_path_monitor_set_update_handler(monitor, (&raw const ON_UPDATE).cast());
            nw_path_monitor_set_cancel_handler(monitor, (&raw const ON_CANCEL).cast());
            nw_path_monitor_start(monitor);
        }
        let got = wait(timeout, |s| s.update.is_some());
        // SAFETY: `monitor` is live and started; cancel is asynchronous and ends with the
        // cancel handler, after which no update is delivered.
        unsafe { nw_path_monitor_cancel(monitor) };
        // A late update after an unconfirmed cancel only lands in the next query's slot, which
        // it resets first; the update describes the same system path either way.
        wait(Duration::from_secs(1), |s| s.cancelled);
        // SAFETY: both objects are owned here and released once; the monitor retains its queue
        // for as long as it needs it.
        unsafe {
            nw_release(monitor);
            dispatch_release(queue);
        }
        if !got {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no Network.framework path update",
            ));
        }
        Ok(lock(&SLOT).update.take().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn unsupported_on_linux() {
        let e = path_cost("eth0", Duration::from_secs(1)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    }

    /// A path update arrives on any Mac, CI runners included, also with no route: a name no
    /// path uses reads as `None`, and a second query works after the first one's cancel.
    #[cfg(target_os = "macos")]
    #[test]
    fn update_arrives_for_unused_name() {
        for _ in 0..2 {
            let c = path_cost("pt-none0", Duration::from_secs(5)).expect("a path update");
            assert_eq!(c, None);
        }
    }

    /// The default route's egress interface reads without error; whether it is on the path
    /// depends on the host (a VPN can own the default path).
    #[cfg(target_os = "macos")]
    #[test]
    fn egress_interface_reads() {
        let Ok(ip) = crate::netif::local_addr_for("192.0.2.1:9".parse().unwrap()) else {
            return;
        };
        let Some(iface) = crate::netif::iface_with_addr(ip).ok().flatten() else {
            return;
        };
        let c = path_cost(&iface, Duration::from_secs(5)).expect("a path update");
        eprintln!("{iface}: {c:?}");
    }
}
