//! Linux system interface for PathTrace. The only workspace crate allowed `unsafe`; every
//! unsafe block documents why it is sound.
//!
//! Facts relied upon are verified in docs/research/R-0010 … R-0013.

pub mod clock;
pub mod netif;
pub mod netlink;
pub mod tcp;
pub mod udp;

use std::io;

/// Convert a libc return value into `io::Result`.
pub(crate) fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

pub(crate) fn cvt_ssize(ret: libc::ssize_t) -> io::Result<usize> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

/// `setsockopt` for plain-old-data values.
pub(crate) fn setsockopt<T: Copy>(
    fd: libc::c_int,
    level: libc::c_int,
    name: libc::c_int,
    val: T,
) -> io::Result<()> {
    // SAFETY: `val` is a live, properly aligned `T` for the duration of the call and we pass
    // its exact size; the kernel only reads `size_of::<T>()` bytes.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&raw const val).cast::<libc::c_void>(),
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    cvt(r).map(|_| ())
}

/// `getsockopt` for an `int` option.
pub(crate) fn getsockopt_int(
    fd: libc::c_int,
    level: libc::c_int,
    name: libc::c_int,
) -> io::Result<libc::c_int> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `v` and `len` are valid for writes; `len` holds the buffer size.
    let r = unsafe { libc::getsockopt(fd, level, name, (&raw mut v).cast(), &mut len) };
    cvt(r).map(|_| v)
}
