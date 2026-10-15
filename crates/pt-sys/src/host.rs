//! Host identity (probe.md §9.8): on macOS the OS version, Darwin release, CPU model and host
//! name come from sysctl strings; Linux reads them from procfs and `/etc/os-release`, which
//! need no system call wrapper, so [`sysctl_string`] returns `None` there.

/// A string sysctl by name (`kern.osproductversion`, `kern.osrelease`, `kern.hostname`,
/// `machdep.cpu.brand_string`), unprivileged; `None` if it does not exist or is not text.
#[cfg(target_os = "macos")]
pub fn sysctl_string(name: &str) -> Option<String> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut len = 0usize;
    // SAFETY: a size query: `cname` is NUL-terminated, the output buffer is null and `len`
    // receives the size; nothing is set.
    let r = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != 0 || len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    // SAFETY: `buf` has `len` writable bytes and `len` says so; the kernel writes at most that
    // and stores the written length back; nothing is set.
    let r = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != 0 {
        return None;
    }
    buf.truncate(len);
    let text = buf.split(|b| *b == 0).next().unwrap_or(&[]);
    let s = std::str::from_utf8(text).ok()?.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// A string sysctl by name: not used on Linux, where the same facts are files.
#[cfg(target_os = "linux")]
pub fn sysctl_string(_name: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn reads_macos_identity() {
        let v = sysctl_string("kern.osproductversion").expect("product version");
        assert!(
            v.split('.').next().unwrap().parse::<u32>().unwrap() >= 11,
            "{v}"
        );
        let rel = sysctl_string("kern.osrelease").expect("Darwin release");
        assert!(rel.contains('.'), "{rel}");
        assert!(sysctl_string("machdep.cpu.brand_string").is_some());
        assert_eq!(sysctl_string("kern.no_such_sysctl"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_has_no_sysctl_strings() {
        assert_eq!(sysctl_string("kern.osproductversion"), None);
    }
}
