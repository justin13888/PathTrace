//! Interface feature flags (offloads) through the read-only `SIOCETHTOOL` ioctl (R-0016,
//! docs/design/cli.md "`doctor` reads offloads with `SIOCETHTOOL`").
//!
//! Three unprivileged commands: `ETHTOOL_GSSET_INFO` for the number of feature names,
//! `ETHTOOL_GSTRINGS` for the names, and `ETHTOOL_GFEATURES` for four bit-blocks per 32 features.
//!
//! ethtool is Linux only: on macOS [`features`] fails with
//! [`std::io::ErrorKind::Unsupported`].

#[cfg(target_os = "macos")]
use std::io;

#[cfg(target_os = "linux")]
pub use linux::features;

/// Every feature of interface `ifname`: ethtool is unavailable on macOS.
#[cfg(target_os = "macos")]
pub fn features(_ifname: &str) -> io::Result<Vec<Feature>> {
    Err(crate::unsupported("ethtool"))
}

/// One device feature (`ethtool -k` line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feature {
    /// Kernel name, e.g. `rx-gro`, `tx-tcp-segmentation`.
    pub name: String,
    /// The device can toggle it (`hw_features`).
    pub available: bool,
    /// The user asked for it (`wanted_features`).
    pub requested: bool,
    /// In effect now (`features`).
    pub active: bool,
    /// Can never change (`NETIF_F_NEVER_CHANGE`). `ethtool -k` prints `[fixed]` for this or
    /// for a feature that is not `available`.
    pub never_changed: bool,
}

#[cfg(target_os = "linux")]
mod linux {
    use super::Feature;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const SIOCETHTOOL: libc::c_ulong = 0x8946;
    const ETHTOOL_GSTRINGS: u32 = 0x1b;
    const ETHTOOL_GSSET_INFO: u32 = 0x37;
    const ETHTOOL_GFEATURES: u32 = 0x3a;
    const ETH_SS_FEATURES: u32 = 4;
    const ETH_GSTRING_LEN: usize = 32;
    /// Far above the kernel's feature count (64 bits of `netdev_features_t` in 7.2); bounds the
    /// buffers if a driver reports nonsense.
    const MAX_FEATURES: usize = 1024;

    /// `struct ifreq` with `ifr_data`: 16-byte name, then the 24-byte union on 64-bit Linux.
    #[repr(C)]
    struct IfReq {
        name: [u8; libc::IFNAMSIZ],
        data: *mut libc::c_void,
        _pad: [u8; 16],
    }

    /// `struct ethtool_sset_info` asking for exactly one set, so `data` holds one count.
    #[repr(C)]
    struct SsetInfo {
        cmd: u32,
        reserved: u32,
        sset_mask: u64,
        data: [u32; 1],
    }

    fn ioctl(fd: &OwnedFd, ifname: &str, data: *mut libc::c_void) -> io::Result<()> {
        let mut req = IfReq {
            name: [0; libc::IFNAMSIZ],
            data,
            _pad: [0; 16],
        };
        let b = ifname.as_bytes();
        if b.is_empty() || b.len() >= libc::IFNAMSIZ || b.contains(&0) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        req.name[..b.len()].copy_from_slice(b);
        // SAFETY: `req` is a live ifreq naming a NUL-terminated interface; `data` points at a
        // buffer the caller sized for the ethtool command in its first word, which the kernel
        // writes within those bounds: GFEATURES copies at most the caller's `size` blocks,
        // GSSET_INFO one u32 per bit set in `sset_mask`, and GSTRINGS the feature set's count, a
        // kernel compile-time constant that GSSET_INFO reported and the caller sized for (R-0016).
        crate::cvt(unsafe { libc::ioctl(fd.as_raw_fd(), SIOCETHTOOL as _, &raw mut req) })
            .map(|_| ())
    }

    fn socket() -> io::Result<OwnedFd> {
        // Any socket in this network namespace reaches dev_ioctl; IPv4 then IPv6 for hosts
        // without one of them.
        for fam in [libc::AF_INET, libc::AF_INET6] {
            // SAFETY: plain socket(2); the returned descriptor is owned below.
            let fd = unsafe { libc::socket(fam, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            if fd >= 0 {
                // SAFETY: `fd` is a fresh descriptor nothing else owns.
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
        Err(io::Error::last_os_error())
    }

    /// Bits `i` of the four blocks of `GFEATURES`, laid out as `[cmd, size, {available,
    /// requested, active, never_changed} * size]`.
    fn decode(names: Vec<String>, words: &[u32]) -> Vec<Feature> {
        let blocks = &words[2..];
        names
            .into_iter()
            .enumerate()
            .filter_map(|(i, name)| {
                let b = blocks.get(i / 32 * 4..i / 32 * 4 + 4)?;
                let bit = |w: u32| w & (1 << (i % 32)) != 0;
                Some(Feature {
                    name,
                    available: bit(b[0]),
                    requested: bit(b[1]),
                    active: bit(b[2]),
                    never_changed: bit(b[3]),
                })
            })
            .collect()
    }

    /// Name of one `ETH_GSTRING_LEN` slot: bytes up to the first NUL.
    fn slot_name(slot: &[u8]) -> String {
        let end = slot.iter().position(|&c| c == 0).unwrap_or(slot.len());
        String::from_utf8_lossy(&slot[..end]).into_owned()
    }

    /// Every feature of interface `ifname`, in kernel order. Unprivileged and read-only.
    pub fn features(ifname: &str) -> io::Result<Vec<Feature>> {
        let fd = socket()?;
        let mut info = SsetInfo {
            cmd: ETHTOOL_GSSET_INFO,
            reserved: 0,
            sset_mask: 1 << ETH_SS_FEATURES,
            data: [0],
        };
        ioctl(&fd, ifname, (&raw mut info).cast())?;
        // The kernel clears the bit of a set it does not know.
        if info.sset_mask & (1 << ETH_SS_FEATURES) == 0 {
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
        let n = info.data[0] as usize;
        if n == 0 || n > MAX_FEATURES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{n} features"),
            ));
        }
        // `struct ethtool_gstrings`: cmd, string_set, len, then `len` 32-byte names. u32 words keep
        // the header aligned.
        let mut strings = vec![0u32; 3 + n * ETH_GSTRING_LEN / 4];
        strings[0] = ETHTOOL_GSTRINGS;
        strings[1] = ETH_SS_FEATURES;
        strings[2] = n as u32;
        ioctl(&fd, ifname, strings.as_mut_ptr().cast())?;
        let got = (strings[2] as usize).min(n);
        let bytes: Vec<u8> = strings[3..].iter().flat_map(|w| w.to_ne_bytes()).collect();
        let names: Vec<String> = bytes
            .as_chunks::<ETH_GSTRING_LEN>()
            .0
            .iter()
            .take(got)
            .map(|s| slot_name(s))
            .collect();
        let size = n.div_ceil(32);
        // `struct ethtool_gfeatures`: cmd, size, then `size` blocks of four u32.
        let mut words = vec![0u32; 2 + 4 * size];
        words[0] = ETHTOOL_GFEATURES;
        words[1] = size as u32;
        ioctl(&fd, ifname, words.as_mut_ptr().cast())?;
        Ok(decode(names, &words))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn decodes_blocks() {
            let names: Vec<String> = (0..34).map(|i| format!("f{i}")).collect();
            // Block 0: f1 available, f2 requested, f3 active, f4 never changed. Block 1: f33 active.
            let words = [
                ETHTOOL_GFEATURES,
                2,
                0b10,
                0b100,
                0b1000,
                0b10000,
                0,
                0,
                0b10,
                0,
            ];
            let f = decode(names, &words);
            assert_eq!(f.len(), 34);
            assert!(f[1].available && !f[1].active);
            assert!(f[2].requested && !f[2].available);
            assert!(f[3].active && !f[3].never_changed);
            assert!(f[4].never_changed);
            assert!(f[33].active && f[33].name == "f33");
            assert!(!f[32].active);
            // A name past the blocks the kernel returned is dropped, not misread.
            assert_eq!(decode(vec!["a".into(); 40], &words[..6]).len(), 32);
        }

        #[test]
        fn slot_names() {
            let mut s = [0u8; ETH_GSTRING_LEN];
            s[..6].copy_from_slice(b"rx-gro");
            assert_eq!(slot_name(&s), "rx-gro");
            assert_eq!(slot_name(&[b'x'; ETH_GSTRING_LEN]).len(), ETH_GSTRING_LEN);
        }

        #[test]
        fn loopback_features() {
            let f = features("lo").expect("lo features");
            let gro = f.iter().find(|x| x.name == "rx-gro").expect("rx-gro");
            assert!(gro.active, "{gro:?}");
            assert!(f.iter().any(|x| x.name == "tx-tcp-segmentation"));
            assert!(features("no-such-if0").is_err());
            assert!(features("").is_err());
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn unsupported_on_macos() {
        let e = features("lo0").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    }
}
