//! Keys, pairing and on-disk configuration (docs/design/probe.md §2, REQ-SEC-002).
//!
//! Files (all mode 0600, refused if group/other-readable):
//! - `<config>/key`: two hex lines, X25519 private then public key.
//! - `<config>/authorized_keys` (responder): `<initiator-pub-hex> <psk-hex> <label>` per line.
//! - `<config>/responders` (initiator): `<name> <host:port> <pairing-string>` per line.
//!
//! Pairing string: `pt1:<responder-pub-hex>:<psk-hex>`.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const NOISE_PATTERN: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex32(s: &str) -> io::Result<[u8; 32]> {
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected 64 hex chars, got {s:?}"),
        )
    };
    if s.len() != 64 {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

/// Default configuration directory: `$XDG_CONFIG_HOME/pathtrace` or `~/.config/pathtrace`.
pub fn default_config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("pathtrace")
}

/// Default state directory (responder logs): `$XDG_STATE_HOME/pathtrace` or `~/.local/state/pathtrace`.
pub fn default_state_dir() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("pathtrace")
}

fn write_private(path: &Path, content: &str, append: bool) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .mode(0o600)
        .open(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    f.write_all(content.as_bytes())
}

/// Write a secret file (mode 0600) without touching its directory's permissions.
pub fn write_secret(path: &Path, content: &str) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    f.write_all(content.as_bytes())
}

/// Read a secret file, refusing group- or world-accessible permissions.
pub fn read_private(path: &Path) -> io::Result<String> {
    let meta = fs::metadata(path)?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is accessible by group/other; run: chmod 600 {}",
                path.display(),
                path.display()
            ),
        ));
    }
    fs::read_to_string(path)
}

pub fn generate_keypair() -> Keypair {
    let kp = snow::Builder::new(NOISE_PATTERN.parse().expect("valid pattern"))
        .generate_keypair()
        .expect("key generation");
    Keypair {
        private: kp.private.as_slice().try_into().expect("32"),
        public: kp.public.as_slice().try_into().expect("32"),
    }
}

/// Create `<dir>/key` if absent; return the keypair.
pub fn keygen(dir: &Path, force: bool) -> io::Result<(Keypair, bool)> {
    let path = dir.join("key");
    if path.exists() && !force {
        return Ok((load_keypair(dir)?, false));
    }
    let kp = generate_keypair();
    write_private(
        &path,
        &format!("{}\n{}\n", hex(&kp.private), hex(&kp.public)),
        false,
    )?;
    Ok((kp, true))
}

pub fn load_keypair(dir: &Path) -> io::Result<Keypair> {
    let path = dir.join("key");
    let text = read_private(&path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("{}: {e}; run `pathtrace keygen`", path.display()),
        )
    })?;
    let mut lines = text.lines();
    let private = unhex32(lines.next().unwrap_or("").trim())?;
    let public = unhex32(lines.next().unwrap_or("").trim())?;
    Ok(Keypair { private, public })
}

pub fn random32() -> [u8; 32] {
    // A fresh keypair's private scalar is 32 bytes from the OS RNG (via snow/getrandom).
    generate_keypair().private
}

/// An initiator authorised on the responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorized {
    pub public: [u8; 32],
    pub psk: [u8; 32],
    pub label: String,
}

pub fn pairing_string(responder_pub: &[u8; 32], psk: &[u8; 32]) -> String {
    format!("pt1:{}:{}", hex(responder_pub), hex(psk))
}

pub fn parse_pairing(s: &str) -> io::Result<([u8; 32], [u8; 32])> {
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() != 3 || parts[0] != "pt1" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pairing string must be pt1:<pub>:<psk>",
        ));
    }
    Ok((unhex32(parts[1])?, unhex32(parts[2])?))
}

/// Authorise an initiator key; returns the pairing string to give to the initiator.
pub fn authorize(dir: &Path, initiator_pub: &[u8; 32], label: &str) -> io::Result<String> {
    let kp = load_keypair(dir)?;
    if label.chars().any(char::is_whitespace) || label.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "label must be non-empty without spaces",
        ));
    }
    let psk = random32();
    write_private(
        &dir.join("authorized_keys"),
        &format!("{} {} {label}\n", hex(initiator_pub), hex(&psk)),
        true,
    )?;
    Ok(pairing_string(&kp.public, &psk))
}

pub fn load_authorized(dir: &Path) -> io::Result<Vec<Authorized>> {
    let path = dir.join("authorized_keys");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for line in read_private(&path)?.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 || line.trim_start().starts_with('#') {
            continue;
        }
        out.push(Authorized {
            public: unhex32(f[0])?,
            psk: unhex32(f[1])?,
            label: f[2].to_string(),
        });
    }
    Ok(out)
}

/// A responder known to the initiator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Responder {
    pub name: String,
    pub addr: String,
    pub public: [u8; 32],
    pub psk: [u8; 32],
}

pub fn add_responder(dir: &Path, name: &str, addr: &str, pairing: &str) -> io::Result<()> {
    let _ = parse_pairing(pairing)?;
    if load_responders(dir)?.iter().any(|r| r.name == name) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("responder {name} already exists"),
        ));
    }
    write_private(
        &dir.join("responders"),
        &format!("{name} {addr} {}\n", pairing.trim()),
        true,
    )
}

pub fn load_responders(dir: &Path) -> io::Result<Vec<Responder>> {
    let path = dir.join("responders");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for line in read_private(&path)?.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 || line.trim_start().starts_with('#') {
            continue;
        }
        let (public, psk) = parse_pairing(f[2])?;
        out.push(Responder {
            name: f[0].to_string(),
            addr: f[1].to_string(),
            public,
            psk,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_authorize_pair() {
        let base = std::env::temp_dir().join(format!("pt-cfg-{}", std::process::id()));
        let (r, s) = (base.join("resp"), base.join("init"));
        let (rk, new) = keygen(&r, false).unwrap();
        assert!(new);
        assert_eq!(keygen(&r, false).unwrap().0, rk);
        let (ik, _) = keygen(&s, false).unwrap();
        let pairing = authorize(&r, &ik.public, "laptop").unwrap();
        let auth = load_authorized(&r).unwrap();
        assert_eq!(auth[0].public, ik.public);
        add_responder(&s, "vm", "192.0.2.1:4433", &pairing).unwrap();
        let resp = load_responders(&s).unwrap();
        assert_eq!(resp[0].public, rk.public);
        assert_eq!(resp[0].psk, auth[0].psk);
        let mode = fs::metadata(r.join("key")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::set_permissions(r.join("key"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_keypair(&r).is_err());
        let _ = fs::remove_dir_all(&base);
    }
}
