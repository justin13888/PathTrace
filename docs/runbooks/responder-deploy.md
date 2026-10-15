# Runbook: deploy the responder

Goal: a public Linux VM running `pathtrace serve` under systemd, paired with your laptop.

## Prerequisites

- A Linux VM with a public IPv4 address (IPv6 too if available): x86_64 or aarch64, kernel ≥ 6.1 (Ubuntu 24.04, Debian 12 or newer). Prefer a region near where you travel; one region is fine.
- Cloud firewall / security group open inbound for: UDP 4433, TCP 4433, TCP 443, UDP 443, TCP 80 ([deploy/README.md](../../deploy/README.md)).
- Your laptop runs Linux (x86_64 or aarch64), kernel ≥ 6.1, or macOS 15 or newer on Apple silicon (aarch64). Only Linux and macOS are supported targets (ADR 0014): the laptop (initiator) may be either; the responder runs Linux only.
- Reaching the responder only through Tailscale (no public ports): see [Overlay responder (Tailscale)](#overlay-responder-tailscale) instead of the cloud firewall rules.

## 1. Install the binary (both machines)

Download the release tarball for each machine's architecture from the GitHub release page, verify it, and install.

### Linux (the VM, and a Linux laptop)

```sh
VER=v1.1.0            # the release you are installing; both machines run the same release (field-session.md)
ARCH=x86_64           # or aarch64
curl -fLO https://github.com/justin13888/PathTrace/releases/download/$VER/pathtrace-$VER-$ARCH-unknown-linux-musl.tar.gz
curl -fLO https://github.com/justin13888/PathTrace/releases/download/$VER/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar xzf pathtrace-$VER-$ARCH-unknown-linux-musl.tar.gz
sudo install -m 0755 pathtrace-$VER-$ARCH-unknown-linux-musl/pathtrace /usr/local/bin/pathtrace
pathtrace --version
```

### macOS laptop (Apple silicon)

The macOS archive (`aarch64-apple-darwin`) is published from the first release after v1.1.0; v1.1.0 has Linux archives only. Install the same release on the VM.

```sh
VER=vX.Y.Z            # a release that lists pathtrace-vX.Y.Z-aarch64-apple-darwin.tar.gz
curl -fLO https://github.com/justin13888/PathTrace/releases/download/$VER/pathtrace-$VER-aarch64-apple-darwin.tar.gz
curl -fLO https://github.com/justin13888/PathTrace/releases/download/$VER/SHA256SUMS
shasum -a 256 --ignore-missing -c SHA256SUMS
tar xzf pathtrace-$VER-aarch64-apple-darwin.tar.gz
sudo mkdir -p /usr/local/bin
sudo install -m 0755 pathtrace-$VER-aarch64-apple-darwin/pathtrace /usr/local/bin/pathtrace
pathtrace --version
```

Expected: `pathtrace-…-aarch64-apple-darwin.tar.gz: OK`, then `pathtrace X.Y.Z`. The archive has no systemd unit: a Mac runs the initiator commands only (`serve` and `authorize` are Linux only).

Gatekeeper: the binary is not notarized (#69). `curl` does not mark its downloads as quarantined, so the commands above run as is. If you downloaded the archive with a browser instead, macOS refuses to open the binary ("cannot be opened because the developer cannot be verified"); after the checksum passes, clear the quarantine flag with `xattr -d com.apple.quarantine /usr/local/bin/pathtrace` and run `pathtrace --version` again. Do not clear it for a binary whose checksum did not verify.

Building from source instead (either OS): `mise install && cargo build --release -p pathtrace` gives `target/release/pathtrace`.

## 2. Responder service (VM)

```sh
sudo useradd --system --home /var/lib/pathtrace --create-home --shell /usr/sbin/nologin pathtrace
sudo -u pathtrace env PATHTRACE_CONFIG_DIR=/var/lib/pathtrace/config pathtrace keygen
sudo install -m 0644 pathtrace-$VER-$ARCH-unknown-linux-musl/pathtrace-responder.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pathtrace-responder
journalctl -u pathtrace-responder -n 5
```

Expected log line: `responder ready: udp/4433 (v4+v6), udp/443 yes, tcp/4433, tcp/443, tcp/80`. If `udp/443 no` appears, CAP_NET_BIND_SERVICE did not apply; check the unit file is the shipped one.

## 3. Pair the laptop

On the **laptop**:

```sh
pathtrace keygen                      # prints the laptop public key (64 hex chars)
```

On the **VM**, authorise that key (one line per laptop):

```sh
sudo -u pathtrace env PATHTRACE_CONFIG_DIR=/var/lib/pathtrace/config pathtrace authorize <LAPTOP_PUBKEY> --name laptop
# prints a pairing string: pt1:<responder-pub>:<psk>
```

No restart is needed: authorised keys are re-read on every handshake.

On the **laptop**, register the responder with that pairing string:

```sh
pathtrace responder add vm <VM_PUBLIC_IP_OR_DNS> pt1:...
pathtrace responder list
```

Treat the pairing string as a secret (it contains the pre-shared key). Keys and pairings live in 0600 files under `~/.config/pathtrace/` (laptop) and `/var/lib/pathtrace/config/` (VM). `pathtrace` refuses group- or world-readable key files.

## 4. Verify before travelling

From the laptop on any network:

```sh
pathtrace doctor vm                  # local prerequisites, IPv4/IPv6 reachability, UDP refusals, portals; exits 1 on fatal problems
mkdir -p ~/traces && cd ~/traces
pathtrace probe vm --class home --profile smoke
```

`smoke` takes about 25–30 s and sends at most 50 MB. Expected output ends with `trace: <id>.ptf`, `content_digest: …`, packet counts in both directions, and exit code 0. Then:

```sh
pathtrace trace info <id>.ptf | head -30     # "complete": true
```

## Overlay responder (Tailscale)

Use this when the responder is reachable only through a tailnet (a home server with no public ports, or a VM whose cloud firewall stays closed). Both machines are on the same tailnet, and sections 1 to 4 apply with these changes.

1. **Server firewall.** The cloud firewall needs no PathTrace ports. On a server running firewalld, trust the Tailscale interface so the responder's ports are open on it, and only on it:

   ```sh
   sudo firewall-cmd --permanent --zone=trusted --add-interface=tailscale0
   sudo firewall-cmd --reload
   sudo firewall-cmd --get-zone-of-interface=tailscale0     # expect: trusted
   ```

2. **Pair with the tailnet address.** In step 3, register the responder by its tailnet IP or MagicDNS name, never its public address: `pathtrace responder add vm-ts <host>.<tailnet>.ts.net pt1:...` (or the `100.x.y.z` address from `tailscale ip -4 <host>`).
3. **Direct path, not DERP.** On the laptop, before every session (and once now):

   ```sh
   mkdir -p ~/traces && cd ~/traces
   tailscale ping <host> | tee "$(date -u +%Y%m%dT%H%M%SZ)-tailscale-ping.txt"
   ```

   On a Mac, the Tailscale app does not put a `tailscale` command on `PATH` by default. Turn on its CLI integration (Tailscale menu > Settings > "Show CLI integration", then install it), or call the app's binary directly: `/Applications/Tailscale.app/Contents/MacOS/Tailscale ping <host>`. The same applies to `tailscale ip` in step 2 above and `tailscale netcheck` below.

   The last line must read `pong from <host> (100.x.y.z) via <public-ip>:<port> in N ms`: a direct path. `via DERP(<region>)` means the traffic is relayed through Tailscale's DERP servers over TCP, so a trace would record the relay, not the network: do not record. Fix the direct connection first (UDP 41641 open outbound, `tailscale netcheck` reports `UDP: true`), or record that network without the overlay. Keep the saved output next to the session's trace.
4. **Verify.** `pathtrace doctor vm-ts` warns `tunnel` (`utun*` on a Mac, `tailscale0` on Linux, provider `tailscale`). That warning is expected here; every other check must pass, and the smoke session must complete, as in section 4 above.

Interpretation limits: every probe packet, of every class and transport, travels inside one WireGuard UDP flow between the two Tailscale endpoints. The trace marks this (`trace info` shows `overlay` with `provider: tailscale`), and per-transport treatment, policers, MTU, DSCP and ECN carry `overlay_limited: true`: they describe the tunnel, not the network under it (probe.md §9.9). Capacity, delay, jitter, loss, reorder and queue are still end-to-end measurements of the path the traffic took, tunnel included. A path that switches between direct and DERP during a session changes what the trace describes, so repeat the `tailscale ping` right after the session as well.

## Troubleshooting

| Symptom | Cause / action |
|---|---|
| `responder vm unreachable over UDP 4433 and TCP 443/4433` | Firewall or service down: `systemctl status pathtrace-responder`, check the security group |
| `initiator key not authorized` in `journalctl` | Re-run step 3 with the right laptop key |
| `could not fetch responder log yet …` | The trace is partial (exit 3). Run `pathtrace fetch --resume <id>.session` later (the probe prints the exact command), then `pathtrace merge <id>.a.ptflog <id>.b.ptflog -o <id>.ptf` |
| `warning: … TX stamp joins are implausible` | Transmit stamps could not be matched reliably (kernels before 6.13 predict them). The trace is usable; the raw logs keep every stamp for a later re-merge |
| `warning: … TX stamp ids match no transmission and no burned id` | Transmit ids are likely shifted by one (predicted ids, kernels before 6.13). As above: usable, and the raw logs keep every stamp |
| `wire protocol mismatch` | Laptop and VM run different major versions; install the same release on both |
| Laptop on 1.1, VM still on 1.0 (or the reverse) | Sessions run (same wire major), but a 1.0 responder reports no bytes sent (`sent` feedback) and enforces no byte allowance (`max_bytes`), so a fast path can hit the VM's data cap and stop the light flow early; a 1.0 initiator ignores the responder's `abort` when the VM is stopped mid-session. The peer's wire minor is recorded in META (`extra.<ep>.responder.wire_minor`, `extra.<ep>.initiator_wire_minor`). Upgrade both |
| `doctor` warns about `kernel timestamps` | Traces still work with user-space timestamps (recorded per packet); precision is lower. On Linux the check needs both kernel RX and kernel TX stamps; on a Mac, which has no kernel TX stamps, it needs RX stamps only |
| `doctor` warns `udp/443 not refused` (refused) | The responder does not listen on 443: it runs with `--no-class-ports` or lacks `CAP_NET_BIND_SERVICE`, or a firewall rejects UDP 443. Fix the unit (deploy/README.md) or the security group |
| `doctor` warns `clock sync` on the VM | Run `pathtrace doctor` (no responder) on the VM too; enable chrony or systemd-timesyncd (`timedatectl set-ntp true`) |

## Maintenance

- Session logs: `/var/lib/pathtrace/state/sessions/<id>/`, deleted after 14 days (`--retention-days`). A session's log is fetchable once the session has ended, also after a restart of the service (`systemctl stop` ends a running session cleanly).
- Kernel ≥ 6.13 on both machines gives exact transmit-stamp matching (`tx_ids: explicit` per socket in META `endpoints.<ep>.sockets`, the second line of `pathtrace trace dump <id>.ptf`); older kernels work with predicted ids.
- Upgrading: replace `/usr/local/bin/pathtrace` and run `systemctl restart pathtrace-responder`. Traces from every PTF ≥ 1.0 release stay readable.
