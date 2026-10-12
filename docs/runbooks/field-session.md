# Runbook: capture traces on real networks

Goal: one trustworthy `.ptf` trace per session, labelled so that class-level conclusions are possible later (REQ-PRB-028, issue #16).

## What you need

A session always has two Linux machines (x86_64 or aarch64, kernel ≥ 6.1), both under your control, with `pathtrace` installed on each:

- **Initiator**: the machine physically on the network you want to record (your laptop at the hotel, café or on the train). It runs `pathtrace probe`, so the trace describes the path from where it sits.
- **Responder**: a second machine with a stable, publicly reachable address (a VM or a home server with the ports in [deploy/README.md](../../deploy/README.md) open). It runs `pathtrace serve` under systemd and never initiates anything.

Set up the responder and pair the two once with [responder-deploy.md](responder-deploy.md); its smoke session must pass before the first field session. The responder must not sit on the network being measured, or the path under test is not the one the trace records.

Which release to use: for every field session, both machines run the first release that contains PR #37 and PR #39, or a build from source of `main` after both merged. Do not use v1.0.1 on any network. It lacks the capture hardening of PR #37 that the steps below rely on (the `.session` file, the clean Ctrl-C exit 3, `fetch --resume`, the merge checks and host-drop accounting), and on real paths it loses observations that cannot be recaptured afterwards. It also ramps saturations too slowly on paths with an RTT of about 300 ms or more (GEO satellite, in-flight Wi-Fi; issue #30, fixed by PR #39).

## Before each session

1. Connect to the network and note what it is (class, venue).
2. Close large downloads, sync clients and video calls on the laptop. Local traffic competes with the probe (interface counters are recorded, so it is visible, but it biases capacity).
3. Plug in the laptop: power saving adds timing noise.
4. Run `pathtrace doctor vm`. It exits 1 only when a session cannot work (old kernel, no key, the responder's port unreachable, intercepted or not tested for interception on every address family). Read the warnings too:
   - `tcp/<port> not intercepted` warns with an answer, or `tcp/<port> reachable` failed on every port: a captive portal. Log in through a browser, then run `doctor` again. If it warns `not tested`, the connection failed the second time; run `doctor` again. A trace taken behind an unopened portal records the portal, not the path.
   - `udp/<port> not refused` warns `refused`: this network (or the responder) rejects that UDP port. The session still runs and records the UDP classes on that port as blocked (all of them, over a TCP-only session, when the responder port itself is refused). `not refused` does not prove that UDP arrives: only a session can, so the probe's own result is the final word.
   - `clock sync` warns: start an NTP daemon (chrony, or `timedatectl set-ntp true`) and wait until `doctor` reports it synchronised. Check the responder the same way once, with `pathtrace doctor` on it.
   - `power` warns: the laptop is on battery (step 3). `cpu governor` warns: the governor pins the lowest frequency; switch to `schedutil` or `performance` for the session.
   - `offloads` warns: `rx-gro-list` or `rx-lro` is on for the egress interface, which changes what the probe records on this host. Run the `sudo ethtool -K …` command the warning prints (it lasts until reboot or until the interface is recreated), then run `doctor` again. Run `pathtrace doctor` on the responder too: its default-route interface is checked the same way. `rx-gro` and the segmentation offloads are listed but do not warn.
   - `ipv6` warns: the network or the responder has no IPv6, so only IPv4 is tested (and the probe uses IPv4). Checks with an ` (ipv6)` suffix cover the second family when both exist.

## Run

```sh
cd ~/traces
pathtrace probe vm --class <class> --label "<venue / notes>" [--mobility walking|vehicle|train|flight] [--tag <tag>]…
```

- `--class` is one of `home office hotel-wifi cafe airport cellular-4g cellular-5g train in-flight tether satellite lab other`.
- `--label` is free text (for example, "Hotel X lobby 3rd floor"). Redaction removes it before sharing.
- The profile defaults to `auto`: `light` (≤ 2 MB) on connections NetworkManager reports as metered, `standard` (≤ 200 MB sent per endpoint, so up to about 400 MB through the laptop's link, about 100 s) otherwise. The probe prints its choice first (`[pathtrace] profile auto: …`). Without NetworkManager `auto` cannot tell, picks `standard`, and prints a `warning: profile auto: standard, but the metered state … is unknown` line: on a metered or capped connection (hotspot, roaming SIM, in-flight Wi-Fi) pass `--profile light` yourself. Phone hotspots are usually not flagged as metered even with NetworkManager, so check the printed state. `deep` adds `--track-secs` (default 600) of tracking with periodic short saturations, for trains and flights. On fast connections the saturation phases get shorter so that every phase fits the cap.

Don't use the laptop's network during the session. Moving is fine: set `--mobility`, and address changes are recorded. The light trains and the PMTU ladder pause through short outages and continue afterwards.

If the responder's name has both an IPv4 and an IPv6 address, the probe uses IPv4 unless you pass `--ipv6`. When the preferred family does not work from where you are (no IPv6 on the hotel Wi-Fi, or no IPv4 on an IPv6-only or NAT64 cellular network), the probe uses the other family and prints `[pathtrace] ipv6 unusable (…); session runs over ipv4 …` (or the reverse). The trace is still complete; it records the family it ran on.

If UDP is blocked, the probe falls back to TCP (port 443, then 4433). It then measures only TCP reachability and the TCP reference flows, skips every UDP phase, and exits 3 with `note: UDP control blocked; session ran over TCP fallback`. That is a finding about the network: keep the trace.

Right after connecting, the probe prints the session id and writes `<id>.session` next to the logs. **Keep it until the trace is complete**: it is what fetches the responder's half later. Ctrl-C ends the session early but cleanly (the probe still fetches and merges, exit 3); a second Ctrl-C quits at once.

## Results

| Exit code | Meaning | Action |
|---|---|---|
| 0 | Complete trace | Nothing |
| 3 | Partial trace (for example, the responder log could not be fetched, phases failed, UDP was blocked so only TCP was measured, or you pressed Ctrl-C) | Keep it. If the responder log is missing, run `pathtrace fetch --resume <id>.session` later from any network (TLS on the responder's port, else 443), then `pathtrace merge <id>.a.ptflog <id>.b.ptflog -o <id>.ptf` and delete `<id>.session` |
| 1 | No session (responder unreachable, keys) | `pathtrace doctor vm` |
| 1 with `error: responder busy` | The responder is running another initiator's session (it runs one at a time) | Wait for that session to finish (about 2 minutes for `standard`; `deep` runs longer) and run the probe again |

Each session leaves `<id>.a.ptflog` (laptop raw log), `<id>.b.ptflog` (responder raw log) and `<id>.ptf` (merged and derived trace). **Keep all three.** The logs are the raw evidence, and the trace can always be rebuilt from them. `<id>.session` is deleted automatically once the trace is complete.

Check a trace:

```sh
pathtrace trace check <id>.ptf
pathtrace trace info <id>.ptf | head -40
pathtrace export netem <id>.ptf          # static summary as netem arguments
```

`trace info` shows `merge_checks`: `txts_implausible` should be 0 in both directions, and `txts_unexplained_a`/`txts_unexplained_b` should be 0 (otherwise the probe also warned at the end of the session). Host-side drops are separated from path loss, and `trace info` shows them per direction: `host_drops` (the receiving socket overflowed; `packets` never exceeds `socket_drops`, and `ambiguous_losses` counts losses in a socket-drop gap that could be either) and `local_qdisc_drops` (the laptop's own queue). `pathtrace trace dump <id>.ptf` shows the whole PATH section. Non-zero values are not errors, but they mean the host, not the path, lost those packets: close other traffic and retry if they are large.

## Sampling plan (draft spec §12)

- Repeat sessions on the same network at different times of day. Variation within a network is often larger than between networks.
- Before trusting a class-level conclusion, aim for at least 20–30 sessions across at least 5 distinct networks in that class.
- Minimum corpus for the v1.0 field acceptance (#16): 50 traces across 4 classes.

## Privacy

Traces contain your public IP addresses, hostname, Wi-Fi BSSID (hashed), labels and timestamps. All of these are marked `pii` in the file. Never publish raw traces; share redacted copies instead:

```sh
pathtrace trace redact <id>.ptf --level shareable -o <id>.shareable.ptf   # removes identifying data
pathtrace trace redact <id>.ptf --level anonymous -o <id>.anon.ptf        # also network details, wall-clock time
```

## Later: improved derivation

Derivation methods improve over time. Re-derive any trace with the newest release:

```sh
pathtrace derive <id>.ptf                # rewrites PATH/SERS/PLCY/VALD; raw sections untouched
```
