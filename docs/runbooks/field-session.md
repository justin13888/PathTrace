# Runbook: capture traces on real networks

Goal: one trustworthy `.ptf` trace per session, labelled so that class-level conclusions are possible later (REQ-PRB-028, issue #16).

## Before each session

1. Connect to the network and note what it is (class, venue).
2. Close large downloads, sync clients and video calls on the laptop. Local traffic competes with the probe (interface counters are recorded, so it is visible, but it biases capacity).
3. Plug in the laptop: power saving adds timing noise.

## Run

```sh
cd ~/traces
pathtrace probe vm --class <class> --label "<venue / notes>" [--mobility walking|vehicle|train|flight] [--tag <tag>]…
```

- `--class` is one of `home office hotel-wifi cafe airport cellular-4g cellular-5g train in-flight tether satellite lab other`.
- `--label` is free text (for example, "Hotel X lobby 3rd floor"). Redaction removes it before sharing.
- The profile defaults to `auto`: `light` (≤ 2 MB) on connections NetworkManager reports as metered, `standard` (≤ 200 MB, about 100 s) otherwise. Force a profile with `--profile light|standard|deep`. `deep` adds `--track-secs` (default 600) of tracking with periodic short saturations, for trains and flights.

Don't use the laptop's network during the session. Moving is fine: set `--mobility`, and address changes are recorded.

## Results

| Exit code | Meaning | Action |
|---|---|---|
| 0 | Complete trace | Nothing |
| 3 | Partial trace (for example, the responder log could not be fetched, or phases failed) | Keep it. If a `pathtrace fetch …` command was printed, run it later from any network, then `pathtrace merge <id>.a.ptflog <id>.b.ptflog -o <id>.ptf` |
| 1 | No session (responder unreachable, keys) | `pathtrace doctor vm` |

Each session leaves `<id>.a.ptflog` (laptop raw log), `<id>.b.ptflog` (responder raw log) and `<id>.ptf` (merged and derived trace). **Keep all three.** The logs are the raw evidence, and the trace can always be rebuilt from them.

Check a trace:

```sh
pathtrace trace check <id>.ptf
pathtrace trace info <id>.ptf | head -40
pathtrace export netem <id>.ptf          # static summary as netem arguments
```

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
