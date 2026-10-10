# conformance/v1.0-real/

Golden traces captured by a real `pathtrace` session, kept forever so that every later release proves it still reads PTF 1.0 (REQ-FMT-010).

| File | Provenance |
|---|---|
| `smoke-ipv6-netns-anonymous.ptf` | `smoke` profile over IPv6 in the ground-truth harness (`cargo xtask groundtruth ipv6`, netem 10 ms / 20 Mbit/s each way), derived, then `trace redact --level anonymous` (wall clock shifted, identifying fields removed). Tool commit: see the trace's META |

`expected.json` holds the content digest. Readers must accept the file and reproduce the digest.
