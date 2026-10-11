# deploy/

Artefacts for running the responder on a public Linux VM. Procedure: [docs/runbooks/responder-deploy.md](../docs/runbooks/responder-deploy.md).

| File | Purpose |
|---|---|
| `pathtrace-responder.service` | systemd unit: dedicated `pathtrace` user, `CAP_NET_BIND_SERVICE` only, state in `/var/lib/pathtrace` |

## Ports the responder needs open (cloud firewall / security group)

| Port | Protocol | Purpose | Required |
|---|---|---|---|
| 4433 | UDP | Control, probe flows (`udp/high-port` class) | yes |
| 4433 | TCP | Control fallback, log fetch, `tcp/high-port` class | yes |
| 443 | TCP | TLS reference flows, `tcp/443` class, control fallback | yes |
| 443 | UDP | `udp/443` and QUIC-shaped classes | recommended |
| 80 | TCP | `tcp/80` class | recommended |

Missing optional ports are recorded as unreachable classes in traces. They are not errors.

## Sizing

One session at a time. A `standard` session sends at most 1 GB from the responder (default `--data-cap`), and the rate cap defaults to 500 Mbit/s. Any small VM works; network egress cost is the main expense (a standard session from a 100 Mbit/s access network moves roughly 100–200 MB each way).
