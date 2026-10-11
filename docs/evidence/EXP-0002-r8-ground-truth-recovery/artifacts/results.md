| Scenario (simulator stages) | Check | Truth | Recovered | Pass |
|---|---|---|---|---|
| rate-delay-asym (S5 S6 S10 S15) | session complete | true | true | yes |
| rate-delay-asym (S5 S6 S10 S15) | capacity a_to_b (bit/s, ±10%) | 19815059 | 19749440.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | capacity b_to_a (bit/s, ±10%) | 9907530 | 9891200.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | base delay sum a+b (ms, ±1) | 25 | 25.0047 | yes |
| rate-delay-asym (S5 S6 S10 S15) | split method recorded | symmetric_assumed | symmetric_assumed | yes |
| rate-delay-asym (S5 S6 S10 S15) | buffer a_to_b (bytes, ±15%) | 150000 | 149357.1396 | yes |
| rate-delay-asym (S5 S6 S10 S15) | buffer b_to_a (bytes, ±15%) | 75000 | 74733.9878 | yes |
| rate-delay-asym (S5 S6 S10 S15) | discipline a_to_b | droptail | droptail | yes |
| rate-delay-asym (S5 S6 S10 S15) | netem export present | yes | see closure | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure capacity a_to_b (±10%) | 19749440.0000 | 19749600.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure buffer a_to_b (±15%) | 149357.1396 | 149377.4228 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure capacity b_to_a (±10%) | 9891200.0000 | 9880960.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure buffer b_to_a (±15%) | 74733.9878 | 74665.1235 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure base delay sum (ms, ±1) | 25.0047 | 25.0056 | yes |
| rate-delay-asym | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.102 over 70502 packets | yes |
| symmetric-delay (S10) | base delay a_to_b (ms, ±1) | 20 | 20.0262 | yes |
| symmetric-delay (S10) | base delay b_to_a (ms, ±1) | 20 | 20.0239 | yes |
| symmetric-delay (S10) | clock offset (ms, ±1; same host clock) | 0 | -0.0009 | yes |
| symmetric-delay (S10) | light-train dispersion a_to_b (netem 50 Mbit/s, ±15%) | 49537649 | 49546034.0000 | yes |
| symmetric-delay | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.845 over 19525 packets | n/a (smoke/light: fixed overhead dominates) |
| jitter (S10 S11) | jitter stddev a_to_b (ms, ±30%) | 4 | 4.1793 | yes |
| jitter (S10 S11) | jitter stddev b_to_a (ms, < 0.5) | 0 | 0.0293 | yes |
| jitter (S10 S11) | reordering detected a_to_b (jitter reorders in netem) | > 0 | 0.2138 | yes |
| jitter | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.883 over 37132 packets | n/a (smoke/light: fixed overhead dominates) |
| loss-random (S9) | GE p 98.75% CI covers truth (family-wise 95% over 4) | 0.02 | Some((0.006541543320721146, 0.03014544825308909)) | yes |
| loss-random (S9) | GE r 98.75% CI covers truth (family-wise 95% over 4) | 0.98 | Some((0.6157633951321686, 1.0)) | yes |
| loss-random (S9) | no loss b_to_a | 0 | 0.0000 | yes |
| loss-random | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.625 over 270313 packets | yes |
| loss-gemodel (S9) | GE p 98.75% CI covers truth (family-wise 95% over 4) | 0.02 | Some((0.008569506210214147, 0.03467745309848124)) | yes |
| loss-gemodel (S9) | GE r 98.75% CI covers truth (family-wise 95% over 4) | 0.4 | Some((0.2495373717811207, 0.6884278964614019)) | yes |
| loss-gemodel (S9) | no loss b_to_a | 0 | 0.0000 | yes |
| loss-gemodel | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.321 over 270347 packets | yes |
| rate-step (S6) | capacity series NRMSE a_to_b (≤ 10%) | ≤ 0.10 | 0.0157 over 196 bins | yes |
| rate-step | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.929 over 70913 packets | yes |
| policer (S2 S5) | discipline a_to_b | policer | policer | yes |
| policer (S2 S5) | policed rate a_to_b (±15%) | 4953765 | 4971200.0000 | yes |
| policer | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.937 over 156517 packets | yes |
| aqm-ecn (S5 S13) | discipline a_to_b | aqm_suspected | aqm_suspected | yes |
| aqm-ecn (S5 S13) | ECT marked by fq_codel (ECT(0) or ECT(1)) | marked | ect0 marked, ect1 marked | yes |
| aqm-ecn (S5 S13) | capacity a_to_b (htb 20 Mbit/s, ±15%) | 19815059 | 19849120.0000 | yes |
| aqm-ecn | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.832 over 184319 packets | yes |
| mtu-icmp (S4) | path MTU a_to_b | 1400 | 1400.0000 | yes |
| mtu-icmp (S4) | path MTU b_to_a | 1500 | 1500.0000 | yes |
| mtu-icmp (S4) | a_to_b black hole flag | false | Some(false) | yes |
| mtu-icmp (S4) | a_to_b ICMP Packet Too Big (MTU 1400) observed | true | true | yes |
| mtu-icmp | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.475 over 36534 packets | n/a (smoke/light: fixed overhead dominates) |
| mtu-blackhole (S4) | path MTU a_to_b | 1400 | 1400.0000 | yes |
| mtu-blackhole (S4) | path MTU b_to_a | 1500 | 1500.0000 | yes |
| mtu-blackhole (S4) | a_to_b black hole flag | true | Some(true) | yes |
| mtu-blackhole (S4) | a_to_b ICMP Packet Too Big (MTU 1400) observed | false | false | yes |
| mtu-blackhole | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.316 over 39502 packets | n/a (smoke/light: fixed overhead dominates) |
| tos-rewrite (S13) | DSCP EF rewritten a_to_b | rewritten | rewritten | yes |
| tos-rewrite (S13) | ECT(0) bleached a_to_b | bleached | bleached | yes |
| tos-rewrite (S13) | DSCP EF preserved b_to_a | preserved | preserved | yes |
| tos-rewrite | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.086 over 68129 packets | n/a (smoke/light: fixed overhead dominates) |
| udp443-throttle (S1 S2) | udp/443 capacity ratio vs udp/high-port (2 vs ~20 Mbit/s) | < 0.3 | 0.1073 | yes |
| udp443-throttle (S1 S2) | udp/443-quic capacity ratio | < 0.3 | 0.1073 | yes |
| udp443-throttle | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.504 over 69697 packets | yes |
| udp-blocked (S2) | control fell back to TCP | tcp | tcp | yes |
| udp-blocked (S2) | udp/high-port unreachable | false | Some(false) | yes |
| udp-blocked (S2) | tcp/443 reachable | true | Some(true) | yes |
| udp-blocked (S2) | trace written despite blocked UDP | exit 0 or 3 | 3 | yes |
| udp-blocked | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.681 over 1293 packets | n/a (smoke/light: fixed overhead dominates) |
| nat-timeout (S3) | binding alive after 15 s idle (timeout 20 s) | true | Some(true) | yes |
| nat-timeout (S3) | binding expired after 30 s idle | false | Some(false) | yes |
| nat-timeout (S3) | binding expired after 60 s idle | false | Some(false) | yes |
| nat-timeout | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.305 over 270301 packets | yes |
| rebind (S3 S14) | responder recorded nat_rebind | >= 1 | 1 | yes |
| rebind (S3 S14) | initiator recorded addr_new | >= 1 | 2 | yes |
| rebind (S3 S14) | session complete after rebinding | true | true | yes |
| rebind | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.373 over 270301 packets | yes |
| deadman (S14 safety) | responder heavy packets sent 0.7–3 s into the outage | 0 | Some(0) | yes |
| deadman (S14 safety) | responder stopped within (ms after outage start) | ≤ 600 | 504.5851 | yes |
| deadman (S14 safety) | dead_man flow_stopped event recorded by responder | true | true | yes |
| deadman | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.441 over 71510 packets | yes |
| data-cap (safety) | responder UDP bytes sent ≤ cap + one batch (3 MB + 100 kB) | 3000000 | Some(3019591) | yes |
| data-cap (safety) | budget_cap event recorded by responder | true | true | yes |
| data-cap | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.738 over 8388 packets | n/a (smoke/light: fixed overhead dominates) |
| ipv6 (IPv6) | session complete over IPv6 | true | true | yes |
| ipv6 (IPv6) | initiator used the IPv6 responder address | [fd00:2::2]:4433 | [fd00:2::2]:4433 | yes |
| ipv6 (IPv6) | capacity a_to_b over IPv6 (±10%) | 19815059 | 19740480.0000 | yes |
| ipv6 (IPv6) | udp/443 reachable over IPv6 | true | Some(true) | yes |
| ipv6 | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.460 over 11155 packets | n/a (smoke/light: fixed overhead dominates) |
| light (profile) | session complete | true | true | yes |
| light (profile) | light profile UDP bytes sent per endpoint (≤ 2 MB) | 2000000 | a=Some(609838) b=Some(608975) | yes |
| light (profile) | light trace file size (≤ 200 kB) | 200000 | 58136 | yes |
| light | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.965 over 4376 packets | n/a (smoke/light: fixed overhead dominates) |
| deep (profile S6) | session complete | true | true | yes |
| deep (profile S6) | periodic tracking saturations (120 s → 2) | 2 | 2 | yes |
| deep (profile S6) | deep NAT probes include 300 s idle | true | true | yes |
| deep | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.784 over 112663 packets | yes |
| rate-cap (safety) | initiator heavy send rate under --rate-cap 5 Mbit/s (≤ 5.5 Mbit/s) | 5000000 | 4938488.8832 | yes |
| rate-cap | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.627 over 6763 packets | n/a (smoke/light: fixed overhead dominates) |
| rate-100m (S6 size) | capacity a_to_b at 100 Mbit/s (±10%) | 99075297 | 99051200.0000 | yes |
| rate-100m (S6 size) | standard trace file size at 100 Mbit/s (≤ 10 MB) | 10000000 | 1942149 | yes |
| rate-100m | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.502 over 265853 packets | yes |
| reorder-dup (S11 S12) | reordering detected a_to_b | > 0 | 0.0590 | yes |
| reorder-dup (S11 S12) | duplicate rate a_to_b (2% ± 1%) | 0.02 | 0.0194 | yes |
| reorder-dup (S11 S12) | no duplicates b_to_a | 0 | 0.0000 | yes |
| reorder-dup | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.101 over 54138 packets | n/a (smoke/light: fixed overhead dominates) |
