| Scenario (simulator stages) | Check | Truth | Recovered | Pass |
|---|---|---|---|---|
| rate-delay-asym (S5 S6 S10 S15) | session complete | true | true | yes |
| rate-delay-asym (S5 S6 S10 S15) | capacity a_to_b (bit/s, ±10%) | 19815059 | 19749600.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | capacity b_to_a (bit/s, ±10%) | 9907530 | 9881200.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | base delay sum a+b (ms, ±1) | 25 | 25.0054 | yes |
| rate-delay-asym (S5 S6 S10 S15) | split method recorded | symmetric_assumed | symmetric_assumed | yes |
| rate-delay-asym (S5 S6 S10 S15) | buffer a_to_b (bytes, ±15%) | 150000 | 149364.6053 | yes |
| rate-delay-asym (S5 S6 S10 S15) | buffer b_to_a (bytes, ±15%) | 75000 | 74662.3176 | yes |
| rate-delay-asym (S5 S6 S10 S15) | discipline a_to_b | droptail | droptail | yes |
| rate-delay-asym (S5 S6 S10 S15) | netem export present | yes | see closure | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure capacity a_to_b (±10%) | 19749600.0000 | 19749920.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure buffer a_to_b (±15%) | 149364.6053 | 149409.1915 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure capacity b_to_a (±10%) | 9881200.0000 | 9891200.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure buffer b_to_a (±15%) | 74662.3176 | 74801.9057 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure base delay sum (ms, ±1) | 25.0054 | 25.0050 | yes |
| rate-delay-asym | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.289 over 70314 packets | yes |
| symmetric-delay (S10) | base delay a_to_b (ms, ±1) | 20 | 20.0256 | yes |
| symmetric-delay (S10) | base delay b_to_a (ms, ±1) | 20 | 20.0247 | yes |
| symmetric-delay (S10) | clock offset (ms, ±1; same host clock) | 0 | -0.0003 | yes |
| symmetric-delay (S10) | light-train dispersion a_to_b (netem 50 Mbit/s, ±15%) | 49537649 | 49538729.0000 | yes |
| symmetric-delay | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.260 over 19521 packets | n/a (smoke/light: fixed overhead dominates) |
| jitter (S10 S11) | jitter stddev a_to_b (ms, ±30%) | 4 | 3.9653 | yes |
| jitter (S10 S11) | jitter stddev b_to_a (ms, < 0.5) | 0 | 0.0235 | yes |
| jitter (S10 S11) | reordering detected a_to_b (jitter reorders in netem) | > 0 | 0.2096 | yes |
| jitter | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.267 over 37157 packets | n/a (smoke/light: fixed overhead dominates) |
| loss-random (S9) | GE p 95% CI covers truth | 0.02 | Some((0.007678863269045811, 0.025766996231858737)) | yes |
| loss-random (S9) | GE r 95% CI covers truth | 0.98 | Some((0.7224598312333834, 1.0)) | yes |
| loss-random (S9) | no loss b_to_a | 0 | 0.0000 | yes |
| loss-random | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.117 over 270317 packets | yes |
| loss-gemodel (S9) | GE p 95% CI covers truth | 0.02 | Some((0.020871830159250572, 0.04807933053827498)) | **no** |
| loss-gemodel (S9) | GE r 95% CI covers truth | 0.4 | Some((0.25054734348500335, 0.4907271384171466)) | yes |
| loss-gemodel (S9) | no loss b_to_a | 0 | 0.0000 | yes |
| loss-gemodel | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.040 over 270309 packets | yes |
| rate-step (S6) | capacity series NRMSE a_to_b (≤ 10%) | ≤ 0.10 | 0.0129 over 193 bins | yes |
| rate-step | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.255 over 70620 packets | yes |
| policer (S2 S5) | discipline a_to_b | policer | policer | yes |
| policer (S2 S5) | policed rate a_to_b (±15%) | 4953765 | 4971200.0000 | yes |
| policer | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.354 over 156534 packets | yes |
| aqm-ecn (S5 S13) | discipline a_to_b | aqm_suspected | aqm_suspected | yes |
| aqm-ecn (S5 S13) | ECT(0) marked by fq_codel | marked | marked | yes |
| aqm-ecn (S5 S13) | capacity a_to_b (htb 20 Mbit/s, ±15%) | 19815059 | 19840960.0000 | yes |
| aqm-ecn | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.231 over 184393 packets | yes |
| mtu-icmp (S4) | path MTU a_to_b | 1400 | 1400.0000 | yes |
| mtu-icmp (S4) | path MTU b_to_a | 1500 | 1500.0000 | yes |
| mtu-icmp (S4) | a_to_b black hole flag | false | Some(false) | yes |
| mtu-icmp (S4) | a_to_b ICMP Packet Too Big (MTU 1400) observed | true | true | yes |
| mtu-icmp | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.455 over 36532 packets | n/a (smoke/light: fixed overhead dominates) |
| mtu-blackhole (S4) | path MTU a_to_b | 1400 | 1400.0000 | yes |
| mtu-blackhole (S4) | path MTU b_to_a | 1500 | 1500.0000 | yes |
| mtu-blackhole (S4) | a_to_b black hole flag | true | Some(true) | yes |
| mtu-blackhole (S4) | a_to_b ICMP Packet Too Big (MTU 1400) observed | false | false | yes |
| mtu-blackhole | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.947 over 39488 packets | n/a (smoke/light: fixed overhead dominates) |
| tos-rewrite (S13) | DSCP EF rewritten a_to_b | rewritten | rewritten | yes |
| tos-rewrite (S13) | ECT(0) bleached a_to_b | bleached | bleached | yes |
| tos-rewrite (S13) | DSCP EF preserved b_to_a | preserved | preserved | yes |
| tos-rewrite | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 4.562 over 68127 packets | n/a (smoke/light: fixed overhead dominates) |
| udp443-throttle (S1 S2) | udp/443 capacity ratio vs udp/high-port (2 vs ~20 Mbit/s) | < 0.3 | 0.1072 | yes |
| udp443-throttle (S1 S2) | udp/443-quic capacity ratio | < 0.3 | 0.1072 | yes |
| udp443-throttle | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.505 over 72033 packets | yes |
| udp-blocked (S2) | control fell back to TCP | tcp | tcp | yes |
| udp-blocked (S2) | udp/high-port unreachable | false | Some(false) | yes |
| udp-blocked (S2) | tcp/443 reachable | true | Some(true) | yes |
| udp-blocked (S2) | trace written despite blocked UDP | exit 0 or 3 | 3 | yes |
| udp-blocked | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.543 over 1303 packets | n/a (smoke/light: fixed overhead dominates) |
| nat-timeout (S3) | binding alive after 15 s idle (timeout 20 s) | true | Some(true) | yes |
| nat-timeout (S3) | binding expired after 30 s idle | false | Some(false) | yes |
| nat-timeout (S3) | binding expired after 60 s idle | false | Some(false) | yes |
| nat-timeout | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.384 over 270301 packets | yes |
| rebind (S3 S14) | responder recorded nat_rebind | >= 1 | 1 | yes |
| rebind (S3 S14) | initiator recorded addr_new | >= 1 | 2 | yes |
| rebind (S3 S14) | session complete after rebinding | true | true | yes |
| rebind | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.234 over 270312 packets | yes |
| deadman (S14 safety) | responder heavy packets sent 0.7–3 s into the outage | 0 | Some(0) | yes |
| deadman (S14 safety) | responder stopped within (ms after outage start) | ≤ 600 | 499.8368 | yes |
| deadman (S14 safety) | dead_man flow_stopped event recorded by responder | true | true | yes |
| deadman | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.477 over 73661 packets | yes |
| data-cap (safety) | responder UDP bytes sent ≤ cap + one batch (3 MB + 100 kB) | 3000000 | Some(3018451) | yes |
| data-cap (safety) | budget_cap event recorded by responder | true | true | yes |
| data-cap | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.468 over 8382 packets | n/a (smoke/light: fixed overhead dominates) |
| ipv6 (IPv6) | session complete over IPv6 | true | true | yes |
| ipv6 (IPv6) | initiator used the IPv6 responder address | [fd00:2::2]:4433 | [fd00:2::2]:4433 | yes |
| ipv6 (IPv6) | capacity a_to_b over IPv6 (±10%) | 19815059 | 19730160.0000 | yes |
| ipv6 (IPv6) | udp/443 reachable over IPv6 | true | Some(true) | yes |
| ipv6 | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.275 over 11201 packets | n/a (smoke/light: fixed overhead dominates) |
| light (profile) | session complete | true | true | yes |
| light (profile) | light profile UDP bytes sent per endpoint (≤ 2 MB) | 2000000 | a=Some(609790) b=Some(603202) | yes |
| light (profile) | light trace file size (≤ 200 kB) | 200000 | 59119 | yes |
| light | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 9.179 over 4373 packets | n/a (smoke/light: fixed overhead dominates) |
| deep (profile S6) | session complete | true | true | yes |
| deep (profile S6) | periodic tracking saturations (120 s → 2) | 2 | 2 | yes |
| deep (profile S6) | deep NAT probes include 300 s idle | true | true | yes |
| deep | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.315 over 112708 packets | yes |
| rate-cap (safety) | initiator heavy send rate under --rate-cap 5 Mbit/s (≤ 5.5 Mbit/s) | 5000000 | 4905452.9827 | yes |
| rate-cap | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.896 over 6728 packets | n/a (smoke/light: fixed overhead dominates) |
| rate-100m (S6 size) | capacity a_to_b at 100 Mbit/s (±10%) | 99075297 | 99040960.0000 | yes |
| rate-100m (S6 size) | standard trace file size at 100 Mbit/s (≤ 10 MB) | 10000000 | 2024234 | yes |
| rate-100m | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.585 over 273728 packets | yes |
| reorder-dup (S11 S12) | reordering detected a_to_b | > 0 | 0.0117 | yes |
| reorder-dup (S11 S12) | duplicate rate a_to_b (2% ± 1%) | 0.02 | 0.0210 | yes |
| reorder-dup (S11 S12) | no duplicates b_to_a | 0 | 0.0000 | yes |
| reorder-dup | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.849 over 43589 packets | n/a (smoke/light: fixed overhead dominates) |
