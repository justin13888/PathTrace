| Scenario (simulator stages) | Check | Truth | Recovered | Pass |
|---|---|---|---|---|
| rate-delay-asym (S5 S6 S10 S15) | session complete | true | true | yes |
| rate-delay-asym (S5 S6 S10 S15) | capacity a_to_b (bit/s, ±10%) | 19815059 | 19850240.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | capacity b_to_a (bit/s, ±10%) | 9907530 | 9895600.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | base delay sum a+b (ms, ±1) | 25 | 25.0051 | yes |
| rate-delay-asym (S5 S6 S10 S15) | split method recorded | symmetric_assumed | symmetric_assumed | yes |
| rate-delay-asym (S5 S6 S10 S15) | buffer a_to_b (bytes, ±15%) | 150000 | 150151.8504 | yes |
| rate-delay-asym (S5 S6 S10 S15) | buffer b_to_a (bytes, ±15%) | 75000 | 74792.0642 | yes |
| rate-delay-asym (S5 S6 S10 S15) | discipline a_to_b | droptail | droptail | yes |
| rate-delay-asym (S5 S6 S10 S15) | netem export present | yes | see closure | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure capacity a_to_b (±10%) | 19850240.0000 | 19851200.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure buffer a_to_b (±15%) | 150151.8504 | 150156.0177 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure capacity b_to_a (±10%) | 9895600.0000 | 9895600.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure buffer b_to_a (±15%) | 74792.0642 | 74793.4744 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure base delay sum (ms, ±1) | 25.0051 | 25.0047 | yes |
| rate-delay-asym | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.343 over 70485 packets | yes |
| symmetric-delay (S10) | base delay a_to_b (ms, ±1) | 20 | 20.0284 | yes |
| symmetric-delay (S10) | base delay b_to_a (ms, ±1) | 20 | 20.0213 | yes |
| symmetric-delay (S10) | clock offset (ms, ±1; same host clock) | 0 | -0.0032 | yes |
| symmetric-delay (S10) | light-train dispersion a_to_b (netem 50 Mbit/s, ±15%) | 49537649 | 49535282.0000 | yes |
| symmetric-delay | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.546 over 18952 packets | n/a (smoke/light: fixed overhead dominates) |
| jitter (S10 S11) | jitter stddev a_to_b (ms, ±30%) | 4 | 4.1583 | yes |
| jitter (S10 S11) | jitter stddev b_to_a (ms, < 0.5) | 0 | 0.0210 | yes |
| jitter (S10 S11) | reordering detected a_to_b (jitter reorders in netem) | > 0 | 0.3034 | yes |
| jitter | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.995 over 32776 packets | n/a (smoke/light: fixed overhead dominates) |
| loss-random (S9) | GE p 98.75% CI covers truth (family-wise 95% over 4) | 0.02 | Some((0.011338726786823813, 0.03968628418960662)) | yes |
| loss-random (S9) | GE r 98.75% CI covers truth (family-wise 95% over 4) | 0.98 | Some((0.7062145562684452, 1.0)) | yes |
| loss-random (S9) | no loss b_to_a | 0 | 0.0000 | yes |
| loss-random | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 4.731 over 241714 packets | yes |
| loss-gemodel (S9) | GE p 98.75% CI covers truth (family-wise 95% over 4) | 0.02 | Some((0.008532460957399724, 0.034529745450311566)) | yes |
| loss-gemodel (S9) | GE r 98.75% CI covers truth (family-wise 95% over 4) | 0.4 | Some((0.2728715609344262, 0.7271284390655738)) | yes |
| loss-gemodel (S9) | no loss b_to_a | 0 | 0.0000 | yes |
| loss-gemodel | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 4.744 over 241838 packets | yes |
| rate-step (S6) | capacity series NRMSE a_to_b (≤ 10%) | ≤ 0.10 | 0.0210 over 189 bins | yes |
| rate-step | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.543 over 69524 packets | yes |
| policer (S2 S5) | discipline a_to_b | policer | policer | yes |
| policer (S2 S5) | policed rate a_to_b (±15%) | 4953765 | 4971200.0000 | yes |
| policer | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.104 over 140705 packets | yes |
| aqm-ecn (S5 S13) | discipline a_to_b | aqm_suspected | aqm_suspected | yes |
| aqm-ecn (S5 S13) | ECT marked by fq_codel (ECT(0) or ECT(1)) | marked | ect0 marked, ect1 marked | yes |
| aqm-ecn (S5 S13) | capacity a_to_b (htb 20 Mbit/s, ±15%) | 19815059 | 19840960.0000 | yes |
| aqm-ecn | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.451 over 169371 packets | yes |
| mtu-icmp (S4) | path MTU a_to_b | 1400 | 1400.0000 | yes |
| mtu-icmp (S4) | path MTU b_to_a | 1500 | 1500.0000 | yes |
| mtu-icmp (S4) | a_to_b black hole flag | false | Some(false) | yes |
| mtu-icmp (S4) | a_to_b ICMP Packet Too Big (MTU 1400) observed | true | true | yes |
| mtu-icmp | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.069 over 31489 packets | n/a (smoke/light: fixed overhead dominates) |
| mtu-blackhole (S4) | path MTU a_to_b | 1400 | 1400.0000 | yes |
| mtu-blackhole (S4) | path MTU b_to_a | 1500 | 1500.0000 | yes |
| mtu-blackhole (S4) | a_to_b black hole flag | true | Some(true) | yes |
| mtu-blackhole (S4) | a_to_b ICMP Packet Too Big (MTU 1400) observed | false | false | yes |
| mtu-blackhole | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.494 over 37359 packets | n/a (smoke/light: fixed overhead dominates) |
| tos-rewrite (S13) | DSCP EF rewritten a_to_b | rewritten | rewritten | yes |
| tos-rewrite (S13) | ECT(0) bleached a_to_b | bleached | bleached | yes |
| tos-rewrite (S13) | DSCP EF preserved b_to_a | preserved | preserved | yes |
| tos-rewrite | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 4.623 over 58010 packets | n/a (smoke/light: fixed overhead dominates) |
| udp443-throttle (S1 S2) | udp/443 capacity ratio vs udp/high-port (2 vs ~20 Mbit/s) | < 0.3 | 0.1097 | yes |
| udp443-throttle (S1 S2) | udp/443-quic capacity ratio | < 0.3 | 0.1097 | yes |
| udp443-throttle | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.266 over 73293 packets | yes |
| udp-blocked (S2) | control fell back to TCP | tcp | tcp | yes |
| udp-blocked (S2) | udp/high-port unreachable | false | Some(false) | yes |
| udp-blocked (S2) | tcp/443 reachable | true | Some(true) | yes |
| udp-blocked (S2) | trace written despite blocked UDP | exit 0 or 3 | 3 | yes |
| nat-timeout (S3) | binding alive after 15 s idle (timeout 20 s) | true | Some(true) | yes |
| nat-timeout (S3) | binding expired after 30 s idle | false | Some(false) | yes |
| nat-timeout (S3) | binding expired after 60 s idle | false | Some(false) | yes |
| nat-timeout | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.260 over 240879 packets | yes |
| rebind (S3 S14) | responder recorded nat_rebind | >= 1 | 1 | yes |
| rebind (S3 S14) | initiator recorded addr_new | >= 1 | 2 | yes |
| rebind (S3 S14) | session complete after rebinding | true | true | yes |
| rebind | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 4.946 over 240866 packets | yes |
| deadman (S14 safety) | responder heavy packets sent 0.7–3 s into the outage | 0 | Some(0) | yes |
| deadman (S14 safety) | responder stopped within (ms after outage start) | ≤ 600 | 498.3635 | yes |
| deadman (S14 safety) | dead_man flow_stopped event recorded by responder | true | true | yes |
| deadman | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.207 over 72837 packets | yes |
| data-cap (safety) | responder UDP bytes sent ≤ cap + one batch (1 MB + 100 kB) | 1000000 | Some(1004404) | yes |
| data-cap (safety) | responder saturation skipped for lack of budget (phase_skipped) | >= 1 | 1 | yes |
| data-cap (safety) | budget_cap event recorded by responder | true | true | yes |
| data-cap | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.803 over 6934 packets | n/a (smoke/light: fixed overhead dominates) |
| ipv6 (IPv6) | session complete over IPv6 | true | true | yes |
| ipv6 (IPv6) | initiator used the IPv6 responder address | [fd00:2::2]:4433 | [fd00:2::2]:4433 | yes |
| ipv6 (IPv6) | capacity a_to_b over IPv6 (±10%) | 19815059 | 19851200.0000 | yes |
| ipv6 (IPv6) | udp/443 reachable over IPv6 | true | Some(true) | yes |
| ipv6 | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.349 over 11230 packets | n/a (smoke/light: fixed overhead dominates) |
| light (profile) | session complete | true | true | yes |
| light (profile) | light profile UDP bytes sent per endpoint (≤ 2 MB) | 2000000 | a=Some(666861) b=Some(666358) | yes |
| light (profile) | light trace file size (≤ 200 kB) | 200000 | 65100 | yes |
| light | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.944 over 4448 packets | n/a (smoke/light: fixed overhead dominates) |
| deep (profile S6) | session complete | true | true | yes |
| deep (profile S6) | periodic tracking saturations (120 s → 2) | 2 | 2 | yes |
| deep (profile S6) | deep NAT probes include 300 s idle | true | true | yes |
| deep | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.382 over 122887 packets | yes |
| rate-cap (safety) | initiator heavy send rate under --rate-cap 5 Mbit/s (≤ 5.5 Mbit/s) | 5000000 | 4938496.1510 | yes |
| rate-cap | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.407 over 6803 packets | n/a (smoke/light: fixed overhead dominates) |
| rate-100m (S6 size) | capacity a_to_b at 100 Mbit/s (±10%) | 99075297 | 99060480.0000 | yes |
| rate-100m (S6 size) | standard trace file size at 100 Mbit/s (≤ 10 MB) | 10000000 | 1937404 | yes |
| rate-100m | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.495 over 232824 packets | yes |
| geo (robustness S4 S7) | session complete | true | true | yes |
| geo (robustness S4 S7) | capacity a_to_b at 300 ms one way (bit/s, ±10%) | 19815059 | 19830720.0000 | yes |
| geo (robustness S4 S7) | capacity b_to_a at 300 ms one way (bit/s, ±10%) | 19815059 | 19809600.0000 | yes |
| geo (robustness S4 S7) | train and PMTU flows never stopped by the dead-man | 0 | 0 | yes |
| geo (robustness S4 S7) | light trains a_to_b still delivered after the saturations | > 0 | Some(528) | yes |
| geo (robustness S4 S7) | PMTU ladder a_to_b completed (path MTU 1500) | 1500 | 1500.0000 | yes |
| geo (robustness S4 S7) | light trains b_to_a still delivered after the saturations | > 0 | Some(544) | yes |
| geo (robustness S4 S7) | PMTU ladder b_to_a completed (path MTU 1500) | 1500 | 1500.0000 | yes |
| geo | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.678 over 62924 packets | yes |
| geo-100m (S6) | session complete | true | true | yes |
| geo-100m (S6) | capacity a_to_b at 300 ms one way, 100 Mbit/s (±10%) | 99075297 | 99049920.0000 | yes |
| geo-100m (S6) | saturated time a_to_b (s, ≥ 3) | ≥ 3 | 4.1684 | yes |
| geo-100m (S6) | capacity b_to_a at 300 ms one way, 100 Mbit/s (±10%) | 99075297 | 99050240.0000 | yes |
| geo-100m (S6) | saturated time b_to_a (s, ≥ 7) | ≥ 7 | 6.5609 | **no** |
| geo-100m | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.886 over 147116 packets | yes |
| bufferbloat (robustness S4 S7) | session complete | true | true | yes |
| bufferbloat (robustness S4 S7) | train and PMTU flows never stopped by the dead-man | 0 | 0 | yes |
| bufferbloat (robustness S4 S7) | light trains a_to_b still delivered after the saturations | > 0 | Some(440) | yes |
| bufferbloat (robustness S4 S7) | PMTU ladder a_to_b completed (path MTU 1500) | 1500 | 1500.0000 | yes |
| bufferbloat (robustness S4 S7) | light trains b_to_a still delivered after the saturations | > 0 | Some(440) | yes |
| bufferbloat (robustness S4 S7) | PMTU ladder b_to_a completed (path MTU 1500) | 1500 | 1500.0000 | yes |
| bufferbloat | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.916 over 83843 packets | yes |
| fast (safety budget) | session complete | true | true | yes |
| fast (safety budget) | hard data cap not reached by a (allowances planned the budget) | 0 | 0 | yes |
| fast (safety budget) | a UDP bytes sent within the standard cap (200 MB) | 200000000 | Some(199006312) | yes |
| fast (safety budget) | hard data cap not reached by b (allowances planned the budget) | 0 | 0 | yes |
| fast (safety budget) | b UDP bytes sent within the standard cap (200 MB) | 200000000 | Some(174052314) | yes |
| fast (safety budget) | every phase P4-P8 ran | 4 5 6 7 8 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] | yes |
| fast (safety budget) | saturations ended by their allowances (flow_stopped) | >= 2 | 7 | yes |
| fast | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.296 over 240646 packets | yes |
| rcvbuf (host drops S5 S9) | session complete | true | true | yes |
| rcvbuf (host drops S5 S9) | responder socket drops recorded (rxq_drops) | > 0 | 9.0000 | yes |
| rcvbuf (host drops S5 S9) | lost packets attributed to the receiving host | > 0 | 9.0000 | yes |
| rcvbuf (host drops S5 S9) | responder UDP RcvbufErrors increased (netstack) | > 0 | Some(9) | yes |
| rcvbuf (host drops S5 S9) | host drops not mistaken for a policer | not policer | unknown | yes |
| rcvbuf | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.816 over 32206 packets | n/a (smoke/light: fixed overhead dominates) |
| local-qdisc (host drops tx ids) | session complete | true | true | yes |
| local-qdisc (host drops tx ids) | initiator transmit id mode | explicit | explicit | yes |
| local-qdisc (host drops tx ids) | initiator send failures recorded (local qdisc full) | > 0 | 572 | yes |
| local-qdisc (host drops tx ids) | local qdisc drops a_to_b recorded | > 0 | 572.0000 | yes |
| local-qdisc (host drops tx ids) | TX stamps aligned after send failures (implausible joins) | 0 | Some(0) of Some(5334) | yes |
| local-qdisc | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.054 over 34552 packets | n/a (smoke/light: fixed overhead dominates) |
| local-qdisc-predicted (host drops tx ids) | session complete | true | true | yes |
| local-qdisc-predicted (host drops tx ids) | initiator transmit id mode | predicted | predicted | yes |
| local-qdisc-predicted (host drops tx ids) | initiator send failures recorded (local qdisc full) | > 0 | 623 | yes |
| local-qdisc-predicted (host drops tx ids) | local qdisc drops a_to_b recorded | > 0 | 623.0000 | yes |
| local-qdisc-predicted (host drops tx ids) | TX stamps aligned after send failures (implausible joins) | 0 | Some(0) of Some(5351) | yes |
| local-qdisc-predicted | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.712 over 34579 packets | n/a (smoke/light: fixed overhead dominates) |
| reorder-dup (S11 S12) | reordering detected a_to_b | > 0 | 0.0019 | yes |
| reorder-dup (S11 S12) | duplicate rate a_to_b (2% ± 1%) | 0.02 | 0.0195 | yes |
| reorder-dup (S11 S12) | no duplicates b_to_a | 0 | 0.0000 | yes |
| reorder-dup | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.457 over 31998 packets | n/a (smoke/light: fixed overhead dominates) |
