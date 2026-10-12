| Scenario (simulator stages) | Check | Truth | Recovered | Pass |
|---|---|---|---|---|
| rate-delay-asym (S5 S6 S10 S15) | session complete | true | true | yes |
| rate-delay-asym (S5 S6 S10 S15) | capacity a_to_b (bit/s, ±10%) | 19815059 | 19750720.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | capacity b_to_a (bit/s, ±10%) | 9907530 | 9885360.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | base delay sum a+b (ms, ±1) | 25 | 25.0058 | yes |
| rate-delay-asym (S5 S6 S10 S15) | split method recorded | symmetric_assumed | symmetric_assumed | yes |
| rate-delay-asym (S5 S6 S10 S15) | buffer a_to_b (bytes, ±15%) | 150000 | 149417.5149 | yes |
| rate-delay-asym (S5 S6 S10 S15) | buffer b_to_a (bytes, ±15%) | 75000 | 74718.9854 | yes |
| rate-delay-asym (S5 S6 S10 S15) | discipline a_to_b | droptail | droptail | yes |
| rate-delay-asym (S5 S6 S10 S15) | netem export present | yes | see closure | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure capacity a_to_b (±10%) | 19750720.0000 | 19750400.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure buffer a_to_b (±15%) | 149417.5149 | 149394.5117 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure capacity b_to_a (±10%) | 9885360.0000 | 9891200.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure buffer b_to_a (±15%) | 74718.9854 | 74760.6854 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure base delay sum (ms, ±1) | 25.0058 | 25.0054 | yes |
| rate-delay-asym | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.508 over 70491 packets | yes |
| symmetric-delay (S10) | base delay a_to_b (ms, ±1) | 20 | 20.0257 | yes |
| symmetric-delay (S10) | base delay b_to_a (ms, ±1) | 20 | 20.0247 | yes |
| symmetric-delay (S10) | clock offset (ms, ±1; same host clock) | 0 | -0.0000 | yes |
| symmetric-delay (S10) | light-train dispersion a_to_b (netem 50 Mbit/s, ±15%) | 49537649 | 49545420.0000 | yes |
| symmetric-delay | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.437 over 19359 packets | n/a (smoke/light: fixed overhead dominates) |
| jitter (S10 S11) | jitter stddev a_to_b (ms, ±30%) | 4 | 3.7929 | yes |
| jitter (S10 S11) | jitter stddev b_to_a (ms, < 0.5) | 0 | 0.0422 | yes |
| jitter (S10 S11) | reordering detected a_to_b (jitter reorders in netem) | > 0 | 0.2527 | yes |
| jitter | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.788 over 32409 packets | n/a (smoke/light: fixed overhead dominates) |
| loss-random (S9) | GE p 98.75% CI covers truth (family-wise 95% over 4) | 0.02 | Some((0.012353119584156587, 0.0415637545125279)) | yes |
| loss-random (S9) | GE r 98.75% CI covers truth (family-wise 95% over 4) | 0.98 | Some((0.7194243310387893, 1.0)) | yes |
| loss-random (S9) | no loss b_to_a | 0 | 0.0000 | yes |
| loss-random | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.770 over 241881 packets | yes |
| loss-gemodel (S9) | GE p 98.75% CI covers truth (family-wise 95% over 4) | 0.02 | Some((0.00861940318733588, 0.03487637356028637)) | yes |
| loss-gemodel (S9) | GE r 98.75% CI covers truth (family-wise 95% over 4) | 0.4 | Some((0.21320628838679015, 0.6212308159799754)) | yes |
| loss-gemodel (S9) | no loss b_to_a | 0 | 0.0000 | yes |
| loss-gemodel | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.783 over 241719 packets | yes |
| rate-step (S6) | capacity series NRMSE a_to_b (≤ 10%) | ≤ 0.10 | 0.0212 over 192 bins | yes |
| rate-step | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.670 over 71703 packets | yes |
| policer (S2 S5) | discipline a_to_b | policer | policer | yes |
| policer (S2 S5) | policed rate a_to_b (±15%) | 4953765 | 4971200.0000 | yes |
| policer | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.974 over 141596 packets | yes |
| aqm-ecn (S5 S13) | discipline a_to_b | aqm_suspected | aqm_suspected | yes |
| aqm-ecn (S5 S13) | ECT marked by fq_codel (ECT(0) or ECT(1)) | marked | ect0 marked, ect1 marked | yes |
| aqm-ecn (S5 S13) | capacity a_to_b (htb 20 Mbit/s, ±15%) | 19815059 | 19840960.0000 | yes |
| aqm-ecn | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.794 over 169425 packets | yes |
| mtu-icmp (S4) | path MTU a_to_b | 1400 | 1400.0000 | yes |
| mtu-icmp (S4) | path MTU b_to_a | 1500 | 1500.0000 | yes |
| mtu-icmp (S4) | a_to_b black hole flag | false | Some(false) | yes |
| mtu-icmp (S4) | a_to_b ICMP Packet Too Big (MTU 1400) observed | true | true | yes |
| mtu-icmp | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.693 over 31458 packets | n/a (smoke/light: fixed overhead dominates) |
| mtu-blackhole (S4) | path MTU a_to_b | 1400 | 1400.0000 | yes |
| mtu-blackhole (S4) | path MTU b_to_a | 1500 | 1500.0000 | yes |
| mtu-blackhole (S4) | a_to_b black hole flag | true | Some(true) | yes |
| mtu-blackhole (S4) | a_to_b ICMP Packet Too Big (MTU 1400) observed | false | false | yes |
| mtu-blackhole | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.345 over 37345 packets | n/a (smoke/light: fixed overhead dominates) |
| tos-rewrite (S13) | DSCP EF rewritten a_to_b | rewritten | rewritten | yes |
| tos-rewrite (S13) | ECT(0) bleached a_to_b | bleached | bleached | yes |
| tos-rewrite (S13) | DSCP EF preserved b_to_a | preserved | preserved | yes |
| tos-rewrite | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.265 over 58009 packets | n/a (smoke/light: fixed overhead dominates) |
| udp443-throttle (S1 S2) | udp/443 capacity ratio vs udp/high-port (2 vs ~20 Mbit/s) | < 0.3 | 0.1089 | yes |
| udp443-throttle (S1 S2) | udp/443-quic capacity ratio | < 0.3 | 0.1089 | yes |
| udp443-throttle | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.189 over 71015 packets | yes |
| udp-blocked (S2) | control fell back to TCP | tcp | tcp | yes |
| udp-blocked (S2) | udp/high-port unreachable | false | Some(false) | yes |
| udp-blocked (S2) | tcp/443 reachable | true | Some(true) | yes |
| udp-blocked (S2) | trace written despite blocked UDP | exit 0 or 3 | 3 | yes |
| udp-blocked | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.030 over 1291 packets | n/a (smoke/light: fixed overhead dominates) |
| nat-timeout (S3) | binding alive after 15 s idle (timeout 20 s) | true | Some(true) | yes |
| nat-timeout (S3) | binding expired after 30 s idle | false | Some(false) | yes |
| nat-timeout (S3) | binding expired after 60 s idle | false | Some(false) | yes |
| nat-timeout | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.187 over 240822 packets | yes |
| rebind (S3 S14) | responder recorded nat_rebind | >= 1 | 1 | yes |
| rebind (S3 S14) | initiator recorded addr_new | >= 1 | 2 | yes |
| rebind (S3 S14) | session complete after rebinding | true | true | yes |
| rebind | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.159 over 240824 packets | yes |
| deadman (S14 safety) | responder heavy packets sent 0.7–3 s into the outage | 0 | Some(0) | yes |
| deadman (S14 safety) | responder stopped within (ms after outage start) | ≤ 600 | 504.2537 | yes |
| deadman (S14 safety) | dead_man flow_stopped event recorded by responder | true | true | yes |
| deadman | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.698 over 74687 packets | yes |
| data-cap (safety) | responder UDP bytes sent ≤ cap + one batch (1 MB + 100 kB) | 1000000 | Some(1004892) | yes |
| data-cap (safety) | responder saturation skipped for lack of budget (phase_skipped) | >= 1 | 1 | yes |
| data-cap (safety) | budget_cap event recorded by responder | true | true | yes |
| data-cap | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.095 over 6935 packets | n/a (smoke/light: fixed overhead dominates) |
| ipv6 (IPv6) | session complete over IPv6 | true | true | yes |
| ipv6 (IPv6) | initiator used the IPv6 responder address | [fd00:2::2]:4433 | [fd00:2::2]:4433 | yes |
| ipv6 (IPv6) | capacity a_to_b over IPv6 (±10%) | 19815059 | 19730160.0000 | yes |
| ipv6 (IPv6) | udp/443 reachable over IPv6 | true | Some(true) | yes |
| ipv6 | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.697 over 11215 packets | n/a (smoke/light: fixed overhead dominates) |
| light (profile) | session complete | true | true | yes |
| light (profile) | light profile UDP bytes sent per endpoint (≤ 2 MB) | 2000000 | a=Some(611600) b=Some(611191) | yes |
| light (profile) | light trace file size (≤ 200 kB) | 200000 | 73108 | yes |
| light | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 10.597 over 4366 packets | n/a (smoke/light: fixed overhead dominates) |
| deep (profile S6) | session complete | true | true | yes |
| deep (profile S6) | periodic tracking saturations (120 s → 2) | 2 | 2 | yes |
| deep (profile S6) | deep NAT probes include 300 s idle | true | true | yes |
| deep | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.040 over 122190 packets | **no** |
| rate-cap (safety) | initiator heavy send rate under --rate-cap 5 Mbit/s (≤ 5.5 Mbit/s) | 5000000 | 4936948.7654 | yes |
| rate-cap | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 9.759 over 6764 packets | n/a (smoke/light: fixed overhead dominates) |
| rate-100m (S6 size) | capacity a_to_b at 100 Mbit/s (±10%) | 99075297 | 99051200.0000 | yes |
| rate-100m (S6 size) | standard trace file size at 100 Mbit/s (≤ 10 MB) | 10000000 | 2255393 | yes |
| rate-100m | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.399 over 241955 packets | yes |
| geo (robustness S4 S7) | session complete | true | true | yes |
| geo (robustness S4 S7) | train and PMTU flows never stopped by the dead-man | 0 | 0 | yes |
| geo (robustness S4 S7) | light trains a_to_b still delivered after the saturations | > 0 | Some(528) | yes |
| geo (robustness S4 S7) | PMTU ladder a_to_b completed (path MTU 1500) | 1500 | 1500.0000 | yes |
| geo (robustness S4 S7) | light trains b_to_a still delivered after the saturations | > 0 | Some(544) | yes |
| geo (robustness S4 S7) | PMTU ladder b_to_a completed (path MTU 1500) | 1500 | 1500.0000 | yes |
| geo | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.875 over 52920 packets | **no** |
| bufferbloat (robustness S4 S7) | session complete | true | true | yes |
| bufferbloat (robustness S4 S7) | train and PMTU flows never stopped by the dead-man | 0 | 0 | yes |
| bufferbloat (robustness S4 S7) | light trains a_to_b still delivered after the saturations | > 0 | Some(448) | yes |
| bufferbloat (robustness S4 S7) | PMTU ladder a_to_b completed (path MTU 1500) | 1500 | 1500.0000 | yes |
| bufferbloat (robustness S4 S7) | light trains b_to_a still delivered after the saturations | > 0 | Some(448) | yes |
| bufferbloat (robustness S4 S7) | PMTU ladder b_to_a completed (path MTU 1500) | 1500 | 1500.0000 | yes |
| bufferbloat | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.354 over 86800 packets | **no** |
| fast (safety budget) | session complete | true | true | yes |
| fast (safety budget) | hard data cap not reached by a (allowances planned the budget) | 0 | 0 | yes |
| fast (safety budget) | a UDP bytes sent within the standard cap (200 MB) | 200000000 | Some(199007633) | yes |
| fast (safety budget) | hard data cap not reached by b (allowances planned the budget) | 0 | 0 | yes |
| fast (safety budget) | b UDP bytes sent within the standard cap (200 MB) | 200000000 | Some(174053715) | yes |
| fast (safety budget) | every phase P4-P8 ran | 4 5 6 7 8 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] | yes |
| fast (safety budget) | saturations ended by their allowances (flow_stopped) | >= 2 | 7 | yes |
| fast | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.428 over 240629 packets | yes |
| rcvbuf (host drops S5 S9) | session complete | true | true | yes |
| rcvbuf (host drops S5 S9) | responder socket drops recorded (rxq_drops) | > 0 | 924.0000 | yes |
| rcvbuf (host drops S5 S9) | lost packets attributed to the receiving host | > 0 | 924.0000 | yes |
| rcvbuf (host drops S5 S9) | responder UDP RcvbufErrors increased (netstack) | > 0 | Some(924) | yes |
| rcvbuf (host drops S5 S9) | host drops not mistaken for a policer | not policer | unknown | yes |
| rcvbuf | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.633 over 32725 packets | n/a (smoke/light: fixed overhead dominates) |
| local-qdisc (host drops tx ids) | session complete | true | true | yes |
| local-qdisc (host drops tx ids) | initiator transmit id mode | explicit | explicit | yes |
| local-qdisc (host drops tx ids) | initiator send failures recorded (local qdisc full) | > 0 | 971 | yes |
| local-qdisc (host drops tx ids) | local qdisc drops a_to_b recorded | > 0 | 1318.0000 | yes |
| local-qdisc (host drops tx ids) | TX stamps aligned after send failures (implausible joins) | 0 | Some(0) of Some(5342) | yes |
| local-qdisc | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.031 over 34566 packets | n/a (smoke/light: fixed overhead dominates) |
| local-qdisc-predicted (host drops tx ids) | session complete | true | true | yes |
| local-qdisc-predicted (host drops tx ids) | initiator transmit id mode | predicted | predicted | yes |
| local-qdisc-predicted (host drops tx ids) | initiator send failures recorded (local qdisc full) | > 0 | 920 | yes |
| local-qdisc-predicted (host drops tx ids) | local qdisc drops a_to_b recorded | > 0 | 922.0000 | yes |
| local-qdisc-predicted (host drops tx ids) | TX stamps aligned after send failures (implausible joins) | 0 | Some(0) of Some(5361) | yes |
| local-qdisc-predicted | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.338 over 34588 packets | n/a (smoke/light: fixed overhead dominates) |
| reorder-dup (S11 S12) | reordering detected a_to_b | > 0 | 0.0994 | yes |
| reorder-dup (S11 S12) | duplicate rate a_to_b (2% ± 1%) | 0.02 | 0.0198 | yes |
| reorder-dup (S11 S12) | no duplicates b_to_a | 0 | 0.0000 | yes |
| reorder-dup | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.611 over 49897 packets | n/a (smoke/light: fixed overhead dominates) |
