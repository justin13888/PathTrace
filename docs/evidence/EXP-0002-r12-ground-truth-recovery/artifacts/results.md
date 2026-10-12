| Scenario (simulator stages) | Check | Truth | Recovered | Pass |
|---|---|---|---|---|
| rate-delay-asym (S5 S6 S10 S15) | session complete | true | true | yes |
| rate-delay-asym (S5 S6 S10 S15) | capacity a_to_b (bit/s, ±10%) | 19815059 | 19840960.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | capacity b_to_a (bit/s, ±10%) | 9907530 | 9895920.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | base delay sum a+b (ms, ±1) | 25 | 25.0050 | yes |
| rate-delay-asym (S5 S6 S10 S15) | split method recorded | symmetric_assumed | symmetric_assumed | yes |
| rate-delay-asym (S5 S6 S10 S15) | buffer a_to_b (bytes, ±15%) | 150000 | 150081.6741 | yes |
| rate-delay-asym (S5 S6 S10 S15) | buffer b_to_a (bytes, ±15%) | 75000 | 74794.5645 | yes |
| rate-delay-asym (S5 S6 S10 S15) | discipline a_to_b | droptail | droptail | yes |
| rate-delay-asym (S5 S6 S10 S15) | netem export present | yes | see closure | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure capacity a_to_b (±10%) | 19840960.0000 | 19851200.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure buffer a_to_b (±15%) | 150081.6741 | 150154.8614 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure capacity b_to_a (±10%) | 9895920.0000 | 9895600.0000 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure buffer b_to_a (±15%) | 74794.5645 | 74794.9166 | yes |
| rate-delay-asym (S5 S6 S10 S15) | closure base delay sum (ms, ±1) | 25.0050 | 25.0050 | yes |
| rate-delay-asym | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.486 over 70402 packets | yes |
| symmetric-delay (S10) | base delay a_to_b (ms, ±1) | 20 | 20.0232 | yes |
| symmetric-delay (S10) | base delay b_to_a (ms, ±1) | 20 | 20.0249 | yes |
| symmetric-delay (S10) | clock offset (ms, ±1; same host clock) | 0 | 0.0006 | yes |
| symmetric-delay (S10) | light-train dispersion a_to_b (netem 50 Mbit/s, ±15%) | 49537649 | 49543375.0000 | yes |
| symmetric-delay | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.552 over 18881 packets | n/a (smoke/light: fixed overhead dominates) |
| jitter (S10 S11) | jitter stddev a_to_b (ms, ±30%) | 4 | 3.9068 | yes |
| jitter (S10 S11) | jitter stddev b_to_a (ms, < 0.5) | 0 | 0.0113 | yes |
| jitter (S10 S11) | reordering detected a_to_b (jitter reorders in netem) | > 0 | 0.4484 | yes |
| jitter | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.108 over 33734 packets | n/a (smoke/light: fixed overhead dominates) |
| loss-random (S9) | GE p 98.75% CI covers truth (family-wise 95% over 4) | 0.02 | Some((0.01444788208689143, 0.045361819658635866)) | yes |
| loss-random (S9) | GE r 98.75% CI covers truth (family-wise 95% over 4) | 0.98 | Some((0.6800514020559294, 0.9934825641035057)) | yes |
| loss-random (S9) | no loss b_to_a | 0 | 0.0000 | yes |
| loss-random | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 4.531 over 241700 packets | yes |
| loss-gemodel (S9) | GE p 98.75% CI covers truth (family-wise 95% over 4) | 0.02 | Some((0.0, 1.0)) | yes |
| loss-gemodel (S9) | GE r 98.75% CI covers truth (family-wise 95% over 4) | 0.4 | Some((0.0, 0.008604053783001194)) | **no** |
| loss-gemodel (S9) | no loss b_to_a | 0 | none | **no** |
| loss-gemodel | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 2.876 over 120826 packets | yes |
| rate-step (S6) | capacity series NRMSE a_to_b (≤ 10%) | ≤ 0.10 | 0.0041 over 193 bins | yes |
| rate-step | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 6.314 over 70033 packets | yes |
| policer (S2 S5) | discipline a_to_b | policer | policer | yes |
| policer (S2 S5) | policed rate a_to_b (±15%) | 4953765 | 4971200.0000 | yes |
| policer | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 4.885 over 140722 packets | yes |
| aqm-ecn (S5 S13) | discipline a_to_b | aqm_suspected | droptail | **no** |
| aqm-ecn (S5 S13) | ECT marked by fq_codel (ECT(0) or ECT(1)) | marked | ect0 marked, ect1 marked | yes |
| aqm-ecn (S5 S13) | capacity a_to_b (htb 20 Mbit/s, ±15%) | 19815059 | 19840960.0000 | yes |
| aqm-ecn | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.005 over 169279 packets | yes |
| mtu-icmp (S4) | path MTU a_to_b | 1400 | 1400.0000 | yes |
| mtu-icmp (S4) | path MTU b_to_a | 1500 | 1500.0000 | yes |
| mtu-icmp (S4) | a_to_b black hole flag | false | Some(false) | yes |
| mtu-icmp (S4) | a_to_b ICMP Packet Too Big (MTU 1400) observed | true | true | yes |
| mtu-icmp | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.881 over 31454 packets | n/a (smoke/light: fixed overhead dominates) |
| mtu-blackhole (S4) | path MTU a_to_b | 1400 | 1400.0000 | yes |
| mtu-blackhole (S4) | path MTU b_to_a | 1500 | 1500.0000 | yes |
| mtu-blackhole (S4) | a_to_b black hole flag | true | Some(true) | yes |
| mtu-blackhole (S4) | a_to_b ICMP Packet Too Big (MTU 1400) observed | false | false | yes |
| mtu-blackhole | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.414 over 37334 packets | n/a (smoke/light: fixed overhead dominates) |
| tos-rewrite (S13) | DSCP EF rewritten a_to_b | rewritten | rewritten | yes |
| tos-rewrite (S13) | ECT(0) bleached a_to_b | bleached | bleached | yes |
| tos-rewrite (S13) | DSCP EF preserved b_to_a | preserved | preserved | yes |
| tos-rewrite | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 4.400 over 58010 packets | n/a (smoke/light: fixed overhead dominates) |
| udp443-throttle (S1 S2) | udp/443 capacity ratio vs udp/high-port (2 vs ~20 Mbit/s) | < 0.3 | 0.1186 | yes |
| udp443-throttle (S1 S2) | udp/443-quic capacity ratio | < 0.3 | 0.1186 | yes |
| udp443-throttle | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.061 over 56035 packets | **no** |
| udp-blocked (S2) | control fell back to TCP | tcp | tcp | yes |
| udp-blocked (S2) | udp/high-port unreachable | false | Some(false) | yes |
| udp-blocked (S2) | tcp/443 reachable | true | Some(true) | yes |
| udp-blocked (S2) | trace written despite blocked UDP | exit 0 or 3 | 3 | yes |
| nat-timeout (S3) | binding alive after 15 s idle (timeout 20 s) | true | Some(true) | yes |
| nat-timeout (S3) | binding expired after 30 s idle | false | Some(false) | yes |
| nat-timeout (S3) | binding expired after 60 s idle | false | Some(false) | yes |
| nat-timeout | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 5.959 over 240877 packets | yes |
| rebind (S3 S14) | responder recorded nat_rebind | >= 1 | 1 | yes |
| rebind (S3 S14) | initiator recorded addr_new | >= 1 | 1 | yes |
| rebind (S3 S14) | session complete after rebinding | true | true | yes |
| rebind | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 4.898 over 240868 packets | yes |
| deadman (S14 safety) | responder heavy packets sent 0.7–3 s into the outage | 0 | Some(0) | yes |
| deadman (S14 safety) | responder stopped within (ms after outage start) | ≤ 600 | 496.7780 | yes |
| deadman (S14 safety) | dead_man flow_stopped event recorded by responder | true | true | yes |
| deadman | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.585 over 75294 packets | yes |
| data-cap (safety) | responder UDP bytes sent ≤ cap + one batch (1 MB + 100 kB) | 1000000 | Some(1004406) | yes |
| data-cap (safety) | responder saturation skipped for lack of budget (phase_skipped) | >= 1 | 1 | yes |
| data-cap (safety) | budget_cap event recorded by responder | true | true | yes |
| data-cap | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.835 over 6789 packets | n/a (smoke/light: fixed overhead dominates) |
| ipv6 (IPv6) | session complete over IPv6 | true | true | yes |
| ipv6 (IPv6) | initiator used the IPv6 responder address | [fd00:2::2]:4433 | [fd00:2::2]:4433 | yes |
| ipv6 (IPv6) | capacity a_to_b over IPv6 (±10%) | 19815059 | 19751840.0000 | yes |
| ipv6 (IPv6) | udp/443 reachable over IPv6 | true | Some(true) | yes |
| ipv6 | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 10.113 over 8061 packets | n/a (smoke/light: fixed overhead dominates) |
| light (profile) | session complete | true | true | yes |
| light (profile) | light profile UDP bytes sent per endpoint (≤ 2 MB) | 2000000 | a=Some(660012) b=Some(656617) | yes |
| light (profile) | light trace file size (≤ 200 kB) | 200000 | 72455 | yes |
| light | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 10.244 over 4392 packets | n/a (smoke/light: fixed overhead dominates) |
| deep (profile S6) | session complete | true | true | yes |
| deep (profile S6) | periodic tracking saturations (120 s → 2) | 2 | 2 | yes |
| deep (profile S6) | deep NAT probes include 300 s idle | true | true | yes |
| deep | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.416 over 86253 packets | **no** |
| rate-cap (safety) | initiator heavy send rate under --rate-cap 5 Mbit/s (≤ 5.5 Mbit/s) | 5000000 | 4791388.6258 | yes |
| rate-cap | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 9.945 over 6681 packets | n/a (smoke/light: fixed overhead dominates) |
| rate-100m (S6 size) | capacity a_to_b at 100 Mbit/s (±10%) | 99075297 | 99050240.0000 | yes |
| rate-100m (S6 size) | standard trace file size at 100 Mbit/s (≤ 10 MB) | 10000000 | 953030 | yes |
| rate-100m | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.395 over 90466 packets | **no** |
| geo (robustness S4 S7) | session complete | true | true | yes |
| geo (robustness S4 S7) | capacity a_to_b at 300 ms one way (bit/s, ±10%) | 19815059 | 19830720.0000 | yes |
| geo (robustness S4 S7) | capacity b_to_a at 300 ms one way (bit/s, ±10%) | 19815059 | 19810240.0000 | yes |
| geo (robustness S4 S7) | train and PMTU flows never stopped by the dead-man | 0 | 0 | yes |
| geo (robustness S4 S7) | light trains a_to_b still delivered after the saturations | > 0 | Some(448) | yes |
| geo (robustness S4 S7) | PMTU ladder a_to_b completed (path MTU 1500) | 1500 | 1500.0000 | yes |
| geo (robustness S4 S7) | light trains b_to_a still delivered after the saturations | > 0 | Some(464) | yes |
| geo (robustness S4 S7) | PMTU ladder b_to_a completed (path MTU 1500) | 1500 | 1500.0000 | yes |
| geo | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.857 over 59908 packets | **no** |
| geo-100m (S6) | session complete | true | true | yes |
| geo-100m (S6) | capacity a_to_b at 300 ms one way, 100 Mbit/s (±10%) | 99075297 | none | **no** |
| geo-100m (S6) | saturated time a_to_b (s, ≥ 3) | ≥ 3 | none | **no** |
| geo-100m (S6) | capacity b_to_a at 300 ms one way, 100 Mbit/s (±10%) | 99075297 | 77580160.0000 | **no** |
| geo-100m (S6) | saturated time b_to_a (s, ≥ 7) | ≥ 7 | 0.1529 | **no** |
| geo-100m | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 9.442 over 50225 packets | **no** |
| bufferbloat (robustness S4 S7) | session complete | true | true | yes |
| bufferbloat (robustness S4 S7) | train and PMTU flows never stopped by the dead-man | 0 | 0 | yes |
| bufferbloat (robustness S4 S7) | light trains a_to_b still delivered after the saturations | > 0 | Some(400) | yes |
| bufferbloat (robustness S4 S7) | PMTU ladder a_to_b completed (path MTU 1500) | 1500 | 1500.0000 | yes |
| bufferbloat (robustness S4 S7) | light trains b_to_a still delivered after the saturations | > 0 | Some(432) | yes |
| bufferbloat (robustness S4 S7) | PMTU ladder b_to_a completed (path MTU 1500) | 1500 | 1500.0000 | yes |
| bufferbloat | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 9.899 over 33853 packets | **no** |
| fast (safety budget) | session complete | true | true | yes |
| fast (safety budget) | hard data cap not reached by a (allowances planned the budget) | 0 | 0 | yes |
| fast (safety budget) | a UDP bytes sent within the standard cap (200 MB) | 200000000 | Some(165020185) | yes |
| fast (safety budget) | hard data cap not reached by b (allowances planned the budget) | 0 | 0 | yes |
| fast (safety budget) | b UDP bytes sent within the standard cap (200 MB) | 200000000 | Some(174032880) | yes |
| fast (safety budget) | every phase P4-P8 ran | 4 5 6 7 8 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] | yes |
| fast (safety budget) | saturations ended by their allowances (flow_stopped) | >= 2 | 3 | yes |
| fast | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 7.380 over 218219 packets | yes |
| rcvbuf (host drops S5 S9) | session complete | true | true | yes |
| rcvbuf (host drops S5 S9) | responder socket drops recorded (rxq_drops) | > 0 | 80.0000 | yes |
| rcvbuf (host drops S5 S9) | lost packets attributed to the receiving host | > 0 | 80.0000 | yes |
| rcvbuf (host drops S5 S9) | responder UDP RcvbufErrors increased (netstack) | > 0 | Some(80) | yes |
| rcvbuf (host drops S5 S9) | host drops not mistaken for a policer | not policer | unknown | yes |
| rcvbuf | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 10.047 over 8811 packets | n/a (smoke/light: fixed overhead dominates) |
| local-qdisc (host drops tx ids) | session complete | true | true | yes |
| local-qdisc (host drops tx ids) | initiator transmit id mode | explicit | explicit | yes |
| local-qdisc (host drops tx ids) | initiator send failures recorded (local qdisc full) | > 0 | 396 | yes |
| local-qdisc (host drops tx ids) | local qdisc drops a_to_b recorded | > 0 | 750.0000 | yes |
| local-qdisc (host drops tx ids) | TX stamps aligned after send failures (implausible joins) | 0 | Some(0) of Some(3317) | yes |
| local-qdisc | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 11.673 over 5934 packets | n/a (smoke/light: fixed overhead dominates) |
| local-qdisc-predicted (host drops tx ids) | session complete | true | true | yes |
| local-qdisc-predicted (host drops tx ids) | initiator transmit id mode | predicted | predicted | yes |
| local-qdisc-predicted (host drops tx ids) | initiator send failures recorded (local qdisc full) | > 0 | 469 | yes |
| local-qdisc-predicted (host drops tx ids) | local qdisc drops a_to_b recorded | > 0 | 664.0000 | yes |
| local-qdisc-predicted (host drops tx ids) | TX stamps aligned after send failures (implausible joins) | 0 | Some(0) of Some(3766) | yes |
| local-qdisc-predicted | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 11.553 over 6330 packets | n/a (smoke/light: fixed overhead dominates) |
| reorder-dup (S11 S12) | reordering detected a_to_b | > 0 | 0.0501 | yes |
| reorder-dup (S11 S12) | duplicate rate a_to_b (2% ± 1%) | 0.02 | 0.0217 | yes |
| reorder-dup (S11 S12) | no duplicates b_to_a | 0 | 0.0000 | yes |
| reorder-dup | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | 8.121 over 36714 packets | n/a (smoke/light: fixed overhead dominates) |
