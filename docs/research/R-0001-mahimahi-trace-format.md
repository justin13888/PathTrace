# R-0001: Mahimahi trace format, mm-link queues, mm-delay and mm-loss arguments
- source: https://github.com/ravinet/mahimahi (master @ f1346c38c415abfc98626dd82450f49a57033603): src/frontend/link_queue.{cc,hh}, src/frontend/linkshell.cc, src/frontend/delayshell.cc, src/frontend/lossshell.cc, src/frontend/loss_queue.{cc,hh}, src/packet/dropping_packet_queue.cc, src/packet/codel_packet_queue.cc, src/packet/pie_packet_queue.cc, man/mm-link.1
- accessed: 2026-10-10
- claim-under-test: Mahimahi traces have one line per delivery opportunity; the value is a millisecond timestamp; each opportunity carries one 1500-byte (MTU-sized) packet; the trace loops at the end.
- verdict: partially-confirmed
- applicability: Directly applicable. Mahimahi is PTF's main import and export target (SPEC sections 7.7, 11.4), so both the semantics and the edge cases must be exact.
## Evidence
man/mm-link.1 lines 40-47:
> Each line in the trace represents a packet delivery opportunity [...] Accounting is done
> at the byte-level, and each delivery opportunity represents the ability to
> deliver 1500 bytes. Thus, a single line [...] can delivery several smaller packets [...] When
> mm-link reaches the end of an input trace file, it wraps around to the beginning

The code differs from the man page in two ways.
- `link_queue.hh:19`: `const static unsigned int PACKET_SIZE = 1504; /* default max TUN payload size */`. The real quantum is 1504 bytes, not 1500.
- `link_queue.cc:219-247`: a packet larger than what is left of an opportunity carries over to the next one (`packet_in_transit_bytes_left_`). If the queue is empty, the rest of the opportunity is lost (`break`).
- `link_queue.cc:47-63`: each line is parsed with `myatoi` as an integer number of ms. Values must be monotonically non-decreasing, so repeated values are allowed and mean several opportunities in the same ms. The last value must be non-zero.
- `link_queue.cc:198-206`: on wraparound, `base_timestamp_ += schedule_.back()`. The loop period is the last timestamp. `--once` (linkshell.cc:128) turns looping off, and the link then stops delivering.

mm-link queues (linkshell.cc:17-30):
> --uplink-queue=QUEUE_TYPE --downlink-queue=QUEUE_TYPE  --uplink-queue-args=QUEUE_ARGS ...
> QUEUE_TYPE = infinite | droptail | drophead | codel | pie
> NAME = bytes | packets | target | interval | qdelay_ref | max_burst  (target, interval, qdelay_ref, max_burst in ms)

- The default queue is `infinite` (linkshell.cc:111). droptail and drophead require `packets=` or `bytes=` (dropping_packet_queue.cc:12-16). codel requires `target` and `interval` (codel_packet_queue.cc:10-19). pie takes `qdelay_ref` and `max_burst`. Example: `--downlink-queue=droptail --downlink-queue-args="packets=100"`.
- mm-delay (delayshell.cc:25): `delay-milliseconds [command...]`. A single integer in ms. The delay is fixed and applies to both directions.
- mm-loss (lossshell.cc:18): `uplink|downlink RATE`. RATE is in [0,1], applies to one direction, and is i.i.d. Bernoulli (loss_queue.hh:41 `bernoulli_distribution`). loss_queue.cc also has StochasticSwitchingLink and PeriodicSwitchingLink (on/off) classes, used by the mm-onoff shell.

Summary: a line is a ms timestamp, a line is an opportunity, and the trace loops. The "1500-byte packet" part is imprecise in two ways. Accounting is per byte with a 1504-byte quantum, and packets can span opportunities.
## Implications for PTF / probe
- PTF `capacity` in opportunity form needs an explicit `quantum_bytes`. The Mahimahi importer should set 1504, the value in the code, and record that the man page says 1500. The difference is about 0.27% of rate.
- Exported timestamps lose everything below 1 ms. Several opportunities in the same ms are legal, so the exporter must emit repeated lines and not rate-limit to 1 per ms.
- Export needs a loop period, which is the last timestamp. If PTF traces are not meant to loop, the exporter should pass `--once` or document the wrap.
- Mahimahi queue args only express packet or byte limits plus codel and pie parameters in ms. PTF queue hints should be convertible to `packets=`/`bytes=`.
- Export loses: delay variation (mm-delay is a constant integer in ms), loss structure (Bernoulli only), duplication, reordering, policers, and per-transport treatment.
