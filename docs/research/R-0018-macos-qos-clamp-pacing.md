# R-0018: macOS QoS clamps, darwinbg and the time-constraint policy for the pacer
- source: macOS SDK 26 headers (`mach/thread_policy.h`, `mach/thread_act.h`, `sys/resource.h`, `pthread/pthread.h`); taskpolicy(8) (macOS 26.6.1); issue #91 (local experiments that motivated this note); local experiments (macOS 26.6.1, Darwin 25.6.0 arm64, uid 501, no privileges) with `pt-sys` at branch `fix/91-macos-pacer-qos-clamp`
- accessed: 2026-10-15
- claim-under-test: a thread cannot raise its QoS class above its process's QoS clamp, so a probe launched under one paces milliseconds late even with `QOS_CLASS_USER_INTERACTIVE`; the Mach `THREAD_TIME_CONSTRAINT_POLICY`, settable unprivileged, restores sub-millisecond wakeups under a `utility` clamp but not under a `background` clamp or darwinbg; `getpriority(PRIO_DARWIN_PROCESS, 0)` reports darwinbg.
- verdict: partially-confirmed
- applicability: probe.md §9.4 (pacer and receiver scheduling, the pacing check), cli.md (`doctor` `pacing` check). The `macos-15` GitHub runner's 1.7-2.5 ms lateness (#89) matches the `utility` clamp, but which clamp that runner applies is not established here.
## Evidence

### Clamps and darwinbg **[man page + headers]**
taskpolicy(8): `-c clamp` "Run the program using the specified QoS clamp. The argument can be either
"utility", "background", or "maintenance""; `-b` "Run the program after calling setpriority(2) with a
priority of PRIO_DARWIN_BG". `sys/resource.h:106` `#define PRIO_DARWIN_PROCESS 4 /* Second argument is a
PID */`; `:116` "use PRIO_DARWIN_BG to set the current thread into "background" state which lowers CPU, disk
IO, and networking" priority (the header misspells the last word). Tested: `getpriority(PRIO_DARWIN_PROCESS, 0)` returned a positive value under
`taskpolicy -b` and 0 otherwise (also under `-c background`); it returns the state, not `PRIO_DARWIN_BG`
(0x1000), so the check is `> 0`.

### Time-constraint policy **[headers]**
`mach/thread_policy.h:120-150`: "This scheduling mode is for threads which have real time constraints on their
execution"; computation: "The thread may be preempted after the computation time has elapsed"; constraint:
"Must be (>= computation)"; preemptible: "IGNORED". `thread_policy_set(thread_act_t, thread_policy_flavor_t,
thread_policy_t, mach_msg_type_number_t)` in `mach/thread_act.h:322`; the calling thread's port is
`pthread_mach_thread_np(pthread_self())` (`pthread/pthread.h:543`), which needs no deallocation.

### Measured lateness **[tested]**
`clock::tests::sleep_until_is_accurate`: best of five `sleep_until(now + 2 ms)` with `SPIN_NS` = 500 µs, after
`set_pacing_qos`; pass is < 1 ms.

| launch | QoS class only (#91) | QoS class + time-constraint (this branch) |
|---|---|---|
| terminal, no clamp | pass | 5/5 pass; `doctor` reports `0 µs` |
| `taskpolicy -c utility` | 2.3 ms late | 5/5 pass (was 3/3 in #91) |
| `taskpolicy -c background` | not run | 2 of 3 fail, 20.6 and 34.7 ms late |
| `taskpolicy -b` (darwinbg) | 4.4 ms late | 6/6 fail, 3.4-42 ms late |

#91 also found that `setpriority(PRIO_DARWIN_PROCESS, 0, 0)` lifted the `-b` case (5/5 pass) but not the
`-c utility` clamp (5.2 and 5.5 ms late), and that `pthread_set_qos_class_self_np` fails once the
time-constraint policy is set, so the class must be set first. With that order both calls returned success in
every run above (`pacing_check` reported no policy error).

Not established: why the policy holds under `utility` but not `background` (no XNU source was read for the
clamp's effect on real-time threads), and whether XNU's real-time fail-safe demotes a pacer that spins for
long stretches at high rates.

## Implications for PTF / probe
- No PTF change: the lateness is already recorded per datagram (`tx_user_lag`) and as `stall` events.
- Pacer and receiver threads: QoS class, then the time-constraint policy (0.5 ms computation, 1 ms constraint).
- A clamp the policy cannot overcome is reported, not overridden: `doctor` `pacing` warns and `probe` prints a
  warning before measuring when a pacing-like thread wakes 1 ms or more late, naming darwinbg when `getpriority` reports it.
- `sleep_until_is_accurate` runs on macOS again; if the CI runner's clamp is `background` or darwinbg it fails
  there, which this note would then explain.
