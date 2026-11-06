# Learn-mode end-to-end (F11 Phase 5)

Run 2026-11-06T13:36:29+00:00 on statewall-dev, learn namespace `ariguard-internal`.

The agent emits a full-syscall trace per process in an opted-in namespace; benign traffic becomes a production baseline and a process that trips a threat state yields an attack-labelled trace. Both land in the console mining corpus next to honeypot traces.

## Mining corpus after the run
| source | label | traces |
|---|---|---|
| learn | benign | 11459 (+38 during the run) |
| learn | attack | 6 (from the driven reverse-shell) |
| honeypot | attack | 1772 |
| honeypot | benign | 1291 |

The benign learn traces feed the baseline that gates false positives; the attack learn traces seed backbone discovery — the same path honeypot traces take (`compiler/tests/test_loop.py::test_learn_*`).

## Overhead (per hooked syscall, BPF_STATS)

Measured on the same single-node (4 vCPU) kind cluster, program `sw_openat` (the base detection hook) vs `sw_openat_learn` (the learn emit) — mean ns/run over a window.

| regime | sw_openat | sw_openat_learn | learn vs base |
|---|---|---|---|
| steady state (normal traffic) | ~3975 ns | ~2038 ns | +51% |
| 2M-openat flood (ring saturated) | ~1419 ns | ~6940 ns | +4.9x |

At normal rates the learn emit costs about half a detection hook per hooked syscall. Under a syscall flood on an opted-in pod the single AG_LEARN ring saturates and the emit cost balloons (lock contention) — which is exactly why learn-mode is opt-in per namespace and off by default, and why a sampling budget is the next increment. Absolute ns/run are rate- and cache-dependent on this tiny VM (note the base hook is cheaper warm under the flood); the within-regime ratio and the saturation behaviour are the stable signals.

