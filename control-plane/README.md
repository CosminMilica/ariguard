# control-plane — cluster operator (Go)

A Kubernetes operator (controller-runtime) that manages Statewall across the fleet:

- **apis/v1alpha1** — the `ThreatPolicy` CRD: which FSM / kill chains to enforce and
  how to escalate mitigation.
- **controllers** — reconcile `ThreatPolicy` objects, compile them (via the Python
  compiler) into transition tables, and distribute them to the node agents.

It also aggregates audit telemetry from agents. The control plane is cluster-scoped
coordination only — it never makes per-syscall decisions.
