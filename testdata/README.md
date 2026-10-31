# testdata

Evaluation workloads, fixtures and the Phase 1 exit check. Tasks: [TASKS.md](TASKS.md).

```
testdata/
├── golden/container-escape.bin      compiled policy bundle (make golden)
├── workloads/
│   ├── benign/                      namespace statewall-eval
│   │   ├── web.yaml                 nginx + curl client loop
│   │   ├── busy.yaml                file churn + frequent exec
│   │   └── fragments.yaml           chain steps isolated / out of order, never the socket open
│   └── attack/container-escape.yaml socket open -> setns -> mount -> execve
├── scripts/
│   ├── phase1-exit-check.sh         EVAL-1.3: agent + workloads + assertions
│   └── check_audit.py               asserts on the JSONL audit stream (stdlib only)
└── fixtures/                        JSONL inputs for check_audit.py --self-test
```

| Assertion | Meaning |
|---|---|
| 1 | exactly one cgroup reaches `compromised` |
| 2 | that cgroup goes normal → suspicious → escalating → breakout_imminent → compromised, in timestamp order |
| 3 | no other cgroup reaches `escalating` or later |

## Run

Exit check, inside the Lima VM (`limactl shell statewall`), with the kind cluster up and
the agent, BPF object and bundle built:

```
testdata/scripts/phase1-exit-check.sh
```

| Variable | Default |
|---|---|
| `STATEWALL_AGENT` | `bin/statewall-agent` |
| `STATEWALL_OBJECT` | `bpf/target/bpfel-unknown-none/release/statewall` |
| `STATEWALL_BUNDLE` | `testdata/golden/container-escape.bin` |
| `KUBE_CONTEXT` | `kind-statewall-dev` |
| `BENIGN_SECONDS` / `ATTACK_SECONDS` | `30` / `15` |

The audit stream and agent log stay in the printed temp directory. Re-check a saved stream:

```
python3 testdata/scripts/check_audit.py /path/to/audit.jsonl
python3 testdata/scripts/check_audit.py --self-test
```

Exit codes: `0` pass, `1` assertion failed, `2` missing input.
