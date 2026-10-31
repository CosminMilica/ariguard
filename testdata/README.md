# testdata

Evaluation workloads, expectations, fixtures and the exit check. Tasks: [TASKS.md](TASKS.md).

```
testdata/
├── expectations.json                per rule: terminal, chain, expected attacker pods
├── golden/policy.bin                compiled policy bundle (make golden)
├── workloads/                       namespace statewall-eval
│   ├── benign/
│   │   ├── web.yaml                 nginx + curl client loop
│   │   ├── busy.yaml                file churn + frequent exec
│   │   ├── fragments.yaml           escape-chain steps isolated / out of order, never the socket open
│   │   ├── reverse-twin.yaml        connect -> dup2 onto fd 5 -> exec /bin/true
│   │   └── fileless-twin.yaml       memfd_create -> exec /bin/true by path
│   └── attack/
│       ├── container-escape.yaml          openat socket -> setns -> mount -> execve
│       ├── container-escape-connect.yaml  connect socket -> setns -> mount -> execve
│       ├── reverse-seq.yaml               connect -> dup2(1) -> execve /bin/sh
│       └── fileless-seq.yaml              memfd_create -> execve /proc/self/fd/<n>
├── scripts/
│   ├── phase1-exit-check.sh         agent + workloads + assertions
│   └── check_audit.py               asserts on the v3 JSONL audit stream (stdlib only)
└── fixtures/                        JSONL inputs for check_audit.py --self-test
```

## Rules and emitters

| Rule | Scope | Chain | Attack pods | Benign twin (max state) |
|---|---|---|---|---|
| `container-escape` | cgroup | normal, suspicious, escalating, breakout_imminent, compromised | `container-escape`, `container-escape-connect` | `fragments` (normal) |
| `reverse-shell` | process | normal, connected, stdio_redirected, compromised | `reverse-seq` | `reverse-twin` (connected) |
| `fileless-exec` | process | normal, memfd_created, compromised | `fileless-seq` | `fileless-twin` (memfd_created) |

Every "attack" pod is a benign syscall-sequence emitter: it issues a fixed list of syscalls
so the `sys_enter_*` tracepoints fire. Tracepoints fire on syscall entry, so each call is
deliberately harmless: connect to a closed local port or a runtime socket, dup2 onto
`/dev/null`, exec of `/bin/true` or a no-op shell, a container-local tmpfs. There is no
listener, no Service and no remote endpoint. The twins keep the pod Running after the
emitter finishes so the exit check can wait for Ready.

## Assertions

Records are grouped per (rule, pod). `namespace` and `pod` come from the agent; a record
with an empty pod is a host process.

| Assertion | Meaning |
|---|---|
| A1 | every attacker listed for a rule has records whose from/to steps follow the chain in timestamp order up to the terminal state |
| A2 | no other pod, and no host process, reaches that rule's terminal state |
| A3 | every record with an action other than `observe` belongs to an attacker of that record's rule |

`check_audit.py` prints a per-(rule, pod) table (max state, actions). Exit codes: `0` pass,
`1` assertion failed, `2` bad input.

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
| `STATEWALL_BUNDLE` | `testdata/golden/policy.bin` |
| `STATEWALL_KUBECONFIG` | invoking user's `~/.kube/config` (resolved before sudo) |
| `KUBE_CONTEXT` | `kind-statewall-dev` |
| `BENIGN_SECONDS` / `ATTACK_SECONDS` | `30` / `15` |

The audit stream and agent log stay in the printed temp directory. Re-check a saved stream:

```
python3 testdata/scripts/check_audit.py [--expectations PATH] /path/to/audit.jsonl
python3 testdata/scripts/check_audit.py --self-test
```
