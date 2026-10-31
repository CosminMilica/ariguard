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
│   ├── phase1-exit-check.sh         agent + workloads + assertions (STATEWALL_ENFORCE=1 for enforce mode)
│   ├── phase2-exit-check.sh         phase1-exit-check.sh with STATEWALL_ENFORCE=1
│   └── check_audit.py               asserts on the v3 JSONL audit stream (stdlib only)
└── fixtures/                        JSONL inputs for check_audit.py --self-test
    ├── pass.jsonl, fail-a1-*, fail-a2-*, fail-a3-*   v1 (no `enforced` key; dry-run only)
    ├── pass-v2-dryrun.jsonl         every record enforced:false
    ├── pass-v2-enforce.jsonl        attackers' terminal records enforced:true, rest false
    └── fail-a4-*.jsonl              benign-enforced, host-enforced, action-not-kill, enforce-missing
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

| A4 | every record with `enforced: true` belongs to an attacker of that record's rule and has `action == kill` |

A4 modes: with `--enforce`, each attacker's terminal record (`to` == the rule's terminal)
must also have `enforced: true`; without it (dry-run), no record may have `enforced: true`.
A missing `enforced` key counts as false (v1 streams pass in dry-run).

| A4 reason | Meaning |
|---|---|
| `pod` / `host` | enforced on a non-attacker pod / a host process |
| `action` | enforced on an attacker record whose action is not `kill` |
| `unenforced` | `--enforce`: attacker terminal record without `enforced: true` |
| `dryrun` | no `--enforce`: a record has `enforced: true` |

`check_audit.py` prints a per-(rule, pod) table (max state, actions, enforced = enforced
records / records). Exit codes: `0` pass, `1` assertion failed, `2` bad input.

## Run

Exit check, inside the Lima VM (`limactl shell statewall`), with the kind cluster up and
the agent, BPF object and bundle built:

```
testdata/scripts/phase1-exit-check.sh
```

Enforce mode (Phase 2): `testdata/scripts/phase2-exit-check.sh`, or
`STATEWALL_ENFORCE=1 testdata/scripts/phase1-exit-check.sh`. The agent gets `--enforce` and the
checker gets `--enforce`. Besides the audit assertions, it requires every attack pod to reach
phase `Failed` and every benign pod to be neither `Failed` nor restarted; the agent and node
must stay up (host untouched).

| Variable | Default |
|---|---|
| `STATEWALL_ENFORCE` | `0` (`1` = enforce mode) |
| `STATEWALL_AGENT` | `bin/statewall-agent` |
| `STATEWALL_OBJECT` | `bpf/target/bpfel-unknown-none/release/statewall` |
| `STATEWALL_BUNDLE` | `testdata/golden/policy.bin` |
| `STATEWALL_KUBECONFIG` | invoking user's `~/.kube/config` (resolved before sudo) |
| `KUBE_CONTEXT` | `kind-statewall-dev` |
| `BENIGN_SECONDS` / `ATTACK_SECONDS` | `30` / `15` |

The audit stream and agent log stay in the printed temp directory. Re-check a saved stream:

```
python3 testdata/scripts/check_audit.py [--expectations PATH] [--enforce] /path/to/audit.jsonl
python3 testdata/scripts/check_audit.py --self-test    # runs every fixture in both modes
```
