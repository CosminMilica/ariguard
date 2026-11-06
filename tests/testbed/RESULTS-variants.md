# Detection rate across variants (T3)

Each technique is driven by several **distinct implementations** of the same kill-chain, to show the
rules detect the *behaviour* (the hooked-syscall chain) rather than overfitting one payload. "caught"
= the agent raised a threat-state event (`stdio_redirected`/`memfd_created`/.../`compromised`) for
that technique's rule. Each variant was run against a tracked pod on `statewall-dev` (kind, kernel
6.x) and verified against the agent's audit stream.

## Per technique

| technique | detected | variants | rate |
|---|---|---|---|
| reverse-shell | 4 | 4 | 100% |
| fileless-exec | 2 | 2 | 100% |
| container-escape | 1 | 1 | 100% |
| **all** | **7** | **7** | **100%** |

## Per variant

| technique | variant | result |
|---|---|---|
| reverse-shell | `/bin/sh`, stdio via `dup2` | caught (→ compromised) |
| reverse-shell | `/bin/bash`, stdio via `dup2` | caught (→ compromised) |
| reverse-shell | `/bin/sh`, stdio via the `dup3` syscall | caught (→ compromised) |
| reverse-shell | `/usr/bin/bash`, stdio via `dup2` | caught (→ compromised) |
| fileless-exec | `memfd_create` → `execve(/proc/self/fd/N)` | caught (→ compromised) |
| fileless-exec | `memfd_create` → `execveat(AT_EMPTY_PATH)` | caught (→ compromised) |
| container-escape | runtime-socket → `setns` (nsenter) → host `mount` → `execve` | caught (→ compromised) |

## Why these variants

The rules match on *bindings*, not literal payloads, so each technique's single rule spans its
variants by construction, which the run confirms:

- **reverse-shell** — `stdio_redirect` matches `dup2` **or** `dup3` (newfd ≤ 2), and `shell_exec`
  lists `/bin/sh`, `/bin/bash`, `/usr/bin/bash`; so the shell used and the redirect syscall vary
  freely.
- **fileless-exec** — the in-memory fd is executed via `execve(/proc/self/fd/…)` **or**
  `execveat(AT_EMPTY_PATH)`; both reach `compromised` from `memfd_created`.
- **container-escape** — `namespace_manipulation` matches `setns`/`unshare` with the escape flags,
  `host_mount` matches `mount`/`fsmount`/`move_mount`; the chain is cgroup-scoped.

## Running it

`run-variants.sh` automates this against a running enforce+sink agent. It drives each variant through
the target's shell, reads detection straight from the agent's audit stream, and writes this file. The
targets must be **settled/tracked** first — the agent begins auditing a pod's cgroup only a short
while after the pod is created, so a freshly-(re)started target can read as missed until it warms up
(the script warms each target before attacking).
