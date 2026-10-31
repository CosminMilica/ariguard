# Sigma rules → AriGuard FSM (CMP-3.1)

The AI bridge: a kill chain written as a [Sigma](https://sigmahq.io) `temporal_ordered`
correlation compiles to the same FSM `Rule` a hand-written `rules/*.yml` produces, so it
flows through `emit.py` and the policy bundle unchanged. The compiler is
`ariguard_compiler/sigma.py` (`compile_sigma(path) -> Rule`).

```
rules/sigma/
  reverse-shell.yml     # connect -> dup2/dup3 onto fd 0/1/2 -> exec /bin/sh,...       (T1059.004)
  fileless-exec.yml     # memfd_create -> fexecve/execve of the memfd                  (T1620)
  container-escape.yml  # runtime socket -> setns/unshare -> host mount -> execve      (T1611/T1610)
  README.md             # this file
```

All three hand-written rules (`reverse-shell`, `fileless-exec`, `container-escape`) are
expressible here and compile to rules that are fully structurally equal to their
`rules/*.yml` counterparts (see `tests/test_sigma.py`).

## The A1 subset

A file is a multi-document YAML: one `detection` **sub-rule** per step, then one
**correlation** that lists the sub-rules in order (the order = the FSM chain). A sub-rule's
`detection` has one or more named selections and a `condition` that names them; each
selection's `syscall` is one hook, or a **list of hooks that share the same predicates**
(e.g. `[dup2, dup3]`).

### Multi-selection OR (`condition: a or b`)

`condition` is either a single selection name or an OR of names (`sel1 or sel2 or sel3`).
Each selection is an **independent alternative with its own predicate shape**, so one step
can match over *different* hooks *and* *different* predicate kinds — e.g. `openat` on a
socket path **OR** `connect` on a `sun_path`, or `execveat` with `AT_EMPTY_PATH` **OR**
`execve` of a `/proc/self/fd` path. Only the `or` operator is supported in this subset:
`and`, `not` and parentheses raise `schema.RuleError`.

### Selection field → event binding

| Sigma field in a selection        | AriGuard binding            | Notes |
|-----------------------------------|-----------------------------|-------|
| `syscall: <hook>` / `[<hook>,...]`| `hook` (one binding each)   | required; hook ∈ `schema.HOOKS` |
| `path|startswith: [..]`           | `path_prefix`               | path arg per hook (`PATH_ARGS`) |
| `sun_path|startswith: [..]`       | `sun_path_prefix`           | `connect` only (AF_UNIX) |
| `arg<N>|mask_any: v`              | `arg {index:N, mask_any:v}` | bit set in arg N |
| `arg<N>|mask_none: v`            | `arg {index:N, mask_none:v}`| no bit of v set in arg N |
| `arg<N>|lte: v`                   | `arg {index:N, le:v}`       | arg N ≤ v |
| `arg<N>|eq: v`                    | `arg {index:N, eq:v}`       | arg N == v |

At most one `arg` predicate per selection. Patterns are ≤ 63 bytes (`schema.PATTERN_LEN`).

### Correlation + AriGuard extensions

| Key                | Meaning                                                        | Default |
|--------------------|---------------------------------------------------------------|---------|
| `type`             | must be `temporal_ordered`                                     | —       |
| `rules`            | ordered list of sub-rule names = the FSM chain                 | —       |
| `timespan`         | `<int><s\|m\|h\|d>` → `window_seconds`                         | 0 (none)|
| `scope`            | `cgroup` or `process` (`schema.SCOPE_VALUES`)                  | cgroup  |
| `terminal_action`  | action at the final step: `observe\|throttle\|deny\|kill`      | kill    |
| `actions`          | `{sub_rule_name: action}` to override a step's action          | observe for non-terminal steps |
| `states`           | explicit `N+1` state names (last = terminal)                   | `normal, stage_1.., compromised` |

Non-terminal steps default to `observe`; the terminal step uses `terminal_action`.

## ATT&CK tie-in

Each sub-rule and correlation carries a `tags:` field (and a comment) with the relevant
technique id: `attack.t1059.004` (Unix Shell) and `attack.t1095` for the reverse shell,
`attack.t1620` (Reflective Code Loading) for fileless execution, and `attack.t1611`
(Escape to Host) / `attack.t1610` (Deploy Container) for container escape. The tags are
documentation for analysts; the compiler ignores them (only `detection` and the
correlation drive the FSM).
