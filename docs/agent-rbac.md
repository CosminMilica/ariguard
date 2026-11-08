# Agent RBAC (least privilege per isolation mode)

The agent DaemonSet runs privileged + hostPID with BPF/SYS_ADMIN, so its ServiceAccount
permissions are part of the node's blast radius: anything the token can do, a compromised agent
or node can do cluster-wide. The ClusterRole is therefore scoped to exactly what the enabled
features call, gated by Helm on `agent.isolate` and `agent.isolateFallback`
(`templates/agent-rbac.yaml`). A detect-only deployment gets no destructive verbs at all.

## What the code actually calls

- `podmeta` polls `Pods(AllNamespaces).List` to map cgroups to pods — needs read on `pods`.
- `responder` (autonomous isolation) only acts on a confirmed terminal kill/deny:
  - `Pods(ns).Patch` — add/remove the `ariguard.io/quarantine` label (quarantine + release).
  - `NetworkPolicies(ns).Create` — a deny-all NetworkPolicy (`isolate: on` only; `AlreadyExists`
    is treated as success, so it never Updates/Gets/Lists/Patches NetworkPolicies).
  - `Pods(ns).Delete` — evict the quarantined pod (`isolateFallback: evict` only).

## Verbs granted per mode

| Resource | Verbs | detect-only (`isolate: off`) | `isolate: dryrun` | `isolate: on` | `isolate: on` + `isolateFallback: evict` |
|---|---|---|---|---|---|
| `pods` | `get,list,watch` | yes | yes | yes | yes |
| `pods` | `patch` | — | yes | yes | yes |
| `pods` | `delete` | — | — | — | yes |
| `networkpolicies` | `create` | — | — | yes | yes |

Read on `pods` is always granted (it carries no destructive power). `patch` is granted whenever
isolation is enabled (`isolate != off`), because both `dryrun` and `on` (un)label pods. The two
cluster-wide destructive verbs are each opt-in:

- `pods: delete` only when `isolateFallback: evict`.
- `networkpolicies: create` only when `isolate: on` (`dryrun` never touches the networking API).

## Blast-radius reasoning

`pods: delete` cluster-wide lets a compromised agent delete any pod in the cluster, and
`networkpolicies: create` lets it cut traffic to any workload. Neither is needed unless the
corresponding isolation feature is turned on, so they are withheld by default. The read grant is
cluster-wide by necessity (an agent resolves pods on any namespace scheduled to its node), but
read-only exposure (pod metadata) is a much smaller risk than write/delete. `update` on
NetworkPolicies was dropped entirely: the responder only ever creates the static deny-all object.
