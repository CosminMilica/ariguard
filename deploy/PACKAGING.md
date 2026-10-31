# AriGuard — packaging & release

Ship the whole app (agent + console) as versioned, public container images on
GHCR, installable with one Helm command. Status: `[ ]` todo.

Decisions
- GHCR packages are **public** (no imagePullSecret in the cluster).
- Registry namespace: `ghcr.io/cosminmilica`.
- Images: `ariguard-agent`, `ariguard-console-backend`, `ariguard-console-frontend`.
- Multi-arch `linux/amd64,linux/arm64` (runners are amd64, the dev VM is arm64).

## 1. Helm chart — one umbrella for the whole app

```
deploy/helm/ariguard/
  Chart.yaml            # name: ariguard, version (chart), appVersion (release)
  values.yaml
  templates/
    _helpers.tpl
    namespace.yaml
    agent/            rbac.yaml  daemonset.yaml
    console/          backend-deployment.yaml  backend-service.yaml  backend-pvc.yaml
                      frontend-deployment.yaml frontend-service.yaml
    ingress.yaml      # optional, gated by values
```

`values.yaml` (the knobs):
| Key | Default | Meaning |
|---|---|---|
| `image.registry` | `ghcr.io/cosminmilica` | pull base |
| `image.tag` | `.Chart.appVersion` | image tag for all three |
| `agent.enforce` | `true` | detect vs enforce |
| `agent.sinkUrl` | auto → console backend svc | where the agent pushes |
| `agent.resources` / `console.*.resources` | modest requests | hygiene |
| `console.enabled` | `true` | deploy the console or agent-only |
| `console.storage.size` | `1Gi` | SQLite PVC |
| `console.expose` | `none\|nodePort\|ingress` | how to reach the UI |

Install: `helm upgrade --install ariguard deploy/helm/ariguard -n ariguard-system --create-namespace`.
The raw `deploy/k8s` kustomize stays for quick local dev; Helm is the shipped path.

## 2. CI — build + push to GHCR (`.github/workflows/release.yml`)

Triggers: push to `main`, tags `v*`, and manual `workflow_dispatch`.
`permissions: { contents: read, packages: write }`.

Steps:
1. Build the BPF object + agent binary + golden (bpf-linker, as the e2e job does); the `.bpf.o` is arch-independent BPF bytecode, the Go binary is per-arch.
2. `docker/setup-buildx-action` + `docker/setup-qemu-action` for multi-arch.
3. `docker/login-action` to `ghcr.io` with `GITHUB_TOKEN`.
4. `docker/build-push-action` for each of the 3 images, `platforms: linux/amd64,linux/arm64`, Dockerfiles under `console/{backend,frontend}` and `deploy/docker` (agent).
5. Tags per image: `sha-<short>` always; `latest` on `main`; `vX.Y.Z` on a release tag.
6. First publish: mark each package **public** in the repo's package settings (one-time).

Optional on `v*` tags: `helm package` + `helm push` the chart as an **OCI artifact** to
`oci://ghcr.io/cosminmilica/charts`, so `helm install oci://ghcr.io/cosminmilica/charts/ariguard --version X.Y.Z` works.

## 3. Open points (thought-through)
- **Versioning**: `appVersion` = release (drives image tags); chart `version` bumped per chart change. `latest` only from `main`.
- **Agent multi-arch**: build the Go binary per target arch inside buildx; copy the shared `.bpf.o`. (Agent image today is single-arch via `make image`; the release job uses buildx instead.)
- **Keep CI green**: `release.yml` is separate from `ci.yml`; it does not gate PRs (runs on main/tags).
- **Local dev unchanged**: `make image` / kind-load / kustomize still work for the VM loop.

## Implementation waves
1. Helm chart (templates + values) from the current manifests; `make helm-install`.
2. `release.yml`: multi-arch build + push of the 3 images to public GHCR.
3. (optional) Helm chart as OCI on tags.
4. Point `values.yaml` image tags at GHCR; verify `helm install` pulls public images into kind.
