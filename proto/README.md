# proto — gRPC contract (agent ↔ control-plane)

Source: [ariguard/v1/ariguard.proto](ariguard/v1/ariguard.proto).
Generated Go lands in `pkg/proto/ariguardv1` (per the `go_package` option).

## Generate

```sh
make proto      # runs `buf generate proto` from the repo root
```

## Prerequisites (one-time, not installed globally by this repo)

```sh
# buf CLI
brew install bufbuild/buf/buf          # or: go install github.com/bufbuild/buf/cmd/buf@latest

# protoc plugins (installed into $(go env GOPATH)/bin — keep it on PATH)
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

After the first generation, pull in the runtime deps:

```sh
go mod tidy     # adds google.golang.org/protobuf and google.golang.org/grpc
```

## Layout

- `buf.yaml` (here) — module config: lint + breaking-change rules.
- `buf.gen.yaml` (repo root) — plugins and output; `module=` strips the Go module
  prefix so files land at `pkg/proto/ariguardv1/`.
