.PHONY: help dev-up kubeconfig dev-down build build-bpf build-agent build-go build-compiler proto golden deploy load-policy demo-escape test fmt clean \
	ci ci-hygiene ci-unit ci-contract ci-bpf ci-kernel ci-kernel-host ci-e2e ci-security

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

dev-up: ## Provision the Linux dev VM (Lima) + kind cluster
	limactl start --name=statewall --tty=false --timeout=20m deploy/lima/statewall.yaml
	limactl stop statewall && limactl start statewall --tty=false --timeout=20m   # apply BPF LSM cmdline + docker group
	limactl shell statewall -- bash -lc 'cd $(CURDIR) && kind create cluster --name statewall-dev --config deploy/kind/cluster.yaml'
	$(MAKE) kubeconfig
	@echo "Dev VM ready. Enter with: limactl shell statewall"

kubeconfig: ## Export the kind kubeconfig to ~/.kube/statewall-dev.yaml (for kubectl/Lens on the host)
	@mkdir -p $(HOME)/.kube
	limactl shell statewall -- kind get kubeconfig --name statewall-dev > $(HOME)/.kube/statewall-dev.yaml
	@chmod 600 $(HOME)/.kube/statewall-dev.yaml
	@echo "Use: KUBECONFIG=$(HOME)/.kube/statewall-dev.yaml kubectl get nodes  (or add the file in Lens)"

dev-down: ## Tear down the local dev environment
	-limactl shell statewall -- kind delete cluster --name statewall-dev
	-limactl stop statewall
	limactl delete statewall

build: build-bpf build-go build-compiler ## Build everything

BPF_OBJECT := bin/statewall.bpf.o

build-bpf: ## Build the Rust eBPF data plane into bin/statewall.bpf.o (Linux VM)
	cd bpf && cargo build --release
	@mkdir -p bin
	cp bpf/target/bpfel-unknown-none/release/statewall $(BPF_OBJECT)

build-agent: ## Build the node agent for Linux into bin/statewall-agent
	@mkdir -p bin
	GOOS=linux go build -o bin/statewall-agent ./agent/cmd/statewall-agent

build-go: ## Build the Go agent + control-plane
	go build ./...

build-compiler: ## Install the Python rule compiler (editable)
	cd compiler && pip install -e .

proto: ## Generate Go + gRPC from proto/ (needs: buf, protoc-gen-go, protoc-gen-go-grpc — see proto/README.md)
	buf generate proto

golden: ## Regenerate the cross-language golden transition table
	cd compiler && python -m statewall_compiler.cli \
		--input rules/container-escape.yml \
		--out ../testdata/golden/container-escape.bin

deploy: ## Deploy the DaemonSet + operator to the kind cluster
	@echo "TODO(phase-1): kubectl apply -k deploy/k8s"

load-policy: ## Load a threat policy (POLICY=container-escape)
	@echo "TODO(phase-3): compile + push policy $(POLICY)"

demo-escape: ## Run the container-escape demo (train, then block)
	@echo "TODO(phase-2): run demo"

test: ## Run all tests
	cargo test --manifest-path bpf/Cargo.toml -p statewall-common   # from the root: skips the BPF target in bpf/.cargo
	go test ./...
	cd compiler && python -m pytest

# CI gates (docs/ci-plan.md). CI runs exactly these targets.
OBJECT_ENV := STATEWALL_REQUIRE_OBJECT=1 STATEWALL_OBJECT=$(CURDIR)/$(BPF_OBJECT)
KERNEL ?= stable
BUF_AGAINST ?= .git\#ref=refs/remotes/origin/main,subdir=proto

ci: ci-hygiene ci-unit ci-contract ci-bpf ci-security ## Run every gate that needs no VM

ci-hygiene: ## G0: format + lint
	cd bpf && cargo fmt --check
	cd bpf && cargo clippy --release -- -D warnings
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	golangci-lint run ./...
	cd compiler && ruff check . ../testdata/scripts && ruff format --check . ../testdata/scripts
	buf lint proto
	shellcheck testdata/scripts/*.sh

ci-unit: test ## G1: unit tests
	python3 testdata/scripts/check_audit.py --self-test

ci-contract: golden ## G2: generated artifacts fresh, contracts unbroken
	git diff --exit-code -- testdata/golden
	go mod tidy -diff
	buf breaking proto --against '$(BUF_AGAINST)'

ci-bpf: build-bpf ## G3: BPF object builds, ABI matches its BTF, instruction budget
	$(OBJECT_ENV) go test -count=1 ./pkg/fsm ./agent/internal/loader

ci-kernel: ## G4: load + chain tests on KERNEL in a VM (vimto; needs bin/statewall.bpf.o)
	$(OBJECT_ENV) vimto -kernel :$(KERNEL) -- go test -tags integration -count=1 -v ./agent/internal/integration

ci-kernel-host: ## G4: load + chain tests on the running kernel (sudo; needs bin/statewall.bpf.o)
	$(OBJECT_ENV) go test -exec 'sudo -E' -tags integration -count=1 -v ./agent/internal/integration

ci-e2e: build-agent ## G5: Phase 1 exit check on the kind cluster (needs bin/statewall.bpf.o)
	STATEWALL_OBJECT=$(CURDIR)/$(BPF_OBJECT) testdata/scripts/phase1-exit-check.sh

ci-security: ## G6: vulnerability, license and secret scans
	govulncheck ./...
	cd bpf && cargo deny check
	pip-audit --progress-spinner off ./compiler
	gitleaks git --redact --no-banner .

fmt: ## Format all code
	cd bpf && cargo fmt
	go fmt ./...
	cd compiler && ruff format .

clean: ## Remove build artifacts
	cd bpf && cargo clean
	go clean ./...
