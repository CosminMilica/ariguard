.PHONY: help dev-up kubeconfig vm-sync dev-down build build-bpf build-agent build-go build-compiler proto golden deploy load-policy demo-escape test fmt clean \
	cover ci ci-hygiene ci-unit ci-contract ci-bpf ci-kernel ci-kernel-host ci-e2e ci-security

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

# Checkouts outside the VM's mount (~/work/statewall) are copied to the VM's own disk.
VM_DIR ?= /home/$(USER).guest/$(notdir $(CURDIR))

vm-sync: ## Copy this checkout into the VM ($(VM_DIR)); then: limactl shell --workdir $(VM_DIR) statewall
	rsync -a --delete --exclude bin/ --exclude bpf/target/ --exclude compiler/.venv/ \
		-e "ssh -F $(HOME)/.lima/statewall/ssh.config" ./ lima-statewall:$(VM_DIR)/

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
	cd compiler && python -m statewall_compiler.cli --rules-dir rules --out ../testdata/golden/policy.bin

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

PYTHON ?= python
COVER_MIN := 80.0
# Linux-only kernel glue, covered by ci-kernel; "[no statements]" packages are skipped too.
COVER_EXCLUDE := agent/cmd/statewall-agent agent/internal/loader
COVER_DIR := bin/cover

cover: ## Per-package coverage gate: Go + Python >= $(COVER_MIN)%
	@mkdir -p $(COVER_DIR)
	@fail=0; for pkg in $$(go list -f '{{.ImportPath}}' ./...); do \
		rel=$${pkg#$$(go list -m)/}; \
		case " $(COVER_EXCLUDE) " in *" $$rel "*) printf '%-45s skipped (excluded)\n' $$rel; continue;; esac; \
		rm -f $(COVER_DIR)/c.out; \
		out=$$(go test -count=1 -coverprofile=$(COVER_DIR)/c.out $$pkg) || { echo "$$out"; fail=1; continue; }; \
		if [ "$$(awk 'NR>1{n+=$$2} END{print n+0}' $(COVER_DIR)/c.out 2>/dev/null)" -eq 0 ]; then printf '%-45s skipped (no statements)\n' $$rel; continue; fi; \
		pct=$$(go tool cover -func=$(COVER_DIR)/c.out | tail -1 | awk '{print $$NF}' | tr -d %); \
		if awk "BEGIN{exit !($$pct >= $(COVER_MIN))}"; then st=ok; else st=FAIL; fail=1; fi; \
		printf '%-45s %5s%%  %s\n' $$rel $$pct $$st; \
	done; \
	cd compiler && $(PYTHON) -m pytest -q --cov=statewall_compiler --cov-report=term --cov-fail-under=80 || fail=1; \
	exit $$fail

ci-unit: test cover ## G1: unit tests + coverage gate
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
