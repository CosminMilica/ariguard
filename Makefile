.PHONY: image kind-load help dev-up kubeconfig dev-down build build-bpf build-agent build-go build-compiler proto golden deploy load-policy demo-escape test fmt clean \
	cover ci ci-hygiene ci-unit ci-contract ci-bpf ci-kernel ci-kernel-host ci-e2e ci-security

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

dev-up: ## Provision the Linux dev VM (Lima) + kind cluster
	limactl start --name=ariguard --tty=false --timeout=20m deploy/lima/ariguard.yaml
	limactl stop ariguard && limactl start ariguard --tty=false --timeout=20m   # apply BPF LSM cmdline + docker group
	limactl shell ariguard -- bash -lc 'cd $(CURDIR) && kind create cluster --name ariguard-dev --config deploy/kind/cluster.yaml'
	$(MAKE) kubeconfig
	@echo "Dev VM ready. Enter with: limactl shell ariguard"

kubeconfig: ## Export the kind kubeconfig to ~/.kube/ariguard-dev.yaml (for kubectl/Lens on the host)
	@mkdir -p $(HOME)/.kube
	limactl shell ariguard -- kind get kubeconfig --name ariguard-dev > $(HOME)/.kube/ariguard-dev.yaml
	@chmod 600 $(HOME)/.kube/ariguard-dev.yaml
	@echo "Use: KUBECONFIG=$(HOME)/.kube/ariguard-dev.yaml kubectl get nodes  (or add the file in Lens)"

dev-down: ## Tear down the local dev environment
	-limactl shell ariguard -- kind delete cluster --name ariguard-dev
	-limactl stop ariguard
	limactl delete ariguard

build: build-bpf build-go build-compiler ## Build everything

BPF_OBJECT := bin/ariguard.bpf.o

build-bpf: ## Build the Rust eBPF data plane into bin/ariguard.bpf.o (Linux VM)
	cd bpf && cargo build --release
	@mkdir -p bin
	cp bpf/target/bpfel-unknown-none/release/ariguard $(BPF_OBJECT)

build-agent: ## Build the node agent for Linux into bin/ariguard-agent
	@mkdir -p bin
	GOOS=linux go build -o bin/ariguard-agent ./agent/cmd/ariguard-agent

build-go: ## Build the Go agent + control-plane
	go build ./...

build-compiler: ## Install the Python rule compiler (editable)
	cd compiler && pip install -e .

proto: ## Generate Go + gRPC from proto/ (needs: buf, protoc-gen-go, protoc-gen-go-grpc — see proto/README.md)
	buf generate proto

golden: ## Regenerate the cross-language golden transition table
	cd compiler && python -m ariguard_compiler.cli --rules-dir rules --out ../testdata/golden/policy.bin

IMAGE ?= ariguard-agent:dev
IMAGE_PLATFORM ?= linux/$(shell go env GOARCH)

image: ## Package the agent image (run make build-agent build-bpf golden first; in the VM)
	docker build --platform $(IMAGE_PLATFORM) -f deploy/docker/Dockerfile -t $(IMAGE) .

kind-load: ## Load the agent image into the kind cluster (in the VM)
	kind load docker-image $(IMAGE) --name ariguard-dev

deploy: ## Deploy the DaemonSet (detect overlay) to the kind cluster (in the VM)
	kubectl apply -k deploy/k8s/overlays/detect

load-policy: ## Load a threat policy (POLICY=container-escape)
	@echo "TODO(phase-3): compile + push policy $(POLICY)"

demo-escape: ## Run the container-escape demo: detect-only, then --enforce (in the VM; needs `make image kind-load`)
	limactl shell ariguard -- bash -lc 'cd $(CURDIR) && deploy/demo-escape.sh'

test: ## Run all tests
	cargo test --manifest-path bpf/Cargo.toml -p ariguard-common   # from the root: skips the BPF target in bpf/.cargo
	go test ./...
	cd compiler && python -m pytest

# CI gates (docs/ci-plan.md). CI runs exactly these targets.
OBJECT_ENV := ARIGUARD_REQUIRE_OBJECT=1 ARIGUARD_OBJECT=$(CURDIR)/$(BPF_OBJECT)
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
COVER_EXCLUDE := agent/cmd/ariguard-agent agent/internal/loader \
	agent/internal/audit/ringbuf agent/internal/policy/kmap \
	agent/internal/metrics/metricmap agent/internal/podsync/podmap
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
	cd compiler && $(PYTHON) -m pytest -q --cov=ariguard_compiler --cov-report=term --cov-fail-under=80 || fail=1; \
	exit $$fail

ci-unit: test cover ## G1: unit tests + coverage gate
	$(PYTHON) -m pytest tests/meta
	python3 testdata/scripts/check_audit.py --self-test

ci-contract: golden ## G2: generated artifacts fresh, contracts unbroken
	git diff --exit-code -- testdata/golden
	go mod tidy -diff
	buf breaking proto --against '$(BUF_AGAINST)'

ci-bpf: build-bpf ## G3: BPF object builds, ABI matches its BTF, instruction budget
	$(OBJECT_ENV) go test -count=1 ./pkg/fsm ./agent/internal/loader

ci-kernel: ## G4: load + chain tests on KERNEL in a VM (vimto; needs bin/ariguard.bpf.o)
	$(OBJECT_ENV) vimto -kernel :$(KERNEL) -- go test -tags integration -count=1 -v ./agent/internal/integration

ci-kernel-host: ## G4: load + chain tests on the running kernel (sudo; needs bin/ariguard.bpf.o)
	$(OBJECT_ENV) go test -exec 'sudo -E' -tags integration -count=1 -v ./agent/internal/integration

ci-e2e: build-bpf build-agent golden ## G5: detect + enforce end-to-end on the kind cluster (in the VM; needs a kill-capable BPF object)
	ARIGUARD_REQUIRE_E2E=1 go test -tags e2e -count=1 -v -timeout 40m ./test/e2e

ci-security: ## G6: vulnerability, license and secret scans
	govulncheck ./...
	cd bpf && cargo deny check
	pip-audit --progress-spinner off ./compiler
	gitleaks git --redact --no-banner .

ci-console: ## G7: console backend tests + frontend build + image builds (separate module)
	cd console/backend && go build ./... && go test ./...
	cd console/frontend && npm ci && npm run build
	docker build -t ariguard-console-backend:ci console/backend
	docker build -t ariguard-console-frontend:ci console/frontend

fmt: ## Format all code
	cd bpf && cargo fmt
	go fmt ./...
	cd compiler && ruff format .

console-up: ## Build + run the AriGuard Console (backend+frontend+sqlite) at http://localhost:8080
	docker compose -f console/docker-compose.yml up --build

console-down: ## Stop the console
	docker compose -f console/docker-compose.yml down

console-backend: ## Run the console backend locally on :8080 (serves ./public if built)
	cd console/backend && go run . --addr :8080

console-frontend: ## Run the console frontend dev server (Vite)
	cd console/frontend && npm install && npm run dev

clean: ## Remove build artifacts
	cd bpf && cargo clean
	go clean ./...
