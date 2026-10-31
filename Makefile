.PHONY: help dev-up kubeconfig dev-down build build-bpf build-agent build-go build-compiler proto golden deploy load-policy demo-escape test fmt clean

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

fmt: ## Format all code
	cd bpf && cargo fmt
	go fmt ./...
	cd compiler && ruff format .

clean: ## Remove build artifacts
	cd bpf && cargo clean
	go clean ./...
