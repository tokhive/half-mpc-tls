.PHONY: build test check smoke smoke-tls13 smoke-tls13-large demo bench-e2e bench-e2e-quick validate-local
build:
	mkdir -p bin
	go build -trimpath -o bin/tokenhive-hub ./cmd/tokenhive-hub
	go build -trimpath -o bin/tokenhive-provider-agent ./cmd/tokenhive-provider-agent
	cd rust && cargo build --locked --release -p tokenhive-sidecar

test:
	go test -race ./...
	cd rust && cargo test --locked --workspace

check:
	go vet ./...
	cd rust && cargo fmt --all --check
	cd rust && cargo clippy --locked --workspace --all-targets -- -D warnings

smoke: build
	python3 scripts/demo.py --check

smoke-tls13: build
	python3 scripts/demo.py --check --tls-version 1.3

smoke-tls13-large: build
	python3 scripts/demo.py --check --tls-version 1.3 --capacity 5m --prompt-bytes 5241856

demo: build
	python3 scripts/demo.py

# Local synthetic upstream, real MPC and SDK; no paid API calls.
bench-e2e: build
	go build -trimpath -o bin/tokenhive-loadtest ./scripts/loadtest
	python3 scripts/benchmark-e2e.py --seconds 45

bench-e2e-quick: build
	go build -trimpath -o bin/tokenhive-loadtest ./scripts/loadtest
	python3 scripts/benchmark-e2e.py --quick --seconds 5

# Local fault recovery, CPU profile and 3 x 5 minute continuous load.
validate-local: build
	go build -trimpath -o bin/tokenhive-loadtest ./scripts/loadtest
	go build -trimpath -o bin/tokenhive-profile-hub ./scripts/profilehub
	python3 scripts/validate-production.py --mode faults
	python3 scripts/validate-production.py --mode profile
	python3 scripts/validate-production.py --mode soak --seconds 300
