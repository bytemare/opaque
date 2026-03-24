# Coverage defaults
GO_COVERAGE_REPORT_PATH ?= coverage.out
GO_COVERAGE_PACKAGE ?= ../...
GO_COVERAGE_TEST_TARGET ?= ../...

# Fuzzing defaults
# Local and CI intentionally use different caches. Local runs should build on
# prior short sessions, while CI gets its own persistent cache restored by the
# workflow.
FUZZ_DEFAULT_TIME ?= 3s
FUZZ_LOCAL_GOCACHE_DIR ?= .gocache
FUZZ_CI_GOCACHE_DIR ?= .gocache-fuzz-ci

.PHONY: update
update:
	@echo "Updating dependencies..."
	@cd ../ && go get -u ./...
	@go mod tidy

.PHONY: update-linters
update-linters:
	@echo "Updating linters..."
	@go install mvdan.cc/gofumpt@latest
	@go install github.com/daixiang0/gci@latest
	@go install github.com/segmentio/golines@latest
	@go install github.com/google/addlicense@latest
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@go install golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment@latest

.PHONY: fmt
fmt:
	@echo "Formatting ..."
	@go mod tidy
	@go fix ../...
	@go fmt ../...
	@golines -m 120 -t 4 -w ../
	@gofumpt -w -extra ../
	@gci write -s standard -s default -s "Prefix($(shell go list -m))" -s blank -s dot -s alias --skip-generated ../
	@fieldalignment -fix ../...

.PHONY: license
license:
	@echo "Checking License headers ..."
	@if addlicense -check -v -skip yaml -f licence-header.tmpl ../*; then echo "License headers OK"; else exit 1; fi;

.PHONY: lint
lint: license
	@echo "Linting ..."
	@if golangci-lint run --config=.golangci.yml ../...; then echo "Linting OK"; else exit 1; fi;

.PHONY: lint-config
lint-config:
	@echo "Verifying golangci-lint configuration ..."
	@if golangci-lint config verify -v --config=.golangci.yml; then echo "Config OK"; else exit 1; fi;

.PHONY: check
check:
	@echo "Running full validation suite ..."
	@$(MAKE) lint
	@$(MAKE) vulncheck
	@$(MAKE) test
	@$(MAKE) cover
	@FUZZTIME=$${FUZZTIME:-1s} $(MAKE) fuzz

.PHONY: vulncheck
vulncheck:
	@echo "Running govulncheck ..."
	@govulncheck -show verbose ../...

.PHONY: test
test:
	@echo "Running all tests ..."
	@go test -v -race -vet=all ../...

.PHONY: vectors
vectors:
	@echo "Testing vectors ..."
	@go test -v ../tests/vectors_test.go

# Coverage
.PHONY: cover
cover:
	@echo "Generating Go coverage..."
	@report_path="$(GO_COVERAGE_REPORT_PATH)" && \
    	    cover_pkg="$(GO_COVERAGE_PACKAGE)" && \
    	    test_target="$(GO_COVERAGE_TEST_TARGET)" && \
    	    mkdir -p "$$(dirname "$$report_path")" && \
	    go test -v -race -covermode=atomic -coverpkg="$$cover_pkg" -coverprofile="$$report_path" $$test_target && \
	    echo "Go coverage report generated: $$report_path"

# Fuzzing
# Local fuzzing: keep a repo-local cache so short runs accumulate useful inputs
# across invocations, and new crashers land under tests/testdata/fuzz for review
# and commit.
.PHONY: fuzz
fuzz:
	@repo_root=$$(cd .. && pwd); \
	FUZZTIME="$${FUZZTIME:-$(FUZZ_DEFAULT_TIME)}" \
	FUZZ_GOCACHE_DIR="$${FUZZ_GOCACHE_DIR:-$$repo_root/$(FUZZ_LOCAL_GOCACHE_DIR)}" \
	$(MAKE) --no-print-directory run-fuzz

.PHONY: fuzz-ci
# Nightly CI fuzzing: use the same runner as local fuzzing, but keep a dedicated
# cache path so workflow-managed state does not mix with local developer caches.
fuzz-ci:
	@repo_root=$$(cd .. && pwd); \
	FUZZTIME="$${FUZZTIME:-$(FUZZ_DEFAULT_TIME)}" \
	FUZZ_GOCACHE_DIR="$${FUZZ_GOCACHE_DIR:-$$repo_root/$(FUZZ_CI_GOCACHE_DIR)}" \
	$(MAKE) --no-print-directory run-fuzz

.PHONY: run-fuzz
# Shared fuzz runner. The wrapper targets above only choose sensible defaults
# for fuzz duration and cache location.
# Each fuzz target gets its own tests/testdata/fuzz/<target> directory so a
# discovered crasher has a stable place to land. If this run created the
# directory and nothing was written, it is removed again to avoid empty dirs.
run-fuzz:
	@echo "Running fuzz tests ..."
	@fuzzTime=$${FUZZTIME:-$(FUZZ_DEFAULT_TIME)}; \
	repo_root=$$(cd .. && pwd); \
	gocache_dir=$${FUZZ_GOCACHE_DIR:-}; \
	gomodcache_dir=$$(go env GOMODCACHE); \
	: "Require an explicit cache directory so local and CI wrappers stay honest."; \
	if [ -z "$$gocache_dir" ]; then \
		echo "Error: FUZZ_GOCACHE_DIR must be set."; \
		exit 1; \
	fi; \
	: "Discover all fuzz targets once so we can print a summary and estimate runtime."; \
	mkdir -p "$$gocache_dir"; \
	cd "$$repo_root"; \
	fuzz_targets=$$(GOCACHE="$$gocache_dir" GOMODCACHE="$$gomodcache_dir" go test ./tests -list '^Fuzz' | grep '^Fuzz' || true); \
	if [ -z "$$fuzz_targets" ]; then \
		echo ""; \
		echo "No fuzz targets found."; \
		exit 0; \
	fi; \
	num_targets=$$(printf '%s\n' "$$fuzz_targets" | wc -l | tr -d ' '); \
	fuzz_seconds=$$(echo "$$fuzzTime" | sed 's/s$$//; s/m$$/*60/; s/h$$/*3600/' | bc); \
	total_seconds=$$((num_targets * fuzz_seconds)); \
	: "Print the execution plan before the first fuzz target starts running."; \
	echo ""; \
	echo "Fuzz targets to run:"; \
	for t in $$fuzz_targets; do echo "  - $$t"; done; \
	echo ""; \
	echo "Number of targets: $$num_targets"; \
	echo "Time per target: $$fuzzTime"; \
	echo "Using fuzz cache: $$gocache_dir"; \
	echo "Estimated total time: $$total_seconds seconds"; \
	echo ""; \
	failed=0; \
	current=0; \
	remaining_seconds=$$total_seconds; \
	: "Run each fuzz target independently so one failure still leaves logs for later targets."; \
	for func in $$fuzz_targets; do \
		current=$$((current + 1)); \
		echo ""; \
		echo "[$$current/$$num_targets] Fuzzing $$func"; \
		testdata_dir="./tests/testdata/fuzz/$$func"; \
		: "Create the target directory if needed so any new crasher has a predictable path."; \
		if [ -d "$$testdata_dir" ]; then \
			preexisting_dir=1; \
		else \
			preexisting_dir=0; \
			mkdir -p "$$testdata_dir"; \
		fi; \
		if ! GOCACHE="$$gocache_dir" GOMODCACHE="$$gomodcache_dir" go test ./tests -run='^$$' -fuzz="^$${func}$$" -fuzztime="$$fuzzTime"; then \
			failed=1; \
			: "When fuzzing fails, print the newest crasher path and contents into the logs."; \
			latest_crasher=$$(ls -t "$$testdata_dir" | head -n 1); \
			if [ -n "$$latest_crasher" ]; then \
				crasher_path="$$testdata_dir/$$latest_crasher"; \
				echo "Crasher found for $$func."; \
				echo "Crasher file: $$crasher_path"; \
				echo "Crashing input:"; \
				cat "$$crasher_path"; \
			else \
				echo "Fuzzing failed for $$func, but no crasher file was written (run may have been interrupted)."; \
			fi; \
		else \
			echo "No crasher found for $$func."; \
		fi; \
		: "Clean up empty directories that were created only for this run."; \
		if [ $$preexisting_dir -eq 0 ] && [ -d "$$testdata_dir" ] && [ -z "$$(ls -A "$$testdata_dir")" ]; then \
			rmdir "$$testdata_dir"; \
		fi; \
		remaining_seconds=$$((remaining_seconds - fuzz_seconds)); \
		if [ $$remaining_seconds -gt 0 ]; then \
			echo ""; \
			echo "Estimated remaining time: $$remaining_seconds seconds"; \
		fi; \
	done; \
	exit $$failed

# Benchmarks
.PHONY: bench
bench:
	@echo "Running benchmarks ..."
	@bench_regex=$${BENCH:-'.*Suites'}; \
	 bench_time=$${BENCHTIME:-5s}; \
	 go test -run '^$$' -bench "$$bench_regex" -benchmem -benchtime "$$bench_time" ../tests

# Releases
.PHONY: release
release:
	@echo "Creating a new release ..."
	@tag=$${tag:-}; \
		if [ -z "$$tag" ]; then \
			echo "Error: tag variable is not set. Use 'make release tag=vX.Y.Z'"; \
			exit 1; \
		fi; \
		git fetch origin; \
	if ! git tag -s -a "$$tag" -m "chore: cut $$tag"; then \
		echo "Error: Failed to create tag"; \
		exit 1; \
	fi; \
	git push origin "$$tag"
