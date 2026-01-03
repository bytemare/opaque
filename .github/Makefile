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
	@go fmt ../...
	@golines -m 120 -t 4 -w ../
	@gofumpt -w -extra ../
	@gci write -s standard -s default -s "Prefix($(shell go list -m))" -s blank -s dot -s alias --skip-generated ../
	@fieldalignment -fix ../...

.PHONY: license
license:
	@echo "Checking License headers ..."
	@if addlicense -check -v -skip yaml -f licence-header.tmpl ../*; then echo "License headers OK"; else return 1; fi;

.PHONY: lint
lint: fmt license
	@echo "Linting ..."
	@if golangci-lint config verify -v --config=.golangci.yml; then echo "Config OK"; else return 1; fi;
	@if golangci-lint run --config=.golangci.yml ../...; then echo "Linting OK"; else return 1; fi;

.PHONY: vulncheck
vulncheck:
	@echo "Running govulncheck ..."
	@govulncheck -show verbose ../...

.PHONY: test
test:
	@echo "Running all tests ..."
	@go test -v -vet=all ../...

.PHONY: vectors
vectors:
	@echo "Testing vectors ..."
	@go test -v ../tests/vectors_test.go

.PHONY: cover
cover:
	@echo "Testing with coverage ..."
	@go test -v -race -covermode=atomic -coverpkg=../... -coverprofile=./coverage.out ../tests

.PHONY: fuzz
fuzz:
	@echo "Running fuzz tests ..."
	@fuzzTime=$${FUZZTIME:-5m}; \
	 repo_root=$$(cd .. && pwd); \
	 gocache_dir="$$repo_root/.gocache"; \
	 gomodcache_dir=$$(go env GOMODCACHE); \
	 mkdir -p "$$gocache_dir"; \
	 failed=0; \
	 cd "$$repo_root" && GOCACHE="$$gocache_dir" GOMODCACHE="$$gomodcache_dir" go test ./tests -list '^Fuzz' | grep '^Fuzz' | while read -r func; do \
	 	 echo "Fuzzing $$func"; \
	 	 if ! GOCACHE="$$gocache_dir" GOMODCACHE="$$gomodcache_dir" go test ./tests -run='^$$' -fuzz="^$${func}$$" -fuzztime="$$fuzzTime"; then \
	 	 	 failed=1; \
	 	 	 echo "Crasher found for $$func. Crashing input:"; \
	 	 	 testdata_dir="./tests/testdata/fuzz/$$func"; \
	 	 	 if [ -d "$$testdata_dir" ]; then \
	 	 	 	 latest_crasher=$$(ls -t "$$testdata_dir" | head -n 1); \
	 	 	 	 if [ -n "$$latest_crasher" ]; then \
	 	 	 	 	 cat "$$testdata_dir/$$latest_crasher"; \
	 	 	 	 else \
	 	 	 	 	 echo "Could not find crasher file in $$testdata_dir"; \
	 	 	 	 fi; \
	 	 	 else \
	 	 	 	 echo "Could not find testdata directory: $$testdata_dir"; \
	 	 	 fi; \
	 	 fi; \
	 done; \
	 exit $$failed

.PHONY: bench
bench:
	@echo "Running benchmarks ..."
	@bench_regex=$${BENCH:-'.*Suites'}; \
	 bench_time=$${BENCHTIME:-5s}; \
	 go test -run '^$$' -bench "$$bench_regex" -benchmem -benchtime "$$bench_time" ../tests
