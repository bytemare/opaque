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
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment@latest
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

.PHONY: fmt
fmt:
	@echo "Formatting ..."
	@go mod tidy
	@go fmt ../...
	@golines -m 120 -t 4 -w ../
	@gofumpt -w -extra ../
	@gci write -s Standard -s Default -s "Prefix($(shell go list -m))" ../
	@fieldalignment -fix ../...

.PHONY: license
license:
	@echo "Checking License headers ..."
	@if addlicense -check -v -skip yaml -f licence-header.tmpl ../*; then echo "License headers OK"; else return 1; fi;

.PHONY: lint
lint: fmt license
	@echo "Linting ..."
	@if golangci-lint run --config=.golangci.yml ../...; then echo "Linting OK"; else return 1; fi;

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
	@fuzzTime=$${FUZZTIME:-2}; \
    failed=0; \
    find .. -name '*_test.go' -exec grep -l '^func Fuzz' {} \; | while read -r file; do \
    	grep '^func Fuzz' "$$file" | sed -E 's/^func ([^(]+).*/\1/' | while read -r func; do \
    		echo "Fuzzing $$func in $$file"; \
    		if ! go test "$$(dirname "$$file")" -run="$$func" -fuzz="$$func" -fuzztime="$${fuzzTime}s"; then \
    			failed=1; \
    			echo "Crasher found for $$func. Crashing input:"; \
    			testdata_dir="$$(dirname "$$file")/testdata/fuzz/$$func"; \
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
    done; \
    exit $$failed