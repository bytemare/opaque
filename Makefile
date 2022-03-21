PACKAGES    := $(shell go list ./...)
COMMIT      := $(shell git rev-parse HEAD)

.PHONY: update
update:
	@echo "Updating dependencies and linters ..."
	@go get -u
	@go mod tidy
	@go get -u mvdan.cc/gofumpt@latest github.com/daixiang0/gci github.com/segmentio/golines@latest
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

.PHONY: fmt
fmt:
	@echo "Formatting ..."
	@go mod tidy
	@golines -m 120 -t 4 -w .
	@gofumpt -w -extra .
	@gci write --Section Standard --Section Default --Section "Prefix(github.com/bytemare/opaque)" .

.PHONY: lint

lint:
	@echo "Linting ..."
	@if golangci-lint run --config=./.github/.golangci.yml ./...; then echo "Linting OK"; else return 1; fi;

.PHONY: license
license:
	@echo "Checking License headers ..."
	@if addlicense -check -v -f .github/licence-header.tmpl *; then echo "License headers OK"; else return 1; fi;

.PHONY: test
test:
	@echo "Running all tests ..."
	@go test -v ./tests

.PHONY: vectors
vectors:
	@echo "Testing vectors ..."
	@go test -v tests/vectors_test.go

.PHONY: cover
cover:
	@echo "Testing with coverage ..."
	@go test -v -race -covermode=atomic -coverpkg=./... -coverprofile=./coverage.out ./tests
