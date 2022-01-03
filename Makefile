PACKAGES    := $(shell go list ./...)
COMMIT      := $(shell git rev-parse HEAD)

.PHONY: lint
lint:
	@echo "Linting ..."
	@gofumports -w -local github.com/bytemare/opaque .
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
