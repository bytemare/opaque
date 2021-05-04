PACKAGES    := $(shell go list ./...)
COMMIT      := $(shell git rev-parse HEAD)

.PHONY: lint
lint:
	@echo "Linting and security ..."
	@go vet ./...
	@golangci-lint run --fix --config=./.github/.golangci.yml ./...

.PHONY: test
test:
	@echo "Testing ..."
	@go test -v tests/opaque_test.go

.PHONY: vectors
vectors:
	@echo "Testing ..."
	@go test -v tests/vectors_test.go

.PHONY: cover
cover:
	@echo "Coverage ..."
	@go test -v -race -covermode=atomic \
		    -coverpkg=./... tests/opaque_test.go
