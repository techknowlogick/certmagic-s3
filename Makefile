.PHONY: test
test:
	go test -v ./...

.PHONY: test-race
test-race:
	go test -race -v ./...

.PHONY: lint
lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run

.PHONY: fmt
fmt:
	go run mvdan.cc/gofumpt@latest -w .
