# go-FuSa developer Makefile

BINARY   := gofusa
GO_FLAGS := -race -count=1

.PHONY: all build test vet lint check trace verify release qualify evidence clean

all: build

build:
	go build -o $(BINARY) ./cmd/gofusa

test:
	go test $(GO_FLAGS) ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

check: build
	./$(BINARY) check

trace: build
	./$(BINARY) trace

verify: build
	./$(BINARY) verify

release: build
	./$(BINARY) release

qualify: build
	./$(BINARY) qualify

# Collect all evidence in one pass
evidence: verify release qualify

clean:
	rm -f $(BINARY) sbom.json provenance.json .fusa-evidence.json qualify-report.json
