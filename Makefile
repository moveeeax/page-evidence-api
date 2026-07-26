BINARY  := pev
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test vet fmt check demo fixtures clean

all: check build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/pev

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

check: vet test
	@test -z "$$(gofmt -l . )" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

# demo runs the verifier over the committed example bundles: one intact, one
# with a single word changed in the DOM.
demo: build
	./bin/$(BINARY) verify testdata/bundles/valid -tsa-roots testdata/tsa-test-root.pem
	@echo
	-./bin/$(BINARY) verify testdata/bundles/tampered -tsa-roots testdata/tsa-test-root.pem

# fixtures regenerates testdata/. Only needed when the bundle format changes.
fixtures:
	go run ./cmd/genfixture

clean:
	rm -rf bin
