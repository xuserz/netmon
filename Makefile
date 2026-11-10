GO ?= go
VERSION ?= dev
CGO_ENABLED := 1
export CGO_ENABLED

.PHONY: build static test check install uninstall clean
build:
	mkdir -p bin
	$(GO) build -buildvcs=false -trimpath -ldflags='-s -w -X main.version=$(VERSION)' -o bin/dnsmon ./cmd/dnsmon

# Fully static Linux binary: bundled SQLite, no external libsqlite3 required.
# On Debian/Ubuntu install musl-tools first.
static:
	mkdir -p bin
	CC=musl-gcc $(GO) build -buildvcs=false -tags 'netgo osusergo' -trimpath -ldflags='-s -w -X main.version=$(VERSION) -linkmode external -extldflags "-static"' -o bin/dnsmon ./cmd/dnsmon

test:
	$(GO) test -race ./...
check:
	$(GO) vet ./...
	$(GO) test -race ./...
install: build
	sudo ./scripts/install.sh
uninstall:
	sudo ./scripts/uninstall.sh
clean:
	rm -rf bin
