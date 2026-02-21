BINARY=pgw-node
VERSION?=dev
LDFLAGS=-ldflags "-X main.version=$(VERSION)"
GOOS?=linux
GOARCH?=amd64

.PHONY: build clean test

build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(LDFLAGS) -o bin/$(BINARY)-$(GOOS)-$(GOARCH) ./cmd/pgw-node/

build-all:
	GOOS=linux GOARCH=amd64  go build $(LDFLAGS) -o bin/$(BINARY)-linux-amd64  ./cmd/pgw-node/
	GOOS=linux GOARCH=arm64  go build $(LDFLAGS) -o bin/$(BINARY)-linux-arm64  ./cmd/pgw-node/

test:
	go test ./...

clean:
	rm -rf bin/
