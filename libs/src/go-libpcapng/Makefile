GOFLAGS ?= $(GOFLAGS:)

default: build

clean:
	rm -f httpdump

build:
	@go build $(GOFLAGS)

fmt:
	gofmt -w $(wildcard *.go)
