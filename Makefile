APP       := nullfield
IMAGE     := ghcr.io/babywyrm/$(APP)
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOFLAGS   := -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: build build-all build-controller build-injector build-extauthz build-extauthz-linux run test lint docker docker-extauthz push clean

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -o bin/$(APP) ./cmd/$(APP)

build-controller:
	CGO_ENABLED=0 go build $(GOFLAGS) -o bin/$(APP)-controller ./cmd/$(APP)-controller

build-injector:
	CGO_ENABLED=0 go build $(GOFLAGS) -o bin/$(APP)-injector ./cmd/$(APP)-injector

build-extauthz:
	CGO_ENABLED=0 go build $(GOFLAGS) -o bin/$(APP)-extauthz ./cmd/$(APP)-extauthz

# The lab clusters are x86_64 while development happens on arm64. Building
# without this produces an image that pulls cleanly and then crash-loops with
# "exec format error", which reads like a broken binary rather than a wrong one.
build-extauthz-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o bin/$(APP)-extauthz-linux-amd64 ./cmd/$(APP)-extauthz

build-all: build build-controller build-injector build-extauthz

run: build
	./bin/$(APP)

test:
	go test -race -cover ./...

lint:
	golangci-lint run ./...

docker:
	docker build -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

docker-extauthz:
	docker build --platform linux/amd64 -f Dockerfile.extauthz \
		-t $(IMAGE)-extauthz:$(VERSION) -t $(IMAGE)-extauthz:latest .

push: docker
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):latest

clean:
	rm -rf bin/
