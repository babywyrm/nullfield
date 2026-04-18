APP       := nullfield
IMAGE     := ghcr.io/babywyrm/$(APP)
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOFLAGS   := -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: build run test lint docker push clean

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -o bin/$(APP) ./cmd/$(APP)

run: build
	./bin/$(APP)

test:
	go test -race -cover ./...

lint:
	golangci-lint run ./...

docker:
	docker build -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

push: docker
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):latest

clean:
	rm -rf bin/
