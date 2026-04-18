FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /echo-server ./tests/echo-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /echo-server /echo-server
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/echo-server"]
