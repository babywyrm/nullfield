FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /nullfield ./cmd/nullfield

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /nullfield /nullfield
USER nonroot:nonroot
EXPOSE 9090 9091
ENTRYPOINT ["/nullfield"]
