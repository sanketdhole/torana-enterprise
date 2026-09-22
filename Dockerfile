# Build stage: Compile static Go binary
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Pre-fetch dependencies
COPY go.mod ./
# RUN go mod download (uncomment when external dependencies are declared)

# Copy source code
COPY . .

# Build statically linked binary with stripped symbols and zero CGO
ARG VERSION=0.1.0
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w -extldflags '-static' -X main.Version=${VERSION}" \
    -o /bin/gateway-data ./cmd/gateway-data

# Final stage: Distroless static non-root (UID 65532)
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

# Copy statically linked binary
COPY --from=builder /bin/gateway-data /app/gateway-data

# HTTP ingress and gRPC ingress ports
EXPOSE 8080 9090

# Default bootstrap environment variables
ENV LISTEN_HTTP=":8080" \
    LISTEN_GRPC=":9090" \
    GATEWAY_NAMESPACE="default" \
    ENV="production"

# Non-root user is already configured in distroless:nonroot (USER 65532:65532)
ENTRYPOINT ["/app/gateway-data"]
