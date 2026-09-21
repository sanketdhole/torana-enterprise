# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Download dependencies
COPY go.mod ./
# RUN go mod download (uncomment when external modules are added)

# Copy source code
COPY . .

# Build statically linked binary with zero CGO
ARG VERSION=0.1.0
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w -X main.Version=${VERSION}" -o /app/bin/gateway-data ./cmd/gateway

# Final stage: minimal secure image
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata \
    && addgroup -S gateway && adduser -S gateway -G gateway

USER gateway
WORKDIR /app

COPY --from=builder /app/bin/gateway-data /app/gateway-data

EXPOSE 8080

ENV PORT=8080 \
    HOST=0.0.0.0 \
    ENV=production \
    GATEWAY_NAMESPACE=default

ENTRYPOINT ["/app/gateway-data"]
