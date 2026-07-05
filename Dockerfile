# Build stage
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

# Copy go mod files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /auth-server ./cmd/server/main.go

# Runtime stage
FROM alpine:3.21

RUN apk add --no-cache ca-certificates postgresql-client redis curl

WORKDIR /app

# Copy binary from builder
COPY --from=builder /auth-server /app/auth-server

# Copy migrations
COPY --from=builder /app/migrations /app/migrations

# Copy entrypoint script
COPY scripts/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["/app/auth-server"]
