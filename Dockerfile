# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS builder

WORKDIR /build
COPY go.mod main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o drop .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.20

# ca-certificates for outbound TLS if ever needed; tzdata for correct log times
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S drop && adduser -S -G drop drop

WORKDIR /app
COPY --from=builder /build/drop .

RUN mkdir -p /data/files && chown -R drop:drop /data

USER drop

EXPOSE 8080

# Liveness check against /healthz. Expired files are purged hourly in-process;
# run `/app/drop purge` to purge on demand.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/drop", "health"]

CMD ["/app/drop"]
