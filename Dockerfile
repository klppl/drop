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

# Healthcheck doubles as a periodic purge of expired files (every 12 h).
HEALTHCHECK --interval=12h --timeout=60s --start-period=10s --retries=1 \
    CMD ["/app/drop", "purge"]

CMD ["/app/drop"]
