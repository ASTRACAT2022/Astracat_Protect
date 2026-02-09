# ASTRACAT PROTECT

Reverse-proxy / edge-gateway with Auto-HTTPS, L7 protections, and metrics.

## Быстрый старт

```bash
./install
```

## Запуск (dev)

```bash
ADMIN_TOKEN=changeme \
./bin/astracat-protect \
  -config configs/astra.yaml \
  -http :80 \
  -https :443 \
  -admin :9090
```

## Endpoints

- Public: `/healthz`, `/metrics`
- Admin: `/healthz`, `/metrics`, `/reload` (Bearer token)

## Env overrides

ACME:
- `ACME_EMAIL`
- `ACME_CA`
- `ACME_STAGING` (true/1)
- `ACME_KEY_TYPE`
- `ACME_RENEW_WINDOW`
- `ACME_STORAGE` (default `/data/acme`)

Admin:
- `ADMIN_TOKEN` (required for /reload)

Limits:
- `RATE_LIMIT_RPS`
- `RATE_LIMIT_BURST`
- `CONN_LIMIT`
- `WS_CONN_LIMIT`
- `MAX_BODY_BYTES`
- `MAX_HEADER_BYTES`
- `MAX_URL_LENGTH`
- `RISK_THRESHOLD`
- `RISK_TTL` (seconds)
- `RISK_STATUS_WINDOW` (seconds)
- `BAN_AFTER` (violations before ban, default `3`)
- `BAN_SECONDS` (ban duration, default `3600`)

Challenge:
- `CHALLENGE_TTL` (seconds)
- `CHALLENGE_BIND_IP` (true/1)
- `CHALLENGE_BIND_UA` (true/1)

## Notes

- HTTP-01 challenges are served directly by the ACME handler and bypass challenge/rate-limit.
- Use a persistent volume mounted to `/data` to store ACME state.
