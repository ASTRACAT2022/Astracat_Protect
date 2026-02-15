# ASTRACAT PROTECT

Reverse-proxy / edge-gateway with Auto-HTTPS, L7 protections, and metrics.

## Быстрый старт

```bash
./install
```

## Документация

- `INSTALL.md` — локальная сборка и запуск
- `DOCKER_DEPLOY.md` — production deploy в Docker, конфиги и диагностика

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
- `WHITELIST_IPS` (comma-separated IP/CIDR, e.g. `95.27.149.224,172.18.0.0/16`)
- `MAX_BODY_BYTES`
- `MAX_URI_BYTES`
- `MAX_QUERY_BYTES`
- `MAX_PARAMS`
- `MAX_HEADER_BYTES`
- `MAX_URL_LENGTH`
- `RISK_THRESHOLD`
- `RISK_TTL` (seconds)
- `RISK_STATUS_WINDOW` (seconds)
- `BAN_AFTER` (violations before ban, default `3`)
- `BAN_SECONDS` (ban duration, default `3600`)
- `RATE_429_BAN_AFTER`
- `RATE_429_WINDOW_SECONDS`
- `RATE_429_BAN_SECONDS`
- `WAF_BAN_SECONDS`
- `limits.rate_policies` in YAML for route-specific token buckets (e.g. `/api/*`, `/login`)

Challenge:
- `CHALLENGE_TTL` (seconds)
- `CHALLENGE_BIND_IP` (true/1)
- `CHALLENGE_BIND_UA` (true/1)

WAF:
- `WAF_ENABLED` (true/1)
- `WAF_MODE` (`block` or `log`)
- `WAF_SCORE_THRESHOLD`
- `WAF_INBOUND_THRESHOLD`
- `WAF_PARANOIA_LEVEL` (1..4)
- `WAF_MAX_INSPECT_BYTES`
- `WAF_MAX_VALUES_PER_COLLECTION`
- `WAF_MAX_TOTAL_VALUES`
- `WAF_MAX_JSON_VALUES`
- `WAF_MAX_BODY_VALUES`
- `WAF_ALLOWED_METHODS` (comma-separated, e.g. `GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD`)
- `WAF_BLOCKED_CONTENT_TYPES` (comma-separated regex fragments)
- `waf.exempt_globs`, `waf.exempt_hosts`, `waf.exempt_rule_ids`, `waf.exempt_rule_ids_by_glob` in YAML for precise production exceptions

## Notes

- HTTP-01 challenges are served directly by the ACME handler and bypass challenge/rate-limit.
- Use a persistent volume mounted to `/data` to store ACME state.
- WAF uses anomaly-scoring with paranoia levels, rule actions (`score|log|allow|block`) and built-in signatures.
