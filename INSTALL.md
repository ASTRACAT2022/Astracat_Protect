# Установка ASTRACAT PROTECT

Ниже — простой установщик и базовый мануал запуска.

## Быстрая установка

```bash
./install
```

Что делает скрипт:
- проверяет наличие Go (1.22+)
- ставит зависимости
- собирает бинарник в `./bin/astracat-protect`

После установки запуск:
```bash
ADMIN_TOKEN=changeme ./bin/astracat-protect -config ./configs/astra.yaml -http :80 -https :443 -admin :9090
```

## Конфиг

Полный конфиг находится в:
- `./configs/astra.yaml`

Где:
- `log` — логирование
- `acme` — настройки TLS/ACME
- `limits` — лимиты и risk scoring
- `challenge` — антибот‑проверка
- `servers` — маршрутизация (хосты, matchers, strip_prefix, upstream)

Обязательное:
- `acme.email` должен быть реальным, иначе ACME не стартует.

## Порты

- HTTP: `:80` (ACME + редирект на HTTPS)
- HTTPS: `:443` (рабочий трафик)
- Admin: `:9090` (`/healthz`, `/metrics`, `/reload`)

## Админ‑перезагрузка

```bash
curl -H "Authorization: Bearer changeme" http://localhost:9090/reload
```

## Env‑переменные (override)

ACME:
- `ACME_EMAIL`
- `ACME_CA`
- `ACME_STAGING`
- `ACME_KEY_TYPE`
- `ACME_RENEW_WINDOW`
- `ACME_STORAGE`

Limits:
- `RATE_LIMIT_RPS`
- `RATE_LIMIT_BURST`
- `CONN_LIMIT`
- `WS_CONN_LIMIT`
- `MAX_BODY_BYTES`
- `MAX_HEADER_BYTES`
- `MAX_URL_LENGTH`
- `RISK_THRESHOLD`
- `RISK_TTL`
- `RISK_STATUS_WINDOW`

Challenge:
- `CHALLENGE_TTL`
- `CHALLENGE_BIND_IP`
- `CHALLENGE_BIND_UA`

## Docker 

```bash
docker build -t astracat/astracat-protect:1 .
docker run -p 80:80 -p 443:443 -p 9090:9090 \
  -v /path/to/data:/data \
  -e ADMIN_TOKEN=changeme \
  -e ACME_EMAIL=you@example.com \
  astracat/protect:2 \
  -config /app/configs/astra.yaml
```
