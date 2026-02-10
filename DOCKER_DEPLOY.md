# Docker Deploy Manual (ASTRACAT PROTECT)

## 1) Что нужно перед запуском

- Домены должны смотреть на IP сервера (A/AAAA записи).
- Открыты порты `80/tcp` и `443/tcp`.
- На сервере установлен Docker.
- Для ACME обязателен email (`ACME_EMAIL`).

## 2) Структура на сервере

```bash
mkdir -p /opt/astracat-protect/configs
mkdir -p /opt/astracat-protect/data
chown -R 10001:10001 /opt/astracat-protect/data
chmod 700 /opt/astracat-protect/data
```

`/opt/astracat-protect/data` хранит сертификаты и ACME-аккаунт.

## 3) Пример полного `astra.yaml`

Создай файл `/opt/astracat-protect/configs/astra.yaml`:

```yaml
log:
  output: stdout
  format: json

acme:
  email: seo@astracat.ru
  ca: ""
  staging: false
  key_type: ""
  renew_window: ""
  storage_path: /data/acme

limits:
  rps: 50
  burst: 100
  conn_limit: 200
  ws_conn_limit: 50
  max_body_bytes: 10485760
  max_header_bytes: 1048576
  max_url_length: 4096
  risk_threshold: 5
  risk_ttl_seconds: 600
  risk_status_window: 60
  ban_after: 3
  ban_seconds: 3600

challenge:
  enabled: true
  cookie_ttl_seconds: 1800
  bind_ip: true
  bind_ua: false
  exempt_globs:
    - /api/*
    - /cabinet/ws*
    - /.well-known/acme-challenge/*
    - /healthz
    - /metrics
    - '*.css'
    - '*.js'
    - '*.png'
    - '*.woff2'

servers:
  - hostname: panel.astracat.ru
    handles:
      - upstream: 172.18.0.4:3000

  - hostname: nya.astracat.ru
    handles:
      - upstream: remnawave-subscription-page:3010

  - hostname: sunstar.astracat.ru
    handles:
      - upstream: 144.31.25.165:8080

  - hostname: docklet.astracat.ru
    handles:
      - upstream: 144.31.25.165:1499

  - hostname: cabinet.astracat.ru
    handles:
      - matcher_name: api
        matcher:
          path_glob: /api/*
        strip_prefix: /api
        upstream: remnawave_bot:8080

      - matcher_name: ws
        matcher:
          path_glob: /cabinet/ws*
        upstream: remnawave_bot:8080

      - upstream: cabinet_frontend:80
```

## 4) Запуск контейнера

```bash
docker rm -f astracat-protect 2>/dev/null || true
docker run -d --name astracat-protect \
  --restart unless-stopped \
  --network remnawave-network \
  -p 80:80 -p 443:443 -p 127.0.0.1:9091:9090 \
  -v /opt/astracat-protect/configs:/app/configs:ro \
  -v /opt/astracat-protect/data:/data \
  -e ADMIN_TOKEN=changeme \
  -e ACME_EMAIL=seo@astracat.ru \
  astracat/protect:3 \
  -config /app/configs/astra.yaml -http :80 -https :443 -admin :9090
```

Если upstream-контейнеры в других сетях, подключи прокси к ним:

```bash
docker network connect remnawave-bedolaga-telegram-bot_bot_network astracat-protect 2>/dev/null || true
docker network connect bedolaga-cabinet_default astracat-protect 2>/dev/null || true
```

## 5) Что такое `admin listening on :9090`

Это внутренний Admin API процесса.

- `GET /healthz`
- `GET /metrics`
- `POST/GET /reload` (требует `Authorization: Bearer <ADMIN_TOKEN>`)

Пример reload:

```bash
curl -s -H "Authorization: Bearer changeme" http://127.0.0.1:9091/reload
```

## 6) Как писать конфиги (правила)

- `servers[].hostname` — домен (SNI + Host routing).
- `handles` применяются сверху вниз (первый подходящий).
- Для API c префиксом используй:
  - `matcher.path_glob: /api/*`
  - `strip_prefix: /api`
- Последний `handle` обычно без matcher (default/fallback).

## 7) Проверка после деплоя

```bash
docker logs --since=2m astracat-protect | tail -n 60
curl -kI --resolve cabinet.astracat.ru:443:127.0.0.1 https://cabinet.astracat.ru/
curl -k --resolve cabinet.astracat.ru:443:127.0.0.1 https://cabinet.astracat.ru/api/system/stats
```

## 8) Типовые проблемы

### `502 Bad Gateway`

- upstream недоступен из сети контейнера;
- контейнеры не в одной Docker-сети;
- неверное имя/порт upstream.

Проверка:

```bash
docker exec -it astracat-protect sh -lc 'wget -S -O - http://cabinet_frontend:80/login 2>&1 | head -n 12'
docker exec -it astracat-protect sh -lc 'wget -S -O - http://remnawave_bot:8080/health 2>&1 | head -n 12'
```

### API отдает HTML вместо JSON

- запрос пошел в frontend fallback, а не в API handle;
- проверь порядок handles и `strip_prefix`.

### `permission denied` на `/data/acme`

```bash
chown -R 10001:10001 /opt/astracat-protect/data
chmod 700 /opt/astracat-protect/data
docker restart astracat-protect
```

## 9) Сборка и публикация Docker Hub (`v3`)

```bash
docker build --no-cache -t astracat/protect:3 .
docker login
docker push astracat/protect:3
```

