# Astracat Protect

High-performance reverse proxy + AI-driven WAF with Auto-HTTPS, HTTP/3, adaptive defense, and zero-config bootstrap.

## Что это

`Astracat Protect` ставится перед вашими сайтами/API и берет на себя:
- TLS (ACME + custom certs + on-demand)
- L7 защиту (WAF, challenge, rate-limit, adaptive bans)
- routing/balancing до upstream
- observability (`/healthz`, `/metrics`, structured logs)
- WebSocket reverse-proxy (ws:// и wss://)

## Текущий статус

- `HTTP/1.1 + HTTP/2 + HTTP/3 (QUIC)`: реализовано
- `WebSocket reverse-proxy (ws:// и wss://)`: реализовано — см. раздел "WebSocket"
- `AI-WAF (builtin + ONNX/TFLite hooks)`: реализовано
- `DNS-01 automation через hooks`: реализовано
- `Zero-config bootstrap через env`: реализовано
- `Multi-upstream balancing (round_robin/least_conn)`: реализовано
- `Threat-intel ingestion (IP/ASN/JA3 feeds)`: реализовано
- `Bot-management profiles (good/bad bot policy)`: реализовано
- `Strict virtual patching presets (WordPress/Laravel/Next.js)`: реализовано

## Быстрый старт

### Локально

```bash
./install

ADMIN_TOKEN=changeme \
./bin/astracat-protect \
  -config configs/astra.yaml \
  -http :80 \
  -https :443 \
  -admin :9090
```

### Docker (базовый)

```bash
docker run -d --name astracat-protect \
  -p 80:80 -p 443:443 -p 127.0.0.1:9091:9090 \
  -v /opt/astracat-protect/configs:/app/configs:ro \
  -v /opt/astracat-protect/data:/data \
  -e ADMIN_TOKEN=changeme \
  -e ACME_EMAIL=ops@example.com \
  astracat/protect:latest \
  -config /app/configs/astra.yaml -http :80 -https :443 -admin :9090
```

## Endpoints

- Public: `/healthz`, `/metrics`
- Admin: `/healthz`, `/metrics`, `/reload` (Bearer token required)

## Конфиг

Поддерживаются:
- `.yaml` / `.yml`
- `.json`
- caddyfile-like format

Основные примеры:
- `configs/astra.yaml`
- `configs/astra-dns.yaml`

## Основные env-переменные

### ACME / TLS
- `ACME_EMAIL`
- `ACME_CA`
- `ACME_STAGING`
- `ACME_KEY_TYPE`
- `ACME_RENEW_WINDOW`
- `ACME_STORAGE`
- `ON_DEMAND_TLS`
- `SSL_MODE` (`internal|custom`)
- `SSL_CERT_FILE`, `SSL_KEY_FILE`
- `SSL_CERT_DIR`

### DNS-01
- `ACME_DNS01`
- `ACME_DNS_ISSUE_HOOK`
- `ACME_DNS_RENEW_HOOK`
- `ACME_DNS_HOOK_TIMEOUT`
- `ACME_DNS_STORAGE`

### HTTP/3
- `HTTP3_ENABLED`
- `HTTP3_LISTEN`

### WebSocket
- `WS_ENABLED` (default `false`)
- `WS_HANDSHAKE_TIMEOUT` (default `10s`)
- `WS_READ_TIMEOUT`, `WS_WRITE_TIMEOUT` (default `0` = без лимита)
- `WS_MAX_MESSAGE_BYTES` (default `1048576`)
- `WS_PING_INTERVAL` (default `30s`; `0` отключает keep-alive)
- `WS_PONG_TIMEOUT` (default = `WS_PING_INTERVAL`)
- `WS_ALLOWED_ORIGINS` (comma-separated; `*` разрешает любой)
- `WS_SUBPROTOCOLS` (comma-separated)

### AI-WAF
- `AI_ENABLED`
- `AI_LEARNING_MODE`
- `AI_BACKEND` (`builtin|onnx|tflite`)
- `AI_MODEL_PATH`
- `AI_ONNX_COMMAND`, `AI_TFLITE_COMMAND`
- `AI_STATE_PATH`
- `AI_MIN_SAMPLES`
- `AI_CHALLENGE_THRESHOLD`
- `AI_RATE_LIMIT_THRESHOLD`
- `AI_BLOCK_THRESHOLD`
- `AI_MAX_BODY_INSPECT_BYTES`
- `AI_COMMAND_TIMEOUT_MS`
- `AI_UPDATE_PROFILES_ON_BLOCK`

### WAF
- `WAF_ENABLED`
- `WAF_MODE` (`block|log`)
- `WAF_LEVEL` (`low|medium|high|ultra|off`)
- `WAF_PRESETS` (`wordpress,laravel,nextjs`)
- `WAF_SCORE_THRESHOLD`
- `WAF_INBOUND_THRESHOLD`
- `WAF_PARANOIA_LEVEL`
- `WAF_ALLOWED_METHODS`
- `WAF_BLOCKED_CONTENT_TYPES`

### Threat-intel
- `TI_ENABLED`
- `TI_ACTION` (`block|challenge|rate_limit|log`)
- `TI_REFRESH_SECONDS`
- `TI_IP_FEEDS`, `TI_ASN_FEEDS`, `TI_JA3_FEEDS`
- `TI_IPS`, `TI_ASNS`, `TI_JA3`
- `TI_ASN_HEADER` (default `X-ASN`)
- `TI_JA3_HEADER` (default `X-JA3`)

### Bot-management
- `BOT_ENABLED`
- `BOT_BAD_ACTION` (`block|challenge|rate_limit`)
- `BOT_BYPASS_WAF_FOR_GOOD`
- `BOT_GOOD_PATTERNS`, `BOT_BAD_PATTERNS`

### Limits / Challenge / Adaptive
- `RATE_LIMIT_RPS`, `RATE_LIMIT_BURST`
- `CONN_LIMIT`, `WS_CONN_LIMIT`
- `WHITELIST_IPS`
- `CHALLENGE_TTL`, `CHALLENGE_BIND_IP`, `CHALLENGE_BIND_UA`
- `AUTO_SHIELD_ENABLED` и related `AUTO_SHIELD_*`

### Zero-config bootstrap
- `PROTECT_DOMAINS`
- `PROTECT_UPSTREAM` / `UPSTREAM`
- `PROTECT_UPSTREAMS` / `UPSTREAMS`
- `LB_POLICY` (`round_robin|least_conn`)
- `PROXY_MODE` (`standard|passthrough`)
- `DOH_EXCLUDE`

## Точечное отключение защиты

### Отключить auto-shield только для домена

```yaml
servers:
  - hostname: static.example.com
    auto_shield_enabled: false
```

### Отключить WAF только для домена

```yaml
waf:
  exempt_hosts:
    - static.example.com
```

### Полный bypass для конкретного маршрута

```yaml
servers:
  - hostname: static.example.com
    handles:
      - mode: passthrough
        upstream: static:80
```

`passthrough` отключает защитный pipeline на этом route (WAF/challenge/rate/risk/auto-shield).

## WebSocket

Astracat Protect умеет проксировать WebSocket-соединения (RFC 6455, `ws://` и `wss://`). Стандартный `httputil.ReverseProxy` не проксирует HTTP/1.1 `Connection: Upgrade`, поэтому WebSocket-апгрейды раньше молча терялись. Теперь при наличии секции `websocket:` в конфиге прокси сам хайджекит клиента, открывает соединение к upstream, выполняет handshake и прозрачно туннелирует фреймы в обе стороны.

### Что входит

- Hijack клиентского сокета + проброс handshake к upstream (TCP для `ws://`, TLS для `wss://`).
- Парсинг WebSocket-фреймов с лимитом `max_message_bytes` (по умолчанию 1 MiB) на сообщение (включая фрагменты).
- Keep-alive: периодический Ping (`ping_interval`) с настраиваемым `pong_timeout`; клиент, который не отвечает, отключается.
- Валидация Origin: по умолчанию — same-origin (только совпадение `scheme://host`); задайте `allowed_origins: ["*"]` чтобы разрешить любой, или список конкретных origin'ов.
- Subprotocols: задаёте `subprotocols: [...]` — заголовок `Sec-WebSocket-Protocol` будет передан upstream, и его ответ проброшен клиенту.
- Метрики: `astracat_ws_active` (gauge, текущие соединения), `astracat_ws_connections_total`, `astracat_ws_rejected_total`, `astracat_ws_errors_total`.
- Лимит одновременных WS-соединений на IP: используется существующий `limits.ws_conn_limit` (как и раньше).
- WAF и весь защитный pipeline работают только на фазе handshake (проверяется Origin/метод/заголовки). После 101 фреймы передаются как opaque bytes — это норма для WS-туннелей.

### Конфигурация

Глобальная секция (применяется ко всем серверам):

```yaml
websocket:
  enabled: true
  handshake_timeout: 10s
  read_timeout: 0          # 0 = без лимита (рекомендуется для long-lived)
  write_timeout: 0
  max_message_bytes: 1048576
  ping_interval: 30s
  pong_timeout: 30s
  allowed_origins:
    - "https://app.example.com"
    - "*.example.com"
  subprotocols:
    - graphql-ws
```

Per-handle override (например, разрешить WS только для одного маршрута):

```yaml
servers:
  - hostname: api.example.com
    handles:
      - matcher_name: ws
        matcher:
          path_glob: /ws/*
        upstream: backend:8080
        websocket:
          enabled: true
          allowed_origins: ["*"]
          max_message_bytes: 4194304   # 4 MiB для графиков
```

`websocket.enabled: false` в override **отключает** WS на этом маршруте, даже если глобально он включён.

### Защита от злоупотреблений

- `limits.ws_conn_limit` ограничивает количество **одновременных** WebSocket-соединений на IP (счётчик инкрементируется в момент handshake, декрементируется при закрытии).
- `limits.rps` / `limits.burst` тоже действуют на handshake, но **не** на сами фреймы (это и не нужно: лимитировать RPS по фреймам = убить WebSocket).
- WAF exempts (`waf.exempt_globs`) можно использовать, чтобы отключить WAF для `/ws/*` — например, чтобы challenge не мешал установке долгоживущих соединений.

### Метрики и логи

- `astracat_ws_active` — текущее количество открытых WebSocket-соединений.
- `astracat_ws_connections_total` — успешные handshake'ы.
- `astracat_ws_rejected_total` — отказы (Origin, oversized, метод, и т.п.).
- `astracat_ws_errors_total` — ошибки I/O после успешного handshake.
- В access-логе handshake пишется обычная строка (статус 101 если всё ок, иначе код отказа). Каждый фрейм в логе не пишется — это быстро убьёт диск.

### Ограничения

- Прокси **не** разбирает application-данные WebSocket-фреймов (не парсит JSON, не ищет XSS в payload) — фреймы идут как opaque bytes. Это соответствует поведению nginx `proxy_pass` для WS, Caddy, Traefik, HAProxy. Валидация полезной нагрузки должна быть на стороне upstream.
- Поддерживается только WebSocket поверх HTTP/1.1 (RFC 6455). WebSocket-поверх-HTTP/2 (RFC 8441) пока не реализован — браузеры почти всегда используют HTTP/1.1 для WS.
- Per-message-deflate (`Sec-WebSocket-Extensions: permessage-deflate`) не проксируется. Если upstream его использует, клиент и upstream должны договориться без посредника.

## WAF: что уже есть

- anomaly scoring + paranoia levels
- actions: `score`, `log`, `allow`, `block`, `challenge`, `rate_limit`
- protocol hardening:
  - method/content-type enforcement
  - anti-smuggling checks (`TE + CL`, invalid transfer-encoding)
- expanded built-in rules:
  - SQLi / NoSQLi / XSS / RCE / SSTI
  - XXE / SSRF / CRLF injection
  - path traversal / evasions / wrapper abuse
  - deserialization and JNDI markers

## Threat-intel: что уже есть

- ingestion из feed source:
  - `file:///path/to/feed.txt`
  - локальный путь
  - `http(s)://...` feed URL
- поддержка индикаторов:
  - IP/CIDR
  - ASN (+ optional ASN<->CIDR mapping)
  - JA3 hash (или pseudo-JA3 fallback через TLS fingerprint)
- runtime actions:
  - `block`
  - `challenge`
  - `rate_limit`
  - `log`

## Bot-management: что уже есть

- built-in профили good bots (Google/Bing/Yandex/Apple/Twitter/etc.)
- built-in профили bad automation/scanners
- кастомные regex profiles через конфиг
- политика действий для bad bots:
  - `block`
  - `challenge`
  - `rate_limit`
- опция `bypass_waf_for_good`

## Virtual Patching Presets

Доступные strict presets:
- `wordpress`
- `laravel`
- `nextjs`

Включение:

```yaml
waf:
  presets:
    - wordpress
    - laravel
    - nextjs
```

или через env:

```bash
WAF_PRESETS=wordpress,laravel,nextjs
```

## Документация

- `INSTALL.md` — локальная сборка и запуск
- `DOCKER_DEPLOY.md` — production deploy
- `DOCKER_AI_MANUAL_RU.md` — Docker с ONNX/TFLite hooks, HTTP/3, DNS-01
- `NEW_FEATURES_MANUAL_RU.md` — отдельный мануал по новым функциям

## Лицензия

Internal / project-defined.
