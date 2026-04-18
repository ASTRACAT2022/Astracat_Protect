# ASTRACAT PROTECT: Manual По Новым Функциям

Этот документ покрывает только новые возможности, добавленные в последних изменениях:
- `HTTP/3 (QUIC)`;
- `AI-WAF` с `builtin/onnx/tflite` backend;
- `DNS-01` автоматизация сертификатов через hooks;
- `Zero-config` env bootstrap;
- `per-domain`/`per-route` отключение защиты.

## 1) HTTP/3 (QUIC)

### Что это дает
- Поддержка `h3` поверх QUIC для клиентов/браузеров с HTTP/3.
- HTTPS и HTTP/3 работают параллельно.

### Конфиг (YAML)
```yaml
http3:
  enabled: true
  listen: ":443"
```

### Env
- `HTTP3_ENABLED=1`
- `HTTP3_LISTEN=:443`

### Проверка
```bash
curl --http3 -I https://example.com
```

---

## 2) AI-WAF (Adaptive + Hooks)

### Архитектура
- Встроенный адаптивный скоринг (`backend: builtin`) работает без внешних библиотек.
- Профили “нормального” трафика сохраняются в `bbolt` (`AI_STATE_PATH`).
- Для `onnx|tflite` используется hook-команда:
  - вход: JSON через `stdin`;
  - выход: JSON через `stdout` (`score`, `action`, `reason`).

### Конфиг (YAML)
```yaml
ai:
  enabled: true
  learning_mode: true
  backend: builtin # builtin | onnx | tflite
  model_path: /models/waf.onnx
  onnx_command: "python3 /app/ai-hooks/onnx_infer.py"
  tflite_command: "python3 /app/ai-hooks/tflite_infer.py"
  state_path: /data/ai/state.db
  min_samples: 50
  challenge_threshold: 5.0
  rate_limit_threshold: 7.0
  block_threshold: 9.0
  max_body_inspect_bytes: 8192
  command_timeout_ms: 25
  update_profiles_on_block: false
```

### Env
- `AI_ENABLED=1`
- `AI_LEARNING_MODE=1`
- `AI_BACKEND=builtin|onnx|tflite`
- `AI_MODEL_PATH=/models/waf.onnx`
- `AI_ONNX_COMMAND=...`
- `AI_TFLITE_COMMAND=...`
- `AI_STATE_PATH=/data/ai/state.db`
- `AI_MIN_SAMPLES=50`
- `AI_CHALLENGE_THRESHOLD=5`
- `AI_RATE_LIMIT_THRESHOLD=7`
- `AI_BLOCK_THRESHOLD=9`
- `AI_MAX_BODY_INSPECT_BYTES=8192`
- `AI_COMMAND_TIMEOUT_MS=25`

### Формат hook I/O
Вход (`stdin`):
```json
{
  "backend":"onnx",
  "model":"/models/waf.onnx",
  "host":"api.example.com",
  "method":"POST",
  "path":"/v1/login",
  "features":{
    "path_shape":"/v1/login",
    "path_length":9,
    "query_length":0,
    "header_count":12,
    "query_params":0,
    "body_length":423,
    "suspicious_hits":1
  }
}
```

Выход (`stdout`):
```json
{"score":8.4,"action":"block","reason":"onnx-runtime"}
```

Допустимые `action`:
- `allow`
- `challenge`
- `rate_limit`
- `block`

Если `action` не возвращать, решение принимается по threshold.

---

## 3) DNS-01 Автоматизация Сертификатов

### Что это
Вместо HTTP-01 можно включить DNS-01 через внешние hook-команды (например `lego`, `certbot`, внутренний скрипт).

### Конфиг (YAML)
```yaml
acme:
  email: ops@example.com
  storage_path: /data/acme
  on_demand_tls: true
  dns01_enabled: true
  dns_issue_hook: "lego ... {domain} ... --path {storage} ... && cp ... {cert} && cp ... {key}"
  dns_renew_hook: "lego ... renew ... {domain} ... --path {storage} ... && cp ... {cert} && cp ... {key}"
  dns_hook_timeout_seconds: 180
  dns_storage_path: /data/acme/dns01
```

### Env
- `ACME_DNS01=1`
- `ACME_DNS_ISSUE_HOOK='...'`
- `ACME_DNS_RENEW_HOOK='...'`
- `ACME_DNS_HOOK_TIMEOUT=180`
- `ACME_DNS_STORAGE=/data/acme/dns01`

### Подстановки в hook-командах
- `{domain}`: SNI домен
- `{storage}`: рабочая директория DNS-01
- `{cert}`: куда положить итоговый сертификат
- `{key}`: куда положить итоговый ключ

---

## 4) Zero-Config Bootstrap Через Env

### Назначение
Если не хотите сразу писать полный `servers[]`, можно собрать маршруты только через env.

### Минимальный набор
```bash
PROTECT_DOMAINS="example.com,api.example.com"
PROTECT_UPSTREAMS="app-1:8080,app-2:8080"
LB_POLICY="least_conn"
PROXY_MODE="standard"
SSL_MODE="internal"
```

### Полезно
- `DOH_EXCLUDE="doh.example.com"` — облегченный bypass для DoH endpoint.

---

## 5) Как Выключить Защиту Для Домена

Есть несколько уровней “выключения”:

### 5.1 Отключить Auto Shield только для домена
```yaml
servers:
  - hostname: static.example.com
    auto_shield_enabled: false
```

### 5.2 Отключить WAF для домена
```yaml
waf:
  exempt_hosts:
    - static.example.com
```

### 5.3 Убрать challenge для домена/пути
- challenge сейчас исключается по путям (`challenge.exempt_globs`), не по host.
- для домена с особыми endpoint обычно делают route `mode: passthrough`.

### 5.4 Полный bypass защиты на route
```yaml
servers:
  - hostname: static.example.com
    handles:
      - mode: passthrough
        upstream: static:80
```

`passthrough` отключает для этого маршрута защитный pipeline (WAF/challenge/rate/risk/auto-shield).

---

## 6) Балансировка Upstream

Поддерживаемые политики:
- `round_robin`
- `least_conn`

Пример:
```yaml
servers:
  - hostname: api.example.com
    handles:
      - lb_policy: least_conn
        upstreams:
          - api-1:8080
          - api-2:8080
          - api-3:8080
```

---

## 7) Быстрый Docker Рецепт (ONNX)

```bash
docker build -f Dockerfile.ai -t astracat/protect:ai .

docker run -d --name astracat-protect \
  -p 80:80 -p 443:443 -p 127.0.0.1:9091:9090 \
  -v /opt/astracat-protect/configs:/app/configs:ro \
  -v /opt/astracat-protect/data:/data \
  -v /opt/astracat-protect/models:/models:ro \
  -e ADMIN_TOKEN=changeme \
  -e ACME_EMAIL=ops@example.com \
  -e HTTP3_ENABLED=1 \
  -e AI_ENABLED=1 \
  -e AI_BACKEND=onnx \
  -e AI_MODEL_PATH=/models/waf.onnx \
  -e AI_ONNX_COMMAND='python3 /app/ai-hooks/onnx_infer.py' \
  astracat/protect:ai \
  -config /app/configs/astra.yaml -http :80 -https :443 -admin :9090
```

---

## 8) Эксплуатационные Рекомендации

- Храните `/data` на persistent volume.
- Сначала запускайте AI в `learning_mode: true`, потом включайте строгий enforcement.
- Для DNS-01 делайте hooks идемпотентными и с retry.
- Для низкорисковых доменов используйте `passthrough`, но только осознанно.
- Проверяйте `/metrics` и логи после каждого изменения.

---

## 9) Где Смотреть Дополнительно

- Docker + AI: `DOCKER_AI_MANUAL_RU.md`
- Общий deploy: `DOCKER_DEPLOY.md`
- Общий manual: `MANUAL_RU.md`

---

## 10) Threat-Intel Feed Ingestion (IP / ASN / JA3)

### Что умеет модуль
- Подгружает индикаторы из:
  - локального файла (`/path/feed.txt`);
  - `file:///path/feed.txt`;
  - `http(s)://feed.example.com/list.txt`.
- Поддерживает категории:
  - `IP` и `CIDR`;
  - `ASN` (включая связку ASN -> CIDR);
  - `JA3` (или pseudo-JA3 fallback из TLS).
- Автообновляет данные каждые `refresh_seconds`.

### Конфиг (YAML)
```yaml
threat_intel:
  enabled: true
  action: block # block | challenge | rate_limit | log
  refresh_seconds: 300
  ip_feeds:
    - https://ti.example.com/ip.txt
    - file:///etc/astracat/feeds/ip.txt
  asn_feeds:
    - /etc/astracat/feeds/asn.txt
  ja3_feeds:
    - https://ti.example.com/ja3.txt
  ips:
    - 203.0.113.10
    - 198.51.100.0/24
  asns:
    - AS13335
    - AS15169,1.1.1.0/24
  ja3:
    - e7d705a3286e19ea42f587b344ee6865
  asn_header: X-ASN
  ja3_header: X-JA3
```

### Формат feed-файлов
- IP feed:
  - `1.2.3.4`
  - `10.0.0.0/8,known scanner net`
- ASN feed:
  - `AS13335`
  - `AS15169,1.1.1.0/24`
  - `1.0.0.0/24,AS64500`
  - `AS4242,manual watchlist`
- JA3 feed:
  - `e7d705a3286e19ea42f587b344ee6865`
  - `e7d705a3286e19ea42f587b344ee6865,suspicious tls fingerprint`

Комментарии в feed поддерживаются через `#`.

### Env
- `TI_ENABLED=1`
- `TI_ACTION=block|challenge|rate_limit|log`
- `TI_REFRESH_SECONDS=300`
- `TI_IP_FEEDS=...`
- `TI_ASN_FEEDS=...`
- `TI_JA3_FEEDS=...`
- `TI_IPS=...`
- `TI_ASNS=...`
- `TI_JA3=...`
- `TI_ASN_HEADER=X-ASN`
- `TI_JA3_HEADER=X-JA3`

---

## 11) Bot-Management Profiles (Good / Bad Policy)

### Что умеет модуль
- Встроенные профили:
  - good bots (Google/Bing/Yandex/Apple/Twitter и т.д.);
  - bad automation/scanners (sqlmap/nikto/nuclei/curl headless stacks).
- Кастомные профили через regex.
- Политики для bad bots:
  - `block`
  - `challenge`
  - `rate_limit`
- Для good bots можно включить bypass WAF: `bypass_waf_for_good`.

### Конфиг (YAML)
```yaml
bot_management:
  enabled: true
  bad_action: challenge # block | challenge | rate_limit
  bypass_waf_for_good: false
  good_patterns:
    - "my-monitor-bot"
  bad_patterns:
    - "evil-crawler"
  profiles:
    - name: bad-ai-scraper
      kind: bad
      pattern: "gptbot|bytespider|claudebot"
      action: challenge
      priority: 95
    - name: good-partner
      kind: good
      pattern: "partnerbot"
      priority: 40
```

### Env
- `BOT_ENABLED=1`
- `BOT_BAD_ACTION=block|challenge|rate_limit`
- `BOT_BYPASS_WAF_FOR_GOOD=0|1`
- `BOT_GOOD_PATTERNS=...`
- `BOT_BAD_PATTERNS=...`

---

## 12) Strict Virtual Patching Presets (WordPress / Laravel / Next.js)

### Что это
Готовые strict-правила WAF для типовых атак на конкретные стеки без ручного написания regex.

### Поддерживаемые preset
- `wordpress`
  - xmlrpc abuse (`system.multicall`, `pingback.ping`);
  - sensitive endpoints/files (`wp-config.php`, install/setup);
  - execute из `wp-content/uploads/*.php`;
  - login brute-force (`/wp-login.php` -> challenge).
- `laravel`
  - `.env`/laravel.log/phpunit RCE probes;
  - debug routes (`telescope`, `horizon`, `_ignition`, `debugbar`);
  - signed URL abuse patterns.
- `nextjs`
  - image optimizer SSRF (`/_next/image?url=...`);
  - internal route probing (`_next/trace`, hmr probes);
  - risky API/auth probing.

### Включение (YAML)
```yaml
waf:
  enabled: true
  mode: block
  paranoia_level: 2
  presets:
    - wordpress
    - laravel
    - nextjs
```

### Включение (Env)
```bash
WAF_PRESETS=wordpress,laravel,nextjs
```

### Рекомендация по rollout
1. Сначала включить с `waf.mode=log` на короткий период.
2. Проверить false positive в логах.
3. Переключить на `waf.mode=block`.
