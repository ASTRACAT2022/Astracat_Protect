# ASTRACAT PROTECT — подробный manual (RU)

## 1. Что это и зачем

`ASTRACAT PROTECT` — это edge-gateway/reverse-proxy перед вашими сервисами.

Он делает:
- TLS/HTTPS (ACME/Let's Encrypt) на входе;
- HTTP->HTTPS redirect;
- L7-защиту (rate limit, challenge, ban);
- маршрутизацию по домену и пути;
- логи и метрики;
- hot-reload конфига без полного рестарта.

Типовая схема:

`Интернет -> ASTRACAT PROTECT (:80/:443) -> backend(s) в Docker сети`

---

## 2. Базовая архитектура и роли

1. `ASTRACAT PROTECT` слушает `80/443`, принимает весь внешний трафик.
2. Выпускает/обновляет сертификаты в `/data/acme`.
3. Применяет защиту (challenge, лимиты, бан).
4. Проксирует в upstream-сервисы по `astra.yaml`.
5. Отдает `/metrics`, `/healthz`, и admin `/reload`.

---

## 3. Требования перед запуском

1. DNS доменов указывает на IP сервера.
2. Порты `80/tcp` и `443/tcp` открыты на сервере.
3. Docker установлен и работает.
4. Указан рабочий email для ACME.
5. Backend контейнеры доступны ASTRACAT по Docker DNS.

---

## 4. Рекомендуемая структура на сервере

```bash
mkdir -p /opt/astracat-protect/configs
mkdir -p /opt/astracat-protect/data
chown -R 10001:10001 /opt/astracat-protect/data
chmod 700 /opt/astracat-protect/data
```

Где:
- `/opt/astracat-protect/configs/astra.yaml` — ваш конфиг;
- `/opt/astracat-protect/data` — ACME cache и сертификаты.

---

## 5. Запуск контейнера (production)

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
  astracat/protect:8 \
  -config /app/configs/astra.yaml -http :80 -https :443 -admin :9090
```

Если upstream в других сетях:

```bash
docker network connect stealthnet-network astracat-protect 2>/dev/null || true
docker network connect remnawave-network astracat-protect 2>/dev/null || true
```

---

## 6. Полный пример `astra.yaml`

Файл: `/opt/astracat-protect/configs/astra.yaml`

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
  whitelist_ips:
    - 144.31.25.165
    - 127.0.0.1
    - ::1
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
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
    - "/"
    - "/index.html"
    - "/api/*"
    - "/api*"
    - "/miniapp/*"
    - "/miniapp-v2/*"
    - "/static/*"
    - "/assets/*"
    - "/favicon.ico"
    - "/manifest.json"
    - "/logo192.png"
    - "/logo512.png"
    - "/cabinet/ws*"
    - "/.well-known/acme-challenge/*"
    - "/healthz"
    - "/metrics"
    - "*.css"
    - "*.js"
    - "*.png"
    - "*.woff2"

servers:
  - hostname: panel.astracat.ru
    handles:
      - upstream: 172.18.0.4:3000

  - hostname: nya.astracat.ru
    handles:
      - upstream: remnawave-subscription-page:3010

  - hostname: sunstar.astracat.ru
    handles:
      - upstream: 0.0.0.0:8080

  - hostname: docklet.astracat.ru
    handles:
      - upstream: 0.0.0.0:1499

  - hostname: cabinet.astracat.ru
    handles:
      - upstream: stealthnet-api:5000
```

---

## 7. Как редактировать конфиг и применять

Просмотр:

```bash
cat /opt/astracat-protect/configs/astra.yaml
```

Редактирование:

```bash
nano /opt/astracat-protect/configs/astra.yaml
```

Применение без полного рестарта:

```bash
curl -s -H "Authorization: Bearer changeme" http://127.0.0.1:9091/reload
```

Если reload не прошел:

```bash
docker restart astracat-protect
```

---

## 8. Что значит `admin listening on :9090`

Это internal admin API ASTRACAT.

Endpoints:
- `GET /healthz`
- `GET /metrics`
- `POST/GET /reload` с `Authorization: Bearer <ADMIN_TOKEN>`

Пример:

```bash
curl -s -H "Authorization: Bearer changeme" http://127.0.0.1:9091/healthz
curl -s -H "Authorization: Bearer changeme" http://127.0.0.1:9091/reload
```

---

## 9. Логи и метрики

Логи:

```bash
docker logs -f astracat-protect
```

JSON лог содержит:
- `timestamp`
- `remote_ip`
- `host`
- `method`
- `uri`
- `status`
- `latency_ms`
- `upstream`
- `route`
- `challenge_applied`
- `rate_limited`
- `blocked`

Метрики:

```bash
curl -s http://127.0.0.1:9091/metrics | head -n 60
```

---

## 10. Проверка работы после деплоя

1. Проверка HTTPS и ответа:

```bash
curl -kI --resolve cabinet.astracat.ru:443:127.0.0.1 https://cabinet.astracat.ru/
```

2. Проверка API через ASTRACAT:

```bash
curl -kI --resolve cabinet.astracat.ru:443:127.0.0.1 https://cabinet.astracat.ru/api/public/system-settings
```

3. Проверка upstream в логах:

```bash
docker logs --since=2m astracat-protect | grep "cabinet.astracat.ru" | tail -n 30
```

Ожидаемо:
- `status:200`;
- корректный `upstream` (например `stealthnet-api:5000`);
- `challenge_applied:false` для exempt путей Mini App/API.

---

## 11. Как работает защита

1. `Rate limiting` по IP (token bucket): `rps`, `burst`.
2. `Connection limit` по IP: `conn_limit`, `ws_conn_limit`.
3. `Risk scoring` с TTL.
4. При превышении порога:
- interstitial (`Checking your browser...`);
- captcha;
- cookie clearance.
5. Если лимит нарушен `ban_after` раз:
- IP бан на `ban_seconds`.

---

## 12. Белый список IP

Параметр:

```yaml
limits:
  whitelist_ips:
    - 144.31.25.165
    - 10.0.0.0/8
```

Для whitelist IP отключаются:
- challenge,
- rate-limit,
- connection-limit,
- auto-ban.

---

## 13. Mini App (Telegram) — обязательные условия

1. Пути mini app должны быть в `challenge.exempt_globs`.
2. Backend должен корректно видеть прокси-заголовки:
- `X-Forwarded-For`
- `X-Forwarded-Proto`
- `X-Forwarded-Host`
3. В Flask желательно включить `ProxyFix`, иначе возможно 429/неверные редиректы.
4. В Telegram Bot Settings укажите корректный домен mini app URL.

---

## 14. Частые проблемы и решения

### 14.1 `502 Bad Gateway`

Причины:
- upstream недоступен;
- не та Docker-сеть;
- неправильный host:port в `astra.yaml`.

Проверка из контейнера ASTRACAT:

```bash
docker exec -it astracat-protect sh -lc 'wget -S -O - http://stealthnet-api:5000/ 2>&1 | head -n 20'
```

### 14.2 `Too Many Requests (500/hour, 2000/day...)`

Это обычно backend limiter, а не ASTRACAT.

Нужно:
- включить `ProxyFix` в Flask;
- поднять лимиты backend;
- проверить, что IP не схлопывается в один прокси IP.

### 14.3 Mini App редиректит на `http://stealthnet-api:5000/...`

Причина:
- backend получал внутренний `Host`.

Решение:
- использовать версию ASTRACAT с фиксом сохранения `Host` (commit `67933c5` и новее).

### 14.4 ACME permission denied

```bash
chown -R 10001:10001 /opt/astracat-protect/data
chmod 700 /opt/astracat-protect/data
docker restart astracat-protect
```

---

## 15. Обновление образа ASTRACAT

Сборка и push:

```bash
cd /path/to/Astracat_Protect
git pull origin main
docker build --no-cache -t astracat/protect:8 -t astracat/protect:latest .
docker login
docker push astracat/protect:8
docker push astracat/protect:latest
```

Обновление на сервере:

```bash
docker rm -f astracat-protect
docker run -d --name astracat-protect \
  --restart unless-stopped \
  --network remnawave-network \
  -p 80:80 -p 443:443 -p 127.0.0.1:9091:9090 \
  -v /opt/astracat-protect/configs:/app/configs:ro \
  -v /opt/astracat-protect/data:/data \
  -e ADMIN_TOKEN=changeme \
  -e ACME_EMAIL=seo@astracat.ru \
  astracat/protect:8 \
  -config /app/configs/astra.yaml -http :80 -https :443 -admin :9090
```

---

## 16. Резервные копии и rollback

Перед изменениями:

```bash
cp /opt/astracat-protect/configs/astra.yaml /opt/astracat-protect/configs/astra.yaml.bak.$(date +%F-%H%M%S)
```

Rollback конфига:

```bash
cp /opt/astracat-protect/configs/astra.yaml.bak.YYYY-MM-DD-HHMMSS /opt/astracat-protect/configs/astra.yaml
curl -s -H "Authorization: Bearer changeme" http://127.0.0.1:9091/reload || docker restart astracat-protect
```

Rollback образа:

```bash
docker rm -f astracat-protect
docker run ... astracat/protect:<старый_тег> ...
```

---

## 17. Минимальный production checklist

1. Сильный `ADMIN_TOKEN` вместо `changeme`.
2. `9091` слушать только на `127.0.0.1`.
3. Регулярные backup `astra.yaml` и `/opt/astracat-protect/data`.
4. Мониторинг `/metrics` + alert на скачок `5xx`.
5. Проверка сроков сертификатов.
6. Проверка `docker logs` на системные ошибки.

---

## 18. Команды-шпаргалка

Просмотр конфига:

```bash
cat /opt/astracat-protect/configs/astra.yaml
```

Reload:

```bash
curl -s -H "Authorization: Bearer changeme" http://127.0.0.1:9091/reload
```

Restart:

```bash
docker restart astracat-protect
```

Логи:

```bash
docker logs -f astracat-protect
```

Проверка cabinet:

```bash
curl -kI --resolve cabinet.astracat.ru:443:127.0.0.1 https://cabinet.astracat.ru/
```

