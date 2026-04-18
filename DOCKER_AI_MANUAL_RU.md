# Docker Manual: AI Backend (ONNX/TFLite) + HTTP/3 + DNS-01

Этот мануал для production-сборки `astracat-protect` в Docker с:
- `AI_BACKEND=onnx|tflite` через command hooks;
- нативным `HTTP/3`;
- автоматизацией сертификатов через `DNS-01 hooks`.

## 1) Что уже реализовано в приложении

- `AI_ONNX_COMMAND` / `AI_TFLITE_COMMAND`: stdin JSON -> stdout JSON.
- `HTTP3_ENABLED`, `HTTP3_LISTEN`.
- `ACME_DNS01` + hook-команды выдачи/продления.
- persistent AI state в `bbolt` (`AI_STATE_PATH`).

## 2) Быстрый вариант сборки образа с AI рантаймами

В репозитории добавлен `Dockerfile.ai`.

Сборка:

```bash
docker build -f Dockerfile.ai -t astracat/protect:ai .
```

Что входит в образ:
- бинарь `astracat-protect`;
- Python runtime;
- `onnxruntime` (по умолчанию);
- примеры hook скриптов в `/app/ai-hooks`.

Если нужен TFLite runtime внутри этого же образа:

```bash
docker build -f Dockerfile.ai \
  --build-arg AI_PIP_PACKAGES="onnxruntime tflite-runtime" \
  -t astracat/protect:ai .
```

## 3) Подготовка директорий на хосте

```bash
mkdir -p /opt/astracat-protect/configs
mkdir -p /opt/astracat-protect/data
mkdir -p /opt/astracat-protect/models
chown -R 10001:10001 /opt/astracat-protect/data
chmod 700 /opt/astracat-protect/data
```

Где:
- `/opt/astracat-protect/configs` — конфиги;
- `/opt/astracat-protect/data` — ACME/AI state;
- `/opt/astracat-protect/models` — ONNX/TFLite модели.

## 4) Запуск с ONNX backend

```bash
docker rm -f astracat-protect 2>/dev/null || true
docker run -d --name astracat-protect \
  --restart unless-stopped \
  --network remnawave-network \
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
  -e AI_STATE_PATH=/data/ai/state.db \
  -e AI_ONNX_COMMAND='python3 /app/ai-hooks/onnx_infer.py' \
  astracat/protect:ai \
  -config /app/configs/astra.yaml -http :80 -https :443 -admin :9090
```

## 5) Запуск с TFLite backend

```bash
docker rm -f astracat-protect 2>/dev/null || true
docker run -d --name astracat-protect \
  --restart unless-stopped \
  --network remnawave-network \
  -p 80:80 -p 443:443 -p 127.0.0.1:9091:9090 \
  -v /opt/astracat-protect/configs:/app/configs:ro \
  -v /opt/astracat-protect/data:/data \
  -v /opt/astracat-protect/models:/models:ro \
  -e ADMIN_TOKEN=changeme \
  -e ACME_EMAIL=ops@example.com \
  -e HTTP3_ENABLED=1 \
  -e AI_ENABLED=1 \
  -e AI_BACKEND=tflite \
  -e AI_MODEL_PATH=/models/waf.tflite \
  -e AI_STATE_PATH=/data/ai/state.db \
  -e AI_TFLITE_COMMAND='python3 /app/ai-hooks/tflite_infer.py' \
  astracat/protect:ai \
  -config /app/configs/astra.yaml -http :80 -https :443 -admin :9090
```

Если `tflite-runtime` не ставится на вашей платформе, оставьте `AI_TFLITE_COMMAND` на внешний бинарь/скрипт, установленный в контейнер самостоятельно.

## 6) Формат hook-взаимодействия

Приложение передает JSON в stdin:

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

Ожидается stdout:

```json
{"score":8.4,"action":"block","reason":"onnx-runtime"}
```

`action` можно не возвращать, тогда решение принимается по threshold из env/yaml.

## 7) DNS-01 автоматизация (hooks)

Если домены не должны использовать HTTP-01, включите DNS-01:

```bash
-e ACME_DNS01=1 \
-e ACME_DNS_STORAGE=/data/acme/dns01 \
-e ACME_DNS_HOOK_TIMEOUT=180 \
-e ACME_DNS_ISSUE_HOOK='lego --email ops@example.com --dns cloudflare --domains {domain} --path {storage} run && cp {storage}/certificates/{domain}.crt {cert} && cp {storage}/certificates/{domain}.key {key}' \
-e ACME_DNS_RENEW_HOOK='lego --email ops@example.com --dns cloudflare --domains {domain} --path {storage} renew --days 30 && cp {storage}/certificates/{domain}.crt {cert} && cp {storage}/certificates/{domain}.key {key}' \
```

Подстановки:
- `{domain}`: SNI-домен;
- `{storage}`: директория DNS-01 состояния;
- `{cert}`: путь для итогового cert;
- `{key}`: путь для итогового key.

## 8) Проверка, что всё работает

1. Логи контейнера:
```bash
docker logs --since=2m astracat-protect | tail -n 80
```

2. Health:
```bash
curl -s http://127.0.0.1:9091/healthz
```

3. Reload:
```bash
curl -s -H "Authorization: Bearer changeme" http://127.0.0.1:9091/reload
```

4. HTTP/3 проверка:
```bash
curl --http3 -I https://example.com
```

5. AI state файл:
```bash
docker exec -it astracat-protect sh -lc 'ls -lah /data/ai'
```

## 9) Рекомендации для production

- Держите `/data` на persistent volume.
- Для `AI_ONNX_COMMAND`/`AI_TFLITE_COMMAND` используйте абсолютные пути.
- Начинайте с `AI_LEARNING_MODE=true`, затем переключайте в enforcement.
- Сначала включайте `WAF_LEVEL=medium`, потом повышайте до `high/ultra`.
- Хуки DNS-01 делайте идемпотентными и с retry внутри скриптов.
