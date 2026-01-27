# DIAG10 runbook (hello-enclave, 3 minutes)

Цель: быстрый воспроизводимый прогон (≤3 минут на хосте) который:
- гарантированно **не использует** `/bin/sh -c` в enclave image (Rust-бинарник PID1)
- собирает 2 EIF для `vsock-pingpong`: `basic` и `vsock`
- запускает их последовательно (attach-console кратко)
- запускает **AWS hello-enclave** как контроль
- собирает артефакты: `/var/log/nitro_enclaves/err*.log` (полностью), `nitro_enclaves.log` tail, `dmesg` tail, `docker inspect` (Entrypoint/Cmd)
- после прогона выполняется `terraform destroy` (с ноутбука)

## 1) Что нужно поправить в коде

### Файл: `projects/EphemeralML/enclaves/vsock-pingpong/Dockerfile`

Убедиться, что:
- **нет** `CMD ["/bin/sh","-c", ...]`
- есть **явный** `ENTRYPOINT ["/init"]` (PID1 wrapper пишет в `/dev/console` и держит enclave живым)
- режим выбирается **через ENV** (`VSOCK_PINGPONG_MODE`) чтобы `ssm_diag10.sh` мог собирать два image (basic/vsock) через `--build-arg MODE=...`

(Если этого нет — очень часто enclave делает немедленный `reboot: Restarting system` без каких-либо логов приложения.)

## 2) Запуск инфраструктуры (laptop)

```bash
cd projects/EphemeralML/infra/hello-enclave
terraform init
terraform apply -var 'availability_zone=us-east-1a' -var 'instance_type=m6i.xlarge'
```

Сохраните `instance_id` (из output или из EC2).

## 3) Запуск SSM-диагностики (laptop)

Скрипт, который выполняется на хосте: `projects/EphemeralML/infra/hello-enclave/ssm_diag10.sh`

Примечание: скрипт сам делает `git clone` репозитория на хост (в `/root/EphemeralML`), так что не зависит от предварительного checkout.

Вариант A (проще всего): отправить содержимое скрипта как inline-команды.

```bash
INSTANCE_ID=i-xxxxxxxxxxxxxxxxx
REGION=us-east-1

aws ssm send-command \
  --region "$REGION" \
  --document-name "AWS-RunShellScript" \
  --comment "EphemeralML diag10 (<=3min): vsock-pingpong basic/vsock + hello control + log bundle" \
  --instance-ids "$INSTANCE_ID" \
  --parameters commands="$(python3 - <<'PY'
import pathlib
p = pathlib.Path('projects/EphemeralML/infra/hello-enclave/ssm_diag10.sh')
print(p.read_text())
PY
)" \
  --timeout-seconds 190
```

После выполнения, на хосте появится архив:
- `/tmp/hello-enclave-diag10-<TS>.tgz`

Если нужно забрать его через SSM, можно добавить отдельной командой в send-command, например `ls -lh /tmp/hello-enclave-diag10-*.tgz`.

## 4) Destroy (laptop) — обязательно после прогона

```bash
cd projects/EphemeralML/infra/hello-enclave
terraform destroy -auto-approve
```

## 5) Частые грабли (из реальной отладки, 2026-01-27)

### Nitro CLI artifacts (E51)
Если `nitro-cli build-enclave` падает с `E51 Artifacts path environment variable not set`, нужно задать:
- `HOME=/root` **или**
- `NITRO_CLI_ARTIFACTS=/tmp/nitro-cli-artifacts` (и создать директорию).

### Amazon Linux 2023: пакета `aws-nitro-enclaves-allocator` нет
На AL2023 ставить:
- `aws-nitro-enclaves-cli`
- `aws-nitro-enclaves-cli-devel`
(allocator/vsock-proxy сервисы приходят внутри этих пакетов).

### Rust сборка на хосте
Для сборки `kms_proxy_host` нужны:
- `gcc gcc-c++ make` (иначе будет `linker cc not found`).
- при `set -u` обязательно `export HOME=/root` перед `source /root/.cargo/env`.

### SSM size limits
Inline-передача длинного `ssm_diag10.sh` в AWS-RunShellScript может молча обрезаться.
Решение: отправлять скрипт base64 чанками, собирать на инстансе в файл и запускать.

### CPU pool exhaustion
Если видишь ошибки вида "no CPUs available in pool" / E29/E39 при `run-enclave` —
значит старый enclave не был terminated. Перед новым запуском:
- `nitro-cli describe-enclaves`
- `nitro-cli terminate-enclave --enclave-id ...`

## 6) KMS proxy: как дебажить по JSON-логам (request_id/trace_id)

Начиная с hardening v1, `kms_proxy_host` пишет **структурные JSON** строки в stdout.
Их удобно фильтровать по `request_id` (сквозной id от enclave) и связывать с AWS по `kms_request_id`.

### Полезные события
- `event=kms_proxy_request`
  - `request_id`, `trace_id`
  - `op`: `GenerateDataKey` или `Decrypt`
  - `recipient`: `true/false` (RecipientInfo flow)
  - `ciphertext_len`
- `event=kms_proxy_response`
  - `request_id`, `trace_id`
  - `ok`: `true/false`
  - `error_code`: например `timeout`, `upstream_throttled`, `upstream_access_denied`
  - `kms_request_id`: request-id AWS KMS (если был вызов)
  - `duration_ms`
  - `metrics`: снапшот счётчиков (retries/timeouts/throttled/rate_limited)

### Типовые команды
Фильтр по request_id:
```bash
grep '"request_id":"<RID>"' /var/log/ephemeralml-kms-proxy.log 2>/dev/null || true
# если логов в файл нет, проверь journal:
# journalctl -u kms-proxy-host -o cat | grep '"request_id":"<RID>"'
```

Если поднят локальный OTel Collector (в diag10 он стартует контейнером `otelcol`), можно смотреть его вывод:
```bash
sudo docker logs --tail 200 otelcol
```

Показать только ошибки:
```bash
grep '"event":"kms_proxy_response"' /var/log/ephemeralml-kms-proxy.log | grep '"ok":false'
```

Найти все throttling:
```bash
grep '"error_code":"UpstreamThrottled"' /var/log/ephemeralml-kms-proxy.log
```

Сопоставить с AWS KMS по kms_request_id (для CloudTrail/Support):
```bash
grep '"kms_request_id"' /var/log/ephemeralml-kms-proxy.log | head
```

### Интерпретация
- `UpstreamThrottled` + рост `metrics.rate_limited_total` → снижать RPS cap/конкурентность, смотреть квоты KMS.
- `Timeout` + рост `metrics.retries_total` → сеть/региональная деградация, проверить дедлайны и circuit breaker.
- `UpstreamAccessDenied` → ошибка IAM/KMS policy (это **не** ретраится).

## 7) Что смотреть в результате

Внутри `*.tgz`:
- `run_basic.console.log` — консоль enclave basic
- `run_vsock.console.log` — консоль enclave vsock
- `run_hello.console.log` — контрольный hello
- `err*.log` — полные nitro err logs (корневая причина E45/E44)
- `nitro_enclaves.log.tail` — tail системного лога nitro
- `dmesg.tail` — tail dmesg
- `docker_inspect_*` логи — Entrypoint/Cmd

Ожидание:
- в `run_smoke.console.log` должен появиться `[busybox-smoke] alive`.
- в basic/vsock должен появиться хотя бы `[init] starting` и затем `[init] launching ... --mode ...`.
- если снова будет немедленный `reboot: Restarting system` **без `[init]`** — это значит, что Nitro init не смог определить/exec команду из образа (проверять Entrypoint/Cmd в docker inspect и семантику build-enclave).
