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
- есть `ENTRYPOINT ["/vsock-pingpong"]`
- есть `CMD ["--mode","vsock"]` (дефолт)

(В текущем репозитории DIAG10 это уже внесено.)

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

## 5) Что смотреть в результате

Внутри `*.tgz`:
- `run_basic.console.log` — консоль enclave basic
- `run_vsock.console.log` — консоль enclave vsock
- `run_hello.console.log` — контрольный hello
- `err*.log` — полные nitro err logs (корневая причина E45/E44)
- `nitro_enclaves.log.tail` — tail системного лога nitro
- `dmesg.tail` — tail dmesg
- `docker_inspect_*` логи — Entrypoint/Cmd

Ожидание:
- в basic/vsock должен появиться хотя бы `[enclave] mode=...` (stderr) если PID1 стартует.
- если снова будет немедленный `reboot: Restarting system` без логов приложения — это значит, что даже entrypoint бинарника не доходит (тогда ищем причину в init/runtime/EIF).
