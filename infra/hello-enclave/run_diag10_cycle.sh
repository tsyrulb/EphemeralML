#!/usr/bin/env bash
# One-button cycle for Nitro Enclaves debugging:
# 1) terraform apply
# 2) run diag10 via SSM (build/run enclaves + collect logs)
# 3) terraform destroy (always, even on failure)
#
# Safety guardrails:
# - Hard time limit for the whole cycle (default 10 minutes)
# - Always destroys infra on exit
# - Defaults to us-east-1 + m6i.xlarge + us-east-1a (override via env)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

REGION="${REGION:-us-east-1}"
AZ="${AZ:-us-east-1a}"
INSTANCE_TYPE="${INSTANCE_TYPE:-m6i.xlarge}"
CYCLE_TIMEOUT_SECS="${CYCLE_TIMEOUT_SECS:-600}"
SSM_TIMEOUT_SECS="${SSM_TIMEOUT_SECS:-220}"

# Optional: set AWS_PROFILE externally.
AWS_PROFILE_OPT=()
if [[ -n "${AWS_PROFILE:-}" ]]; then
  AWS_PROFILE_OPT=(--profile "$AWS_PROFILE")
fi

log() { echo "[cycle $(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

destroy() {
  log "terraform destroy (best-effort)"
  terraform destroy -auto-approve -lock-timeout=60s -var "availability_zone=${AZ}" -var "instance_type=${INSTANCE_TYPE}" || true
}

cleanup() {
  destroy
}
trap cleanup EXIT

main() {
  log "terraform init"
  terraform init -input=false >/dev/null

  if [[ -z "${AZ}" || -z "${INSTANCE_TYPE}" || -z "${REGION}" ]]; then
    log "ERROR: missing required config (REGION/AZ/INSTANCE_TYPE). REGION='${REGION}' AZ='${AZ}' INSTANCE_TYPE='${INSTANCE_TYPE}'"
    return 2
  fi

  log "terraform apply (REGION=${REGION}, AZ=${AZ}, type=${INSTANCE_TYPE})"
  terraform apply -auto-approve -lock-timeout=60s -var "availability_zone=${AZ}" -var "instance_type=${INSTANCE_TYPE}"

  # Try to extract instance id from outputs first; fall back to state.
  INSTANCE_ID="$(terraform output -raw instance_id 2>/dev/null || true)"
  if [[ -z "$INSTANCE_ID" ]]; then
    INSTANCE_ID="$(terraform state show -no-color aws_instance.parent 2>/dev/null | awk '/^id\s*=/{print $3}' | head -n1 || true)"
  fi

  if [[ -z "$INSTANCE_ID" ]]; then
    log "ERROR: could not determine instance_id from terraform"
    terraform output || true
    terraform state list || true
    return 2
  fi

  log "instance_id=$INSTANCE_ID"

  # Send diag10 script via SSM (inline), robustly (JSON file) so quoting/newlines can't break.
  local tmp_json
  tmp_json="$(mktemp -t diag10-sendcmd-XXXXXX.json)"

  INSTANCE_ID="$INSTANCE_ID" SSM_TIMEOUT_SECS="$SSM_TIMEOUT_SECS" python3 - "$tmp_json" <<'PY'
import json, os, pathlib, sys
out_path = sys.argv[1]
instance_id = os.environ["INSTANCE_ID"]
timeout = int(os.environ.get("SSM_TIMEOUT_SECS", "220"))
script = pathlib.Path("ssm_diag10.sh").read_text()

payload = {
  "DocumentName": "AWS-RunShellScript",
  "Comment": "EphemeralML diag10 cycle",
  "InstanceIds": [instance_id],
  "TimeoutSeconds": timeout,
  "Parameters": {"commands": [script]},
}

with open(out_path, "w", encoding="utf-8") as f:
  json.dump(payload, f)
PY

  # Wait for SSM agent registration (instance becomes a Managed Instance).
  log "wait for SSM registration"
  local wait_start
  wait_start=$(date +%s)
  while true; do
    if aws "${AWS_PROFILE_OPT[@]}" ssm describe-instance-information \
      --region "$REGION" \
      --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
      --query 'InstanceInformationList[0].PingStatus' \
      --output text 2>/dev/null | grep -qE 'Online|ConnectionLost|Inactive'; then
      break
    fi
    if (( $(date +%s) - wait_start > 180 )); then
      log "ERROR: instance did not register with SSM within 180s"
      return 3
    fi
    sleep 5
  done

  log "ssm send-command (timeout=${SSM_TIMEOUT_SECS}s, payload=$tmp_json)"
  local resp cmd_id
  resp="$(aws "${AWS_PROFILE_OPT[@]}" ssm send-command \
    --region "$REGION" \
    --cli-input-json "file://$tmp_json" \
    --output json)"

  cmd_id="$(echo "$resp" | python3 -c 'import json, sys; print(json.load(sys.stdin)["Command"]["CommandId"])')"
  log "command_id=$cmd_id"

  # Wait for completion (poll), but do not exceed cycle timeout.
  local start now elapsed
  start=$(date +%s)
  while true; do
    now=$(date +%s)
    elapsed=$((now-start))
    if (( elapsed > CYCLE_TIMEOUT_SECS )); then
      log "cycle timeout reached while waiting for SSM; stopping wait"
      break
    fi

    local inv
    inv="$(aws "${AWS_PROFILE_OPT[@]}" ssm list-command-invocations --region "$REGION" --command-id "$cmd_id" --details --output json || true)"
    local status
    status="$(echo "$inv" | python3 -c 'import json, sys; j=json.load(sys.stdin); print(j["CommandInvocations"][0]["Status"] if j.get("CommandInvocations") else "UNKNOWN")')"

    log "ssm_status=$status"

    if [[ "$status" == "Success" || "$status" == "Cancelled" || "$status" == "TimedOut" || "$status" == "Failed" ]]; then
      # Print a short tail of stdout/stderr for quick triage
      echo "$inv" | python3 - <<'PY'
import json, sys
j=json.load(sys.stdin)
if not j.get('CommandInvocations'):
    sys.exit(0)
ci=j['CommandInvocations'][0]
plugins=ci.get('CommandPlugins') or []
for p in plugins:
    out=(p.get('Output') or '')
    print(f"\n--- plugin: {p.get('Name')} status: {p.get('Status')}")
    print(out[-3000:])
PY
      break
    fi

    sleep 5
  done

  log "SSM diag finished (or timed out). Destroy will run via trap."
}

log "starting cycle (CYCLE_TIMEOUT_SECS=${CYCLE_TIMEOUT_SECS}, REGION=${REGION}, AZ=${AZ}, INSTANCE_TYPE=${INSTANCE_TYPE})"

# NOTE: We intentionally do NOT re-exec via `bash -lc` here, because that drops
# our variable defaults/guardrails. If you want a hard wall-clock limit, run:
#   timeout 600 ./run_diag10_cycle.sh
main

log "done (destroy executed via trap)"
