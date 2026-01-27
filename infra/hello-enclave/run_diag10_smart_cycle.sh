#!/usr/bin/env bash
# Smart one-button cycle for Nitro Enclaves debugging:
# - Tries multiple (AZ, instance_type) combos to dodge EC2 capacity hiccups.
# - Puts a hard timeout around `terraform apply`.
# - If apply times out / instance stays Pending too long, prints AWS-side reasons/events.
# - Always destroys infra on exit.

set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

REGION="${REGION:-us-east-1}"
# Ordered by preference: cheapest viable first.
CAND_INSTANCE_TYPES_DEFAULT=(c6i.large c6i.xlarge m6i.large m6i.xlarge c6a.large c6a.xlarge m6a.large m6a.xlarge)
CAND_AZS_DEFAULT=(us-east-1a us-east-1b us-east-1c us-east-1d us-east-1f)

# Optional overrides (space-separated)
read -r -a CAND_INSTANCE_TYPES <<<"${CAND_INSTANCE_TYPES:-${CAND_INSTANCE_TYPES_DEFAULT[*]}}"
read -r -a CAND_AZS <<<"${CAND_AZS:-${CAND_AZS_DEFAULT[*]}}"

APPLY_TIMEOUT_SECS="${APPLY_TIMEOUT_SECS:-420}"
SSM_TIMEOUT_SECS="${SSM_TIMEOUT_SECS:-1200}"
CYCLE_TIMEOUT_SECS="${CYCLE_TIMEOUT_SECS:-1800}"
WAIT_RUNNING_SECS="${WAIT_RUNNING_SECS:-240}"

# Optional: set AWS_PROFILE externally.
AWS_PROFILE_OPT=()
if [[ -n "${AWS_PROFILE:-}" ]]; then
  AWS_PROFILE_OPT=(--profile "$AWS_PROFILE")
fi

log() { echo "[smart-cycle $(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

aws_ec2_dump_instance() {
  local instance_id="$1"
  log "aws ec2 describe-instances ($instance_id)"
  aws "${AWS_PROFILE_OPT[@]}" ec2 describe-instances --region "$REGION" --instance-ids "$instance_id" \
    --query 'Reservations[0].Instances[0].{State:State.Name,AZ:Placement.AvailabilityZone,Type:InstanceType,PublicIp:PublicIpAddress,PrivateIp:PrivateIpAddress,StateTransitionReason:StateTransitionReason,LaunchTime:LaunchTime,SubnetId:SubnetId,VpcId:VpcId}' \
    --output json || true

  log "aws ec2 describe-instance-status ($instance_id)"
  aws "${AWS_PROFILE_OPT[@]}" ec2 describe-instance-status --region "$REGION" --include-all-instances --instance-ids "$instance_id" \
    --query 'InstanceStatuses[0].{InstanceState:InstanceState.Name,SystemStatus:SystemStatus.Status,InstanceStatus:InstanceStatus.Status,Events:Events}' \
    --output json || true

  log "aws ec2 get-console-output ($instance_id) [tail]"
  aws "${AWS_PROFILE_OPT[@]}" ec2 get-console-output --region "$REGION" --instance-id "$instance_id" --latest \
    --query 'Output' --output text 2>/dev/null | tail -n 40 || true
}

destroy() {
  log "terraform destroy (best-effort)"
  terraform destroy -auto-approve -lock-timeout=60s -var "availability_zone=${AZ}" -var "instance_type=${INSTANCE_TYPE}" >/dev/null 2>&1 || true
}

cleanup() {
  destroy
}
trap cleanup EXIT

attempt() {
  AZ="$1"
  INSTANCE_TYPE="$2"
  export AZ INSTANCE_TYPE

  log "terraform init"
  terraform init -input=false >/dev/null

  log "attempt apply AZ=$AZ type=$INSTANCE_TYPE (timeout=${APPLY_TIMEOUT_SECS}s)"
  set +e
  timeout "$APPLY_TIMEOUT_SECS" terraform apply -auto-approve -lock-timeout=60s -var "availability_zone=${AZ}" -var "instance_type=${INSTANCE_TYPE}"
  local apply_rc=$?
  set -e

  local instance_id=""
  instance_id="$(terraform output -raw instance_id 2>/dev/null || true)"
  if [[ -z "$instance_id" ]]; then
    instance_id="$(terraform state show -no-color aws_instance.host 2>/dev/null | awk '/^id\s*=/{print $3}' | head -n1 || true)"
  fi

  if [[ $apply_rc -eq 124 ]]; then
    log "apply timed out (rc=124)."
    if [[ -n "$instance_id" ]]; then
      aws_ec2_dump_instance "$instance_id"
    else
      log "No instance_id in state yet. Likely stuck before EC2 instance creation was recorded."
    fi
    return 124
  fi

  if [[ $apply_rc -ne 0 ]]; then
    log "apply failed rc=$apply_rc"
    if [[ -n "$instance_id" ]]; then aws_ec2_dump_instance "$instance_id"; fi
    return $apply_rc
  fi

  if [[ -z "$instance_id" ]]; then
    log "ERROR: apply succeeded but no instance_id"
    terraform output || true
    return 2
  fi

  log "instance_id=$instance_id"

  # Wait for instance to reach running (helps avoid SSM flakiness)
  local start now
  start=$(date +%s)
  while true; do
    now=$(date +%s)
    if (( now - start > WAIT_RUNNING_SECS )); then
      log "instance did not become running within ${WAIT_RUNNING_SECS}s"
      aws_ec2_dump_instance "$instance_id"
      return 125
    fi
    local state
    state=$(aws "${AWS_PROFILE_OPT[@]}" ec2 describe-instances --region "$REGION" --instance-ids "$instance_id" --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || true)
    log "instance_state=$state"
    [[ "$state" == "running" ]] && break
    sleep 10
  done

  # Now run the existing cycle logic for SSM diag (but without re-applying/destroying).
  # We reuse the robust chunked sender from run_diag10_cycle.sh.
  log "running diag10 via SSM on $instance_id"
  INSTANCE_ID="$instance_id" SSM_TIMEOUT_SECS="$SSM_TIMEOUT_SECS" python3 - "/tmp/diag10-smart.json" <<'PY'
import json, os, pathlib, base64, sys
out_path = sys.argv[1]
instance_id = os.environ['INSTANCE_ID']
timeout = int(os.environ.get('SSM_TIMEOUT_SECS', '900'))
script = pathlib.Path('ssm_diag10.sh').read_bytes()
script_b64 = base64.b64encode(script).decode('ascii')
chunks = [script_b64[i:i+3000] for i in range(0, len(script_b64), 3000)]
commands = [
  'set -euo pipefail',
  'rm -f /tmp/ssm_diag10.sh /tmp/ssm_diag10.b64',
]
for c in chunks:
  commands.append("printf '%s' '" + c + "' >> /tmp/ssm_diag10.b64")
commands += [
  'base64 -d /tmp/ssm_diag10.b64 > /tmp/ssm_diag10.sh',
  'chmod +x /tmp/ssm_diag10.sh',
  'bash -lc /tmp/ssm_diag10.sh',
]
payload = {
  'DocumentName': 'AWS-RunShellScript',
  'Comment': 'EphemeralML diag10 smart cycle',
  'InstanceIds': [instance_id],
  'TimeoutSeconds': timeout,
  'Parameters': {'commands': commands},
}
with open(out_path, 'w', encoding='utf-8') as f:
  json.dump(payload, f)
PY

  local cmd_id
  cmd_id=$(aws "${AWS_PROFILE_OPT[@]}" ssm send-command --region "$REGION" --cli-input-json file:///tmp/diag10-smart.json --query 'Command.CommandId' --output text)
  log "ssm_command_id=$cmd_id"

  local start2
  start2=$(date +%s)
  while true; do
    if (( $(date +%s) - start2 > CYCLE_TIMEOUT_SECS )); then
      log "cycle timeout reached waiting for SSM"
      break
    fi
    local status
    status=$(aws "${AWS_PROFILE_OPT[@]}" ssm list-command-invocations --region "$REGION" --command-id "$cmd_id" --details --query 'CommandInvocations[0].Status' --output text 2>/dev/null || echo UNKNOWN)
    log "ssm_status=$status"
    if [[ "$status" == "Success" || "$status" == "Failed" || "$status" == "TimedOut" || "$status" == "Cancelled" ]]; then
      aws "${AWS_PROFILE_OPT[@]}" ssm get-command-invocation --region "$REGION" --command-id "$cmd_id" --instance-id "$instance_id" --query 'StandardErrorContent' --output text > /tmp/ssm_diag10.stderr.txt 2>/dev/null || true
      aws "${AWS_PROFILE_OPT[@]}" ssm get-command-invocation --region "$REGION" --command-id "$cmd_id" --instance-id "$instance_id" --query 'StandardOutputContent' --output text > /tmp/ssm_diag10.stdout.txt 2>/dev/null || true
      tail -n 120 /tmp/ssm_diag10.stdout.txt || true
      if [[ "$status" != "Success" ]]; then
        log "SSM failed; stderr tail:"
        tail -n 80 /tmp/ssm_diag10.stderr.txt || true
      fi
      break
    fi
    sleep 10
  done

  return 0
}

main() {
  log "starting (REGION=$REGION APPLY_TIMEOUT_SECS=$APPLY_TIMEOUT_SECS)"
  for az in "${CAND_AZS[@]}"; do
    for it in "${CAND_INSTANCE_TYPES[@]}"; do
      log "--- trying az=$az type=$it ---"
      # Always start clean for deterministic attempts.
      AZ="$az" INSTANCE_TYPE="$it" destroy
      if attempt "$az" "$it"; then
        log "diag attempt finished (success path)."
        return 0
      else
        log "attempt failed; moving on"
      fi
    done
  done
  log "no successful attempt across candidates"
  return 1
}

main
