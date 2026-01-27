#!/usr/bin/env bash
# diag10: hello-enclave 3-minute end-to-end diagnostic
# - Builds EIFs for vsock-pingpong in two modes (basic/vsock) WITHOUT /bin/sh -c
# - Runs them sequentially (short attach-console windows)
# - Runs AWS public hello enclave as control
# - Collects: err*.log full, nitro_enclaves.log tail, dmesg tail, docker inspect Entrypoint/Cmd
#
# Intended to be executed on the EC2 parent via AWS SSM (aws ssm send-command).
# Keep runtime ~<= 3 minutes.

set -euo pipefail

# NOTE: OUT_BASE is initialized inside main() so it works even when wrapped by `timeout bash -lc ...`.

# Default OUT_BASE so helper functions can log even before main() initializes the final output dir.
OUT_BASE="/tmp/hello-enclave-diag10-pre"
mkdir -p "$OUT_BASE" || true

log() { echo "[diag10 $(date -u +%H:%M:%S)] $*"; }

# Ensure we don't hang forever. Whole script hard-limited to ~175s.
HARD_TIMEOUT_SECS=175

run() {
  local name="$1"; shift
  log "$name"
  # capture stdout+stderr to file AND to SSM output (tail later if needed)
  ( "$@" ) 2>&1 | tee -a "$OUT_BASE/${name}.log"
}

run_quiet() {
  local name="$1"; shift
  log "$name"
  ( "$@" ) >"$OUT_BASE/${name}.log" 2>&1 || return $?
}

cleanup_enclaves() {
  # Best-effort terminate any running enclaves so sequential runs don't collide
  sudo nitro-cli describe-enclaves 2>/dev/null | sed -n '1,200p' >"$OUT_BASE/describe_before_cleanup.json" || true
  local ids
  ids=$(sudo nitro-cli describe-enclaves 2>/dev/null | awk -F '"' '/EnclaveID/ {print $4}' | sort -u || true)
  if [[ -n "${ids}" ]]; then
    while read -r id; do
      [[ -z "$id" ]] && continue
      log "terminate_enclave $id (best-effort)"
      sudo nitro-cli terminate-enclave --enclave-id "$id" >/dev/null 2>&1 || true
    done <<<"$ids"
  fi
  sudo nitro-cli describe-enclaves 2>/dev/null | sed -n '1,200p' >"$OUT_BASE/describe_after_cleanup.json" || true
}

collect_logs() {
  log "collect_logs"

  # Full err logs (E45 references these)
  sudo ls -1 /var/log/nitro_enclaves/err*.log >"$OUT_BASE/err_logs.list" 2>/dev/null || true
  while read -r f; do
    [[ -z "$f" ]] && continue
    sudo cat "$f" >"$OUT_BASE/$(basename "$f")" 2>/dev/null || true
  done <"$OUT_BASE/err_logs.list" || true

  # nitro_enclaves.log tail
  if [[ -f /var/log/nitro_enclaves/nitro_enclaves.log ]]; then
    sudo tail -n 250 /var/log/nitro_enclaves/nitro_enclaves.log >"$OUT_BASE/nitro_enclaves.log.tail" || true
  fi

  # dmesg tail
  sudo dmesg -T | tail -n 220 >"$OUT_BASE/dmesg.tail" || true

  # allocator state
  sudo nitro-cli describe-enclaves >"$OUT_BASE/describe_enclaves.json" 2>/dev/null || true
  sudo systemctl status nitro-enclaves-allocator.service --no-pager >"$OUT_BASE/allocator_status.txt" 2>&1 || true
  sudo systemctl status nitro-enclaves-vsock-proxy.service --no-pager >"$OUT_BASE/vsock_proxy_status.txt" 2>&1 || true
}

main() {
  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  OUT_BASE="/tmp/hello-enclave-diag10-${TS}"
  mkdir -p "$OUT_BASE"

  log "OUT_BASE=$OUT_BASE"

  # ---------- quick sanity ----------
  run "uname" uname -a

  # Ensure Nitro tooling exists
  run "dnf_install_nitro" bash -lc "sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel"
  if ! command -v nitro-cli >/dev/null 2>&1; then
    run "nitro_cli_missing" bash -lc "echo 'ERROR: nitro-cli not found after install'; sudo dnf list installed | grep -i nitro || true; ls -la /usr/bin/nitro-cli || true"
    return 40
  fi

  run "nitro_cli_version" sudo nitro-cli --version

  # Reserve CPUs/memory for enclaves (uses /etc/nitro_enclaves/allocator.yaml).
  run_quiet "enable_allocator" bash -lc "sudo systemctl enable --now nitro-enclaves-allocator.service >/dev/null 2>&1 || true"
  run_quiet "start_allocator"  bash -lc "sudo systemctl start nitro-enclaves-allocator.service >/dev/null 2>&1 || true"

  # vsock proxy is optional for attach-console, but enable if present.
  run_quiet "enable_vsock_proxy" bash -lc "sudo systemctl enable --now nitro-enclaves-vsock-proxy.service >/dev/null 2>&1 || true"

  run "docker_version" sudo docker --version

  # Clean slate
  cleanup_enclaves

  # ---------- build enclaves (smoke + vsock-pingpong) ----------
  # Fetch the repo on-host so the diagnostic is self-contained.
  WORKDIR="/root"
  REPO_ROOT="$WORKDIR/EphemeralML"
  REPO="$REPO_ROOT/enclaves/vsock-pingpong"
  SMOKE_REPO="$REPO_ROOT/enclaves/busybox-smoke"

  run_quiet "dnf_install_git" bash -lc "sudo dnf install -y git >/dev/null 2>&1 || true"
  run "git_clone" bash -lc "cd '$WORKDIR' && rm -rf EphemeralML && git clone -q https://github.com/tsyrulb/EphemeralML.git"
  run "repo_rev" bash -lc "cd '$REPO_ROOT' && git log -1 --oneline"
  run "repo_ls" bash -lc "ls -la '$REPO'"

  # Build two docker tags from the same Dockerfile.
  # Important: We MUST set ENTRYPOINT explicitly. Mode is selected via build-arg -> ENV.
  run_quiet "docker_build_vsock" bash -lc "cd '$REPO' && sudo docker build --build-arg MODE=vsock -t ephemeralml/vsock-pingpong:diag10-vsock ."
  run_quiet "docker_build_basic" bash -lc "cd '$REPO' && sudo docker build --build-arg MODE=basic -t ephemeralml/vsock-pingpong:diag10-basic ."

  # Inspect Entrypoint/Cmd (these are key for Nitro init semantics)
  run "docker_inspect_vsock" bash -lc "sudo docker inspect ephemeralml/vsock-pingpong:diag10-vsock | sed -n '1,260p'"
  run "docker_inspect_basic" bash -lc "sudo docker inspect ephemeralml/vsock-pingpong:diag10-basic | sed -n '1,260p'"

  # Build EIFs
  run "build_eif_vsock" bash -lc "cd '$REPO' && sudo nitro-cli build-enclave --docker-uri ephemeralml/vsock-pingpong:diag10-vsock --output-file '$OUT_BASE/vsock-pingpong-vsock.eif'"
  run "build_eif_basic" bash -lc "cd '$REPO' && sudo nitro-cli build-enclave --docker-uri ephemeralml/vsock-pingpong:diag10-basic --output-file '$OUT_BASE/vsock-pingpong-basic.eif'"

  # Smoke-test EIF (ultra-minimal) — should always stay alive and print to console.
  run_quiet "docker_build_smoke" bash -lc "cd '$SMOKE_REPO' && sudo docker build -t ephemeralml/busybox-smoke:diag10 ."
  run "docker_inspect_smoke" bash -lc "sudo docker inspect ephemeralml/busybox-smoke:diag10 | sed -n '1,220p'"
  run "build_eif_smoke" bash -lc "cd '$SMOKE_REPO' && sudo nitro-cli build-enclave --docker-uri ephemeralml/busybox-smoke:diag10 --output-file '$OUT_BASE/busybox-smoke.eif'"

  run "ls_eifs" bash -lc "ls -lh '$OUT_BASE'/*.eif"

  # ---------- run EIFs sequentially ----------
  # Use distinct CIDs to avoid collisions
  # Keep attach-console short; if enclave reboots immediately we still capture it.

  cleanup_enclaves

  log "run_smoke_attach_console_12s"
  set +e
  sudo timeout 12 nitro-cli run-enclave \
    --eif-path "$OUT_BASE/busybox-smoke.eif" \
    --cpu-count 2 --memory 1024 --enclave-cid 15 --debug-mode --attach-console \
    2>&1 | tee -a "$OUT_BASE/run_smoke.console.log"
  echo "run_smoke_rc=$?" | tee -a "$OUT_BASE/run_smoke.console.log"
  set -e

  sleep 1
  sudo nitro-cli describe-enclaves >"$OUT_BASE/describe_after_smoke.json" 2>/dev/null || true

  cleanup_enclaves

  log "run_basic_attach_console_20s"
  set +e
  sudo timeout 20 nitro-cli run-enclave \
    --eif-path "$OUT_BASE/vsock-pingpong-basic.eif" \
    --cpu-count 2 --memory 1024 --enclave-cid 16 --debug-mode --attach-console \
    2>&1 | tee -a "$OUT_BASE/run_basic.console.log"
  echo "run_basic_rc=$?" | tee -a "$OUT_BASE/run_basic.console.log"
  set -e

  sleep 1
  sudo nitro-cli describe-enclaves >"$OUT_BASE/describe_after_basic.json" 2>/dev/null || true

  cleanup_enclaves

  log "run_vsock_attach_console_20s"
  set +e
  sudo timeout 20 nitro-cli run-enclave \
    --eif-path "$OUT_BASE/vsock-pingpong-vsock.eif" \
    --cpu-count 2 --memory 1024 --enclave-cid 17 --debug-mode --attach-console \
    2>&1 | tee -a "$OUT_BASE/run_vsock.console.log"
  echo "run_vsock_rc=$?" | tee -a "$OUT_BASE/run_vsock.console.log"
  set -e

  sleep 1
  sudo nitro-cli describe-enclaves >"$OUT_BASE/describe_after_vsock.json" 2>/dev/null || true

  cleanup_enclaves

  # ---------- control: AWS public hello enclave ----------
  # Keep this short; ensure we can boot and see application output.
  run_quiet "docker_pull_hello" sudo docker pull public.ecr.aws/aws-nitro-enclaves/hello:latest
  run "build_eif_hello" sudo nitro-cli build-enclave --docker-uri public.ecr.aws/aws-nitro-enclaves/hello:latest --output-file "$OUT_BASE/hello.eif"

  log "run_hello_attach_console_15s"
  set +e
  sudo timeout 15 nitro-cli run-enclave \
    --eif-path "$OUT_BASE/hello.eif" \
    --cpu-count 2 --memory 1024 --enclave-cid 18 --debug-mode --attach-console \
    2>&1 | tee -a "$OUT_BASE/run_hello.console.log"
  echo "run_hello_rc=$?" | tee -a "$OUT_BASE/run_hello.console.log"
  set -e

  # Don't leave hello running.
  cleanup_enclaves

  # ---------- collect host-side logs ----------
  collect_logs

  # Pack results for easy retrieval
  run "tar_results" bash -lc "tar -C '$OUT_BASE' -czf '${OUT_BASE}.tgz' . && ls -lh '${OUT_BASE}.tgz'"

  log "DONE (results: ${OUT_BASE}.tgz)"
}

# Hard timeout wrapper
# Run inside a fresh shell so we can `timeout` everything, but keep OUT_BASE initialization inside main().
run "diag10_wrapper" timeout "$HARD_TIMEOUT_SECS" bash -lc "$(declare -f log run run_quiet cleanup_enclaves collect_logs main); main" || true
