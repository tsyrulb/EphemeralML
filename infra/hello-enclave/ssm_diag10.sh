#!/usr/bin/env bash
# diag10: hello-enclave 3-minute end-to-end diagnostic
# - Builds EIFs for vsock-pingpong in two modes (basic/vsock) WITHOUT /bin/sh -c
# - Runs them sequentially (short attach-console windows)
# - Runs AWS public hello enclave as control
# - Collects: err*.log full, nitro_enclaves.log tail, dmesg tail, docker inspect Entrypoint/Cmd
#
# Intended to be executed on the EC2 parent via AWS SSM (aws ssm send-command).
# Keep runtime ~<= 3 minutes.

set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true

# Fail-fast diagnostics on any error
on_err() {
  local rc=$?
  log "ERROR rc=$rc line=$LINENO cmd=$BASH_COMMAND"
  {
    echo "--- whoami/id/pwd ---"; whoami; id; pwd
    echo "--- df -h ---"; df -h || true
    echo "--- free -h ---"; free -h || true
    echo "--- ulimit -a ---"; ulimit -a || true
    echo "--- docker ps -a ---"; sudo docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' || true
    echo "--- docker system df ---"; sudo docker system df || true
    echo "--- docker journal (tail) ---"; sudo journalctl -u docker --no-pager -n 200 || true
    echo "--- allocator journal (tail) ---"; sudo journalctl -u nitro-enclaves-allocator.service --no-pager -n 200 || true
    echo "--- nitro_cli describe ---"; sudo nitro-cli describe-enclaves || true
    echo "--- dmesg tail ---"; sudo dmesg -T | tail -n 220 || true
  } >>"$OUT_BASE/ERR_TRAP.log" 2>&1 || true
  collect_logs || true
  exit $rc
}
trap on_err ERR

# Tee full script output to a log file (SSM keeps stdout too)
# OUT_BASE may not be initialized yet at this point; use safe default.
exec > >(tee -a "${OUT_BASE:-/tmp/hello-enclave-diag10-pre}/ssm_diag10.full.log") 2>&1


# NOTE: OUT_BASE is initialized inside main() so it works even when wrapped by `timeout bash -lc ...`.

# Default OUT_BASE so helper functions can log even before main() initializes the final output dir.
OUT_BASE="/tmp/hello-enclave-diag10-pre"
mkdir -p "$OUT_BASE" || true

log() { echo "[diag10 $(date -u +%H:%M:%S)] $*"; }

# Ensure we don't hang forever. Whole script hard-limited to ~175s.
HARD_TIMEOUT_SECS=700

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

  # Wait for user-data bootstrap to finish (prevents package-manager lock collisions)
  log "waiting for bootstrap to finish..."
  local b_start
  b_start=$(date +%s)
  while ! grep -q "bootstrap complete" /var/log/ephemeralml-hello-bootstrap.log 2>/dev/null; do
    if (( $(date +%s) - b_start > 300 )); then
      log "WARNING: bootstrap timed out or log missing"
      break
    fi
    sleep 5
  done

  # Ensure Nitro tooling exists (AL2023 uses dnf, AL2 uses yum)
  if command -v dnf >/dev/null 2>&1; then
    PKG_INSTALL=(sudo dnf install -y)
  else
    PKG_INSTALL=(sudo yum install -y)
  fi

  log "install_nitro_packages (quiet)"
  if ! command -v nitro-cli >/dev/null 2>&1; then
    "${PKG_INSTALL[@]}" aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel >/tmp/pkg_nitro.log 2>&1 || {
      log "ERROR: package install failed"
      cat /tmp/pkg_nitro.log
      return 41
    }
  fi
  if ! command -v nitro-cli >/dev/null 2>&1; then
    run "nitro_cli_missing" bash -lc "echo 'ERROR: nitro-cli not found after install'; sudo dnf list installed | grep -i nitro || true; which nitro-cli || true"
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

  # Locate KMS proxy host crate (repo layout may evolve)
  HOST_SRC="$REPO_ROOT/host"
  if [[ ! -d "$HOST_SRC" ]]; then
    log "host dir not found at $HOST_SRC; searching for kms_proxy_host Cargo.toml"
    HOST_TOML=$(grep -Rsl --include Cargo.toml -e 'kms_proxy_host' "$REPO_ROOT" | head -n1 || true)
    if [[ -n "$HOST_TOML" ]]; then
      HOST_SRC=$(dirname "$HOST_TOML")
    fi
  fi
  log "HOST_SRC=$HOST_SRC"

  # Tools needed for cloning/building (AL2 uses yum; AL2023 uses dnf)
  run_quiet "install_git" bash -lc "${PKG_INSTALL[*]} git >/dev/null 2>&1 || true"
  run_quiet "install_build_tools" bash -lc "${PKG_INSTALL[*]} gcc gcc-c++ make >/dev/null 2>&1 || true"
  run_quiet "install_curl" bash -lc "${PKG_INSTALL[*]} curl >/dev/null 2>&1 || true"
  run "git_clone" bash -lc "cd '$WORKDIR' && rm -rf EphemeralML && git clone -q https://github.com/tsyrulb/EphemeralML.git"
  run "repo_rev" bash -lc "cd '$REPO_ROOT' && git log -1 --oneline"

  # Install Rust on host for KMS Proxy
  # NOTE: our deps (aws-sdk-kms etc.) currently require Rust/Cargo >= 1.88, so do NOT pin to old toolchains.
  log "install_rust_on_host (stable)"
  export CARGO_HOME="/root/.cargo"
  export RUSTUP_HOME="/root/.rustup"
  if ! command -v /root/.cargo/bin/rustup >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --no-modify-path >/dev/null 2>&1
  fi
  source "/root/.cargo/env" || true
  /root/.cargo/bin/rustup toolchain install stable >/dev/null 2>&1 || true
  /root/.cargo/bin/rustup default stable || true
  /root/.cargo/bin/rustc --version || true
  /root/.cargo/bin/cargo --version || true

  # Build KMS Proxy Host (production mode)
  log "build_kms_proxy_host"
  ( export CARGO_HOME="/root/.cargo"; export RUSTUP_HOME="/root/.rustup"; source "/root/.cargo/env"; cd "$HOST_SRC" && /root/.cargo/bin/cargo build --release --bin kms_proxy_host --features production ) >/tmp/build_kms_host.log 2>&1 || {
    log "ERROR: build_kms_proxy_host failed"
    cat /tmp/build_kms_host.log
    exit 51
  }

  # Verify host binary exists and is runnable; locate it if target dir differs.
  if [[ ! -x "$REPO_ROOT/host/target/release/kms_proxy_host" ]]; then
    log "ERROR: kms_proxy_host missing at expected path; searching..."
    find "$REPO_ROOT/host" -maxdepth 6 -type f -name kms_proxy_host -ls >"$OUT_BASE/find_kms_proxy_host.txt" 2>&1 || true
    cat "$OUT_BASE/find_kms_proxy_host.txt" || true
    exit 52
  fi
  ( file "$REPO_ROOT/host/target/release/kms_proxy_host" || true ) >"$OUT_BASE/kms_proxy_host.file.txt" 2>&1
  ( ldd "$REPO_ROOT/host/target/release/kms_proxy_host" || true ) >"$OUT_BASE/kms_proxy_host.ldd.txt" 2>&1

  # Build docker tags from the same Dockerfile.
  # Important: We MUST set ENTRYPOINT explicitly. Mode is selected via build-arg -> ENV.
  log "docker_build_vsock (quiet)"
  sudo docker build --build-arg MODE=vsock -t ephemeralml/vsock-pingpong:diag10-vsock "$REPO" >/tmp/docker_build_vsock.log 2>&1
  log "docker_build_attestation (quiet)"
  sudo docker build --build-arg MODE=attestation -t ephemeralml/vsock-pingpong:diag10-attestation "$REPO" >/tmp/docker_build_attestation.log 2>&1
  log "docker_build_kms (quiet)"
  sudo docker build --build-arg MODE=kms -t ephemeralml/vsock-pingpong:diag10-kms "$REPO" >/tmp/docker_build_kms.log 2>&1

  # Build EIFs
  log "build_eif_attestation (quiet)"
  sudo nitro-cli build-enclave --docker-uri ephemeralml/vsock-pingpong:diag10-attestation --output-file "$OUT_BASE/vsock-pingpong-attestation.eif" >/tmp/build_eif_attestation.log 2>&1
  test -s "$OUT_BASE/vsock-pingpong-attestation.eif" || { log "ERROR: attestation EIF missing/empty"; tail -n 200 /tmp/build_eif_attestation.log || true; exit 61; }
  log "build_eif_kms (quiet)"
  sudo nitro-cli build-enclave --docker-uri ephemeralml/vsock-pingpong:diag10-kms --output-file "$OUT_BASE/vsock-pingpong-kms.eif" >/tmp/build_eif_kms.log 2>&1
  test -s "$OUT_BASE/vsock-pingpong-kms.eif" || { log "ERROR: kms EIF missing/empty"; tail -n 200 /tmp/build_eif_kms.log || true; exit 62; }

  # Smoke-test EIF (ultra-minimal) — should always stay alive and print to console.
  log "docker_build_smoke (quiet)"
  sudo docker build -t ephemeralml/busybox-smoke:diag10 "$SMOKE_REPO" >/tmp/docker_build_smoke.log 2>&1
  log "build_eif_smoke (quiet)"
  sudo nitro-cli build-enclave --docker-uri ephemeralml/busybox-smoke:diag10 --output-file "$OUT_BASE/busybox-smoke.eif" >/tmp/build_eif_smoke.log 2>&1
  test -s "$OUT_BASE/busybox-smoke.eif" || { log "ERROR: smoke EIF missing/empty"; tail -n 200 /tmp/build_eif_smoke.log || true; exit 63; }

  run "ls_eifs" bash -lc "ls -lh '$OUT_BASE'/*.eif"

  # ---------- run EIFs sequentially ----------
  # Use distinct CIDs to avoid collisions

  cleanup_enclaves

  # Start OpenTelemetry Collector (logging exporter) for demo traces.
  # The host binary sends OTLP to localhost:4317.
  log "starting otel collector (logging)"
  sudo docker rm -f otelcol >/dev/null 2>&1 || true
  sudo docker run -d --name otelcol \
    -p 4317:4317 -p 4318:4318 \
    -v "$REPO_ROOT/infra/hello-enclave/otelcol-logging.yaml:/etc/otelcol/config.yaml:ro" \
    otel/opentelemetry-collector:latest \
    --config=/etc/otelcol/config.yaml \
    >"$OUT_BASE/otelcol.start.log" 2>&1
  sudo docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' >"$OUT_BASE/docker_ps_a.after_otelcol.txt" 2>&1 || true
  sudo docker logs --tail 120 otelcol >"$OUT_BASE/otelcol.log.tail" 2>&1 || true

  # Start KMS Host Proxy in background (with OTel)
  log "starting kms_proxy_host in background"
  sudo nohup bash -c "source /root/.cargo/env && export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317 && export OTEL_SERVICE_NAME=ephemeralml-kms-proxy-host && $REPO_ROOT/host/target/release/kms_proxy_host" >"$OUT_BASE/kms_proxy_host.log" 2>&1 &
  sleep 2

  log "run_kms_test_attach_console_30s"
  set +e
  sudo timeout 30 nitro-cli run-enclave \
    --eif-path "$OUT_BASE/vsock-pingpong-kms.eif" \
    --cpu-count 2 --memory 1024 --enclave-cid 16 --debug-mode --attach-console \
    >"$OUT_BASE/run_kms_test.console.log" 2>&1
  echo "run_kms_test_rc=$?" >> "$OUT_BASE/run_kms_test.console.log"
  set -e

  cleanup_enclaves

  log "run_attestation_attach_console_20s"
  set +e
  sudo timeout 20 nitro-cli run-enclave \
    --eif-path "$OUT_BASE/vsock-pingpong-attestation.eif" \
    --cpu-count 2 --memory 1024 --enclave-cid 16 --debug-mode --attach-console \
    >"$OUT_BASE/run_attestation.console.log" 2>&1
  echo "run_attestation_rc=$?" >> "$OUT_BASE/run_attestation.console.log"
  set -e

  sleep 1
  sudo nitro-cli describe-enclaves >"$OUT_BASE/describe_after_attestation.json" 2>/dev/null || true

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
    >"$OUT_BASE/run_hello.console.log" 2>&1
  echo "run_hello_rc=$?" >> "$OUT_BASE/run_hello.console.log"
  set -e

  # Don't leave hello running.
  cleanup_enclaves

  # ---------- collect host-side logs ----------
  collect_logs

  # Pack results for easy retrieval
  log "tar_results"
  tar -C "$OUT_BASE" -czf "${OUT_BASE}.tgz" .
  ls -lh "${OUT_BASE}.tgz"

  echo "--- SMOKE CONSOLE (tail 50) ---"
  tail -n 50 "$OUT_BASE/run_smoke.console.log" || true
  echo "--- KMS TEST CONSOLE (tail 100) ---"
  tail -n 100 "$OUT_BASE/run_kms_test.console.log" || true
  echo "--- KMS PROXY LOG (tail 50) ---"
  tail -n 50 "$OUT_BASE/kms_proxy_host.log" || true
  echo "--- ATTESTATION CONSOLE (tail 100) ---"
  tail -n 100 "$OUT_BASE/run_attestation.console.log" || true
  echo "--- HELLO CONSOLE (tail 50) ---"
  tail -n 50 "$OUT_BASE/run_hello.console.log" || true

  log "DONE (results: ${OUT_BASE}.tgz)"
}

# Hard timeout wrapper
# Run inside a fresh shell so we can `timeout` everything, but keep OUT_BASE initialization inside main().
run "diag10_wrapper" timeout "$HARD_TIMEOUT_SECS" bash -lc "$(declare -f log run run_quiet cleanup_enclaves collect_logs main); main" || true
