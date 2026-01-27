# KMS + Nitro Enclaves debug notes (2026-01-27)

This document captures the bugs we hit while wiring **Nitro Enclaves ↔ Host proxy ↔ AWS KMS** and how each was resolved.

## Final outcome
We achieved an end-to-end flow:
- Enclave boots reliably (PID1 wrapper `/init`).
- Enclave connects to host `kms_proxy_host` over **AF_VSOCK**.
- Host proxy calls **AWS KMS** `GenerateDataKey` and `Decrypt`.
- `Decrypt` succeeds with `RecipientInfo` (attestation-bound) and the enclave receives **`ciphertext_for_recipient`** (wrapped key).

## Environment
- Region: `us-east-1`
- Host OS: Amazon Linux 2023
- Nitro CLI: `1.4.4`
- Instance type: `m6i.xlarge`

## Bugs & fixes

### 1) Nitro packaging: enclave reboots immediately
**Symptom**: enclave reboots ~0.17s, no app logs.

**Fix**: in enclave Docker image, use explicit PID1 wrapper:
- `ENTRYPOINT ["/init"]`
- `/init` must `exec` the binary (and log to `/dev/console`).

Ref: also summarized in `HANDOFF.md`.

---

### 2) AL2023 packages: allocator package missing
**Symptom**: user-data attempted to install `aws-nitro-enclaves-allocator` and failed; `nitro-cli` missing.

**Fix** (AL2023): install only packages that exist:
- `aws-nitro-enclaves-cli`
- `aws-nitro-enclaves-cli-devel`

Allocator/vsock-proxy services are provided by the CLI package.

---

### 3) `nitro-cli build-enclave` E51: artifacts path env var not set
**Symptom**:
- `E51 Artifacts path environment variable not set`

**Fix**:
Set either:
- `HOME=/root`, or
- `NITRO_CLI_ARTIFACTS=/tmp/nitro-cli-artifacts`

We used:
```bash
export HOME=/root
export NITRO_CLI_ARTIFACTS=/tmp/nitro-cli-artifacts
mkdir -p "$NITRO_CLI_ARTIFACTS"
```

---

### 4) Rust toolchain issues on host
**Symptoms**:
- `cargo`/`rustc` missing under `sudo` (PATH reset)
- build error: `linker 'cc' not found`

**Fix**:
- Install build tools: `dnf install -y gcc gcc-c++ make`
- Ensure env when using rustup under `set -u`:
  - `export HOME=/root; export CARGO_HOME=/root/.cargo; export RUSTUP_HOME=/root/.rustup`
  - `source /root/.cargo/env`

---

### 5) SSM inline payload truncation (AWS-RunShellScript size limits)
**Symptom**: SSM output repeatedly stopped mid-script (looked like it "ended" at `build_kms_proxy_host`).

**Fix**: in `run_diag10_cycle.sh`, send `ssm_diag10.sh` as base64 chunks and reconstruct on the instance before executing.

---

### 6) Host build breaks due to aws-sdk-kms API changes
**Symptoms**:
- `decrypt().recipient(...)` expected `RecipientInfo`, but we passed `Blob`.

**Fix**:
Use:
```rust
.recipient(aws_sdk_kms::types::RecipientInfo::builder()
  .attestation_document(Blob::new(attestation_doc))
  .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
  .build())
```

---

### 7) KMS GenerateDataKey validation error
**Symptom**:
- `ValidationException: Please specify either number of bytes or key spec.`

**Fix**:
Pass `key_spec` (AES_256/AES_128) or `number_of_bytes`. We map the wire `key_spec` string into `DataKeySpec`.

---

### 8) KMS Decrypt validation errors (RecipientInfo flow)
We hit errors in sequence; each change advanced us to the next layer:

1) **"You must specify an encryption algorithm in this request."**
   - Fix: set `.encryption_algorithm(EncryptionAlgorithmSpec::SymmetricDefault)`.

2) **"You must specify a recipient public key in this request."**
   - Root cause: attestation doc had no KMS-usable public key.
   - Fix: enclave must include public key in the NSM attestation request.

3) **"Invalid public key"**
   - Root cause: wrong public key encoding.
   - Fix: provide RSA public key as **SPKI/PKCS#8 DER** (not PKCS#1 DER).

After (3), we got:
- `SUCCESS: received wrapped key from KMS`

---

### 9) CPU pool exhaustion (nitro-cli E29/E39 / “no CPUs available in pool”)
**Symptom**: `Run Enclave` fails when CPUs remain allocated by a previous enclave.

**Fix**:
- terminate old enclaves before running a new one:
  - `nitro-cli describe-enclaves` → `nitro-cli terminate-enclave --enclave-id ...`
- ensure allocator is configured and started.

## Practical checklist for future runs
1) Ensure Nitro packages installed (AL2023): `aws-nitro-enclaves-cli` + `-devel`.
2) Set `HOME=/root` and `NITRO_CLI_ARTIFACTS=...` before `nitro-cli build-enclave`.
3) Ensure allocator resources are reserved and old enclaves terminated.
4) Host build: install `gcc gcc-c++ make`; use stable Rust (>= deps MSRV).
5) KMS attestation-bound decrypt:
   - RecipientInfo: set `key_encryption_algorithm=RSAES_OAEP_SHA_256`.
   - Enclave attestation: embed **SPKI DER** RSA public key.
   - Decrypt request: include `encryption_algorithm=SYMMETRIC_DEFAULT`.

