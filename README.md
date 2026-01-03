[![Implementation Status](https://img.shields.io/badge/Status-Specification%20Complete-blue?style=for-the-badge)]()
[![Platform](https://img.shields.io/badge/Platform-AWS%20Nitro-orange?style=for-the-badge&logo=amazon-aws)]()
[![Language](https://img.shields.io/badge/Written%20in-Rust-b7410e?style=for-the-badge&logo=rust)]()
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)]()

# 🔒 EphemeralML: Confidential Inference Gateway

> **High-assurance confidential inference with verifiable execution receipts**  
> Run sensitive AI inference where model weights and prompts stay protected, even if the host is compromised.

EphemeralML is a **Confidential Inference Gateway** built on AWS Nitro Enclaves with:
- **Attestation-gated key release** + **HPKE encrypted sessions** + **audit receipts**
- **Host acts as blind relay** - cannot decrypt prompts, outputs, or model keys
- **Designed for regulated and high-assurance environments** (government clouds, defense contractors, critical infrastructure)

---

## 🎯 The Problem

Most "secure inference" systems still leave critical gaps:

- **Host Exposure**: The host can often see plaintext prompts or decrypted weights at some point in the pipeline
- **Transit ≠ Protection**: "Encryption in transit" doesn't prevent data exposure on compromised hosts  
- **No Proof**: Compliance teams need proof of what code processed an inference — not just logs
- **Circular Trust**: Key management is frequently enforced by the same environment you don't trust

**EphemeralML is built for the scenario that matters in high-assurance: assume the host is compromised — and still keep secrets protected.**

---

## 🛡️ What EphemeralML Protects

EphemeralML is a **Confidential Inference Gateway** that protects:

| **Model weights (IP)** | **User inputs/outputs (PII / classified)** | **Execution integrity (verified code)** |
|------------------------|---------------------------------------------|------------------------------------------|

It does this with a **two-part foundation**:
- **TEE isolation** (Nitro Enclave) for trusted operations
- **Attestation-bound cryptography** so secrets are released only to approved enclave measurements

---

## 🔄 How It Works (3 Steps)

### 1️⃣ Verify the enclave (Attestation)
The client verifies the enclave identity + code measurement against an allowlist.

### 2️⃣ Establish encrypted session (HPKE)  
All requests and responses are encrypted to the enclave. The host forwards ciphertext only.

### 3️⃣ Load models with gated keys (KMS)
Model keys are released only when KMS confirms the enclave measurement matches policy. The host never sees plaintext keys.

---

## ✅ Security Guarantees (v1)

### We guarantee:
- ✓ **Host blindness**: the host can relay traffic but cannot decrypt prompts, outputs, or model keys
- ✓ **Attestation-gated key release**: model DEKs are released only to approved enclave measurements  
- ✓ **Session binding**: encryption keys are bound to attestation + nonce to prevent key swapping
- ✓ **Anti-swap model integrity**: signed model manifests prevent serving a different model blob
- ✓ **Auditability**: each inference produces an Attested Execution Receipt (AER) clients can verify

### We explicitly do not claim (v1):
- × Protection against all microarchitectural side-channels
- × Availability guarantees (the host can DoS)
- × "Confidentiality under full enclave compromise"  
- × Multi-cloud / confidential GPU support

---

## 🏗️ Architecture

**Three-zone trust model:**

```
Client (Trusted) ↔ Host (Untrusted Relay) ↔ Enclave (Trusted Compute)
                        ↕
                    KMS/S3 (AWS)
```

- **Client Zone**: Verifies attestation, holds allowlists, establishes HPKE sessions
- **Host Zone**: Networking + storage + AWS API proxy; forwards ciphertext only  
- **Enclave Zone**: Decrypts data, loads models, runs inference, signs receipts

---

## 🧾 Attested Execution Receipts (AER)

Each inference can return an **AER** containing:
- Enclave measurements + attestation hash
- Request/response hashes  
- Policy version + security mode
- Monotonic sequence + signature

**This enables:**
- 📋 **Audit-ready evidence**
- 🔍 **Incident investigation** without storing plaintext prompts
- 🔐 **"What code processed this?"** answered cryptographically

---

## 👥 Who It's For

### Buyers / Owners
- Government cloud platform teams (high-assurance)
- Defense contractors running sensitive analytics
- Regulated enterprises (finance, health) protecting proprietary models and PII
- ML platform teams needing auditable, verifiable inference execution

### Users  
- ML engineers deploying protected inference endpoints
- Security teams enforcing key release policy + allowlists
- Compliance teams verifying AER receipts for audits and investigations

---

## 🎯 Use Cases

| Use Case | Description |
|----------|-------------|
| **Protected Model Serving** | Keep model weights encrypted at rest and decrypted only inside an attested enclave |
| **Sensitive Inference** | Prompts and outputs remain encrypted end-to-end to the enclave |
| **Auditable AI** | Attach a verifiable AER receipt to each inference for compliance and forensics |
| **Third-Party Providers** | Offer "trust but verify" inference without exposing customer data or model keys |
| **Policy-Controlled Deployments** | Rotate/revoke measurements and keys when code changes or enclave images are replaced |

---

## 🚀 Quick Start

### Current Status: Specification Complete ✅

The system is fully specified and ready for implementation:
- **14 comprehensive requirements** with detailed acceptance criteria
- **Complete architecture design** with 3-zone security model  
- **18-task implementation plan** with security validation tests

### Development Setup (Future)

```bash
# Local development with mock attestation
cargo build --features mock

# Terminal 1: Mock enclave (TCP mode)
cd enclave && cargo run --features mock

# Terminal 2: Host relay
cd host && cargo run --features mock  

# Terminal 3: Client
cd client && cargo run --features mock
```

### Production Deployment (Future)

```bash
# Build for AWS Nitro Enclaves
cargo build --release --features production --no-default-features

# Deploy EIF on Nitro-capable EC2 instance
# (See implementation plan for complete deployment procedures)
```

---

## 🛠️ Implementation Plan

### Phase 1: Cryptographic Core (Tasks 1-6)
- Attestation verification, HPKE sessions, receipt generation

### Phase 2: Communication (Tasks 7-12)  
- VSock transport, KMS integration, model loading

### Phase 3: Production (Tasks 13-18)
- Error handling, logging, deployment validation

**Testing Strategy**: 29 property tests for security validation + unit tests + integration tests

---

## 🗺️ Roadmap

### V1 (Gateway) - Current Focus
- ✓ Attestation + HPKE E2E sessions
- ✓ KMS-gated key release  
- ✓ AER receipts
- ✓ Model integrity manifests

### V2 (Shield Mode) - Future
- Leakage-resilient inference under defined partial-compromise scenarios
- Performance controls  
- Expanded deployment targets

---

## ☁️ Deployment & Integration

- **AWS Nitro Enclaves** for v1 deployment
- **KMS attestation-bound policy** for key release
- **S3 encrypted artifacts** with signed manifests
- **Mock mode support** for local development  
- **Gov cloud ready**: Strict trust boundaries, deny-by-default policies, verifiable execution evidence

---

## ❓ FAQ

**Q: Can the host read prompts or outputs?**  
A: No. The host relays ciphertext only; decryption occurs inside the enclave.

**Q: What stops the host from decrypting model keys?**  
A: KMS policy binds decrypt authorization to enclave measurements; without valid attestation, decrypt is denied.

**Q: Is this a full defense against side-channels?**  
A: No. V1 documents residual side-channel risk; mitigations are limited and explicit.

**Q: Do you provide SLA / high availability?**  
A: Not in v1. The goal is correctness and assurance first.

**Q: Do you support confidential GPU?**  
A: Not in v1. This is future scope.

---

## 📞 Contact

**Request a Pilot**: If you deploy AI in a high-assurance environment and need verifiable confidentiality, EphemeralML is built for you.

- 📧 **Email**: [contact@cyntrisec.com](mailto:contact@cyntrisec.com)
- 🔗 **Repository**: [github.com/tsyrulb/EphemeralML](https://github.com/tsyrulb/EphemeralML)

---

## 📄 License

MIT License - see `LICENSE` file for details.

---

<div align="center">

**🔒 Confidential inference with cryptographic proof**  
**🛡️ Run inference like the host is already hacked**  
**🔐 Attestation-gated model access + end-to-end encrypted prompts**

*Specification Complete - Implementation Ready*

</div>