[![Implementation Status](https://img.shields.io/badge/Status-Specification%20Complete-blue?style=for-the-badge)]()
[![Platform](https://img.shields.io/badge/Platform-AWS%20Nitro-orange?style=for-the-badge&logo=amazon-aws)]()
[![Language](https://img.shields.io/badge/Written%20in-Rust-b7410e?style=for-the-badge&logo=rust)]()
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)]()

# 🔒 EphemeralML: Confidential Inference Gateway

> **Attested. Encrypted end-to-end. Evidence-producing.**  
> EphemeralML is a **confidential inference gateway** for protecting **model weights and sensitive inputs** through defense-in-depth security architecture.

EphemeralML implements a two-layer security strategy:

- **Layer 1 — Gateway (v1 Implementation):**  
  **TEE isolation + attestation-gated key release + HPKE encrypted sessions** where the **host acts as a blind relay**.
- **Layer 2 — Shield Mode (Future v2):**  
  **Leakage-resilient inference**: structured obfuscation to make captured weights not directly usable under defined partial-compromise scenarios.

> ⚠️ EphemeralML provides **explicit guarantees under explicit assumptions**, with comprehensive documentation of limitations and threat model boundaries.

---

## 🎯 Why EphemeralML?

### The Problem
Traditional inference deployments expose valuable assets to execution environments:
- **Model IP exposure:** weights are present where admins/operators/host compromise may access them
- **Sensitive prompt/data exposure:** inputs may be visible to the host stack
- **No audit-grade evidence:** teams cannot prove which code actually processed sensitive inference

### Our Approach
EphemeralML implements a **defense-in-depth** confidential inference architecture:

- 🔐 **Attestation-Bound Secure Sessions**  
  The client verifies TEE measurements and establishes **HPKE encrypted sessions** bound to the enclave's cryptographic identity.
- 🔑 **Attestation-Gated Key Release**  
  Decryption keys for models are released only to **approved enclave measurements** via AWS KMS policies.
- 🧾 **Attested Execution Receipts (AER)**  
  Every inference generates cryptographic evidence (measurements, request hash, timestamp, signature).
- 🛡️ **Shield Mode (Future v2)**  
  Structured weight obfuscation to reduce direct usability of captured weights in partial boundary failures.

---

## 🏗️ Architecture (Host = Blind Relay, TEE = Trust Domain)

```mermaid
graph TB
    subgraph "Client Zone (Trusted)"
        C[Client Application]
        V[Attestation Verifier]
        E2E[HPKE Session Manager]
        AL[Measurement Allowlist]
        C --> V --> E2E
        V --> AL
    end
    
    subgraph "Host Zone (Untrusted Relay)"
        HP[Host Proxy]
        VP[VSock Proxy]
        KP[KMS Proxy]
        S3P[S3 Proxy]
        S3[Encrypted Model Storage]
        HP --> VP
        HP --> KP --> AWS_KMS[AWS KMS]
        HP --> S3P --> S3
    end
    
    subgraph "Enclave Zone (Trusted Compute)"
        NSM[Nitro Security Module]
        AD[Attestation Document Generator]
        KMS[KMS Client via VSock]
        SM[Session Manager]
        ML[Model Loader]
        IE[Inference Engine]
        AER[Receipt Generator]
        
        NSM --> AD
        AD --> SM
        KMS --> ML
        ML --> IE
        IE --> AER
    end

    %% Flow
    C -.->|1) Attestation Challenge + Nonce| AD
    AD -.->|2) Attestation Doc + Ephemeral Keys| V
    E2E -.->|3) HPKE Encrypted Payload| VP
    VP -.->|4) VSock| SM
    KP -.->|5) Encrypted DEKs & Models| HP
    HP -.->|6) Stream Ciphertext| VP
    AER -.->|7) Signed Receipt| C

    style NSM fill:#ff6b6b
    style C fill:#4ecdc4
    style HP fill:#45b7d1
```

### Component Roles

* **Client Zone (Trusted):**
  * Verifies attestation documents against AWS Nitro roots and measurement allowlists
  * Establishes HPKE encrypted sessions bound to attested ephemeral keys
  * Encrypts sensitive payloads end-to-end to enclave
  * Verifies AER receipts using Ed25519 signatures

* **Host Zone (Untrusted Relay):**
  * Provides networking, storage I/O, and AWS API proxy services
  * **Must never see plaintext** model weights, DEKs, or user inputs
  * Forwards encrypted payloads via VSock without inspection
  * Can DoS (availability is not guaranteed)

* **Enclave Zone (Trusted Compute):**
  * Generates attestation documents with ephemeral public keys
  * Decrypts models using attestation-gated KMS DEKs
  * Executes inference within hardware-isolated boundary
  * Generates signed execution receipts for audit trails

---

## 🔥 What's New vs "TEE wrapper" Projects

✅ **Host is a ciphertext-only blind relay** (not "semi-trusted").  
✅ **Key release is cryptographically bound to attestation** (KMS policy enforcement).  
✅ **HPKE sessions bound to ephemeral keys** in attestation user data.  
✅ **Evidence is first-class** (AER receipts with Ed25519 signatures per inference).  
✅ **Comprehensive specification** (14 requirements, 18-task implementation plan, 29 property tests).  
✅ **Shield Mode architecture** ready for v2 leakage-resilient inference.

---

## 🛡️ Security Model (Concise)

### Threat Model (v1)

**In scope:**
* Malicious/curious host OS and administrators
* Tampering with deployment artifacts (blocked via attestation allowlists)
* Replay attempts (blocked via nonce-based freshness challenges)
* Partial boundary failures where memory scraping becomes feasible (Shield Mode v2 target)

**Out of scope (v1):**
* Black-box distillation via repeated queries (rate limits, monitoring, watermarking)
* Complete protection from microarchitectural side-channels
* Availability guarantees (host can DoS)

### Guarantees (v1)

* **G1:** Host cannot read user payload plaintext (HPKE E2E encryption)
* **G2:** Host cannot read model weights plaintext (attestation-gated KMS DEK release)
* **G3:** Client can verify enclave code identity before releasing secrets (attestation verification)
* **G4:** Each inference produces cryptographically signed Attested Execution Receipt (AER)

### Shield Mode (v2)

* **G5 (future):** Captured weights are not directly usable without session secrets/masking factors

> Full threat model, assumptions (A1-A26), and misuse cases (MC-01 to MC-15) documented in `appendix/`.

---

## 🚀 Quick Start

### Implementation Status

**Current Status:** ✅ **Specification Complete** - Ready for implementation

The system is fully specified with:
- **14 comprehensive requirements** with detailed acceptance criteria
- **Complete architecture design** with Layer 1 (Gateway) + Layer 2 (Shield Mode) security
- **18-task implementation plan** with 29 property tests for security validation
- **AWS Nitro Enclaves integration** approach with VSock and KMS attestation-bound policies

### Begin Implementation

To start building the system:

```bash
# 1. Review the complete specification
ls .kiro/specs/confidential-inference-gateway/
# requirements.md - 14 detailed requirements with acceptance criteria
# design.md - complete architecture with 3-zone security model
# tasks.md - 18-task implementation plan with property tests

# 2. Start with Task 1: Set up project structure
# Open .kiro/specs/confidential-inference-gateway/tasks.md
# Follow the incremental 18-task implementation plan
```

### Future: Development Mode (Post-Implementation)

Once implemented, local development with mock transport:

```bash
cargo build --features mock

# Terminal 1: mock enclave (TCP mode)
cd enclave && cargo run --features mock

# Terminal 2: host relay  
cd host && cargo run --features mock

# Terminal 3: client
cd client && cargo run --features mock
```

### Future: Production Mode (Post-Implementation)

Once implemented, deploy on AWS Nitro Enclaves:

```bash
# Build production artifacts
cargo build --release --features production --no-default-features

# Deploy EIF on Nitro-capable EC2 instance
# See tasks 19.1-19.2 for complete deployment procedures
```

---

## 📁 Project Structure

```
EphemeralML/
├── .kiro/specs/confidential-inference-gateway/
│   ├── requirements.md     # 14 comprehensive requirements with acceptance criteria
│   ├── design.md          # complete 3-zone architecture (Client/Host/Enclave)
│   └── tasks.md           # 18-task implementation plan with 29 property tests
├── appendix/
│   ├── AppendixA.md       # explicit assumptions (A1-A26)
│   ├── AppendixB.md       # assumption-to-guarantee mapping
│   └── AppendixC.md       # misuse cases (MC-01 to MC-15)
├── client/                # [TO BE IMPLEMENTED] attestation verifier + HPKE sessions
├── host/                  # [TO BE IMPLEMENTED] blind relay + VSock proxy + AWS API mediation
├── enclave/               # [TO BE IMPLEMENTED] trusted runtime (NSM, KMS, inference, receipts)
├── common/                # [TO BE IMPLEMENTED] shared protocol types and crypto primitives
└── tests/                 # [TO BE IMPLEMENTED] integration and property tests (29 tests planned)
```

---

## 🧪 Testing

**Implementation Status:** Comprehensive testing strategy specified

The implementation plan includes:
- **29 Property Tests** for security-critical components and universal correctness properties
- **Unit Tests** for specific examples, edge cases, and integration points  
- **Integration Tests** for end-to-end workflows and security boundary enforcement
- **Performance Benchmarks** for v1 model scope (embedding models, small classifiers)

Once implemented:
```bash
cargo test                         # Run all tests
cargo test --features mock        # Run with mock attestation (local dev)
cargo test --features production  # Run with real Nitro attestation
cargo test property_               # Run property tests only
```

### Key Property Tests (Planned)
- **Property 1:** Attestation Verification Integrity
- **Property 2:** HPKE Session Binding to Attestation  
- **Property 6:** Host Blindness to Sensitive Data
- **Property 10:** Comprehensive Receipt Generation and Verification
- **Property 11:** Session Isolation and Lifecycle Management

---

## 🔧 Feature Flags

* `mock` (default): Local development with TCP transport + mock attestation documents
* `production`: VSock transport + real AWS Nitro attestation flows for production deployment
* `shield_mode` (planned v2): Enables LRCI primitives and leakage-resilient inference benchmarks

---

## 📚 Documentation

### Specification (Complete)
* `.kiro/specs/confidential-inference-gateway/requirements.md` — 14 comprehensive requirements with detailed acceptance criteria
* `.kiro/specs/confidential-inference-gateway/design.md` — complete 3-zone architecture with HPKE sessions, VSock communication, and KMS integration
* `.kiro/specs/confidential-inference-gateway/tasks.md` — 18-task incremental implementation plan with 29 property tests

### Security Analysis (Complete)
* `appendix/AppendixA.md` — explicit assumptions (A1-A26: what must be true for guarantees to hold)
* `appendix/AppendixB.md` — assumption-to-guarantee mapping (what breaks what)
* `appendix/AppendixC.md` — misuse cases (MC-01 to MC-15: common wrong deployments and why they fail)

### Research Context
* `appendix/scientific-grounding.md` — related work and research papers
* `appendix/open-source-shortlist.md` — relevant open source projects

---

## 🔗 Related Work & Inspiration

EphemeralML is informed by confidential inference system designs and model-protection research.
See `appendix/scientific-grounding.md` for a curated list of papers (LoRO, TEESlice, NNSplitter, Slalom, Glamdring, etc.).

---

## 🤝 Community & Feedback

**Current Phase:** **Specification Complete** - Ready for implementation

We welcome feedback on the specification and implementation approach:

* 📋 **Specification Review**: Review `.kiro/specs/confidential-inference-gateway/` for technical feedback on requirements, design, and implementation plan
* 🔐 **Security Analysis**: Review `appendix/` for security model, assumptions, and threat analysis feedback
* 🐛 **Implementation Issues**: Open issues as implementation progresses following the 18-task plan
* 📧 **Private Security Reports**: [security@ephemeralml.com](mailto:security@ephemeralml.com)

**Implementation Roadmap:**
1. **Phase 1 (Tasks 1-6):** Core cryptographic functionality (attestation, HPKE, receipts)
2. **Phase 2 (Tasks 7-12):** Communication and model loading (VSock, KMS, inference)
3. **Phase 3 (Tasks 13-18):** Production hardening (error handling, logging, deployment)
4. **Phase 4 (v2):** Shield Mode leakage-resilient inference

---

## 📄 License

MIT. See `LICENSE`.

---

<div align="center">

**🔒 Attested Execution • 🧾 Evidence Receipts • 🛡️ Defense-in-Depth Confidential AI**

*Specification Complete - Implementation Ready*

</div>