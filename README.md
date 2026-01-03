[![Build Status](https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge&logo=github)]()
[![Platform](https://img.shields.io/badge/Platform-AWS%20Nitro-orange?style=for-the-badge&logo=amazon-aws)]()
[![Language](https://img.shields.io/badge/Written%20in-Rust-b7410e?style=for-the-badge&logo=rust)]()
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)]()

# 🔒 EphemeralML: Confidential Inference with Defense-in-Depth

> **Attested. Encrypted end-to-end. Evidence-producing.**  
> EphemeralML is a **confidential inference control plane** for protecting **model weights and sensitive inputs** in hostile or multi-tenant environments.

EphemeralML is built around a two-layer security strategy:

- **Layer 1 — Paranoid Gateway (Core Product):**  
  **TEE isolation + attestation-gated key release + end-to-end encrypted sessions** where the **host is a ciphertext-only relay**.
- **Layer 2 — Shield Mode (LRCI / Moat):**  
  **Leakage-resilient inference**: optional obfuscation to make captured weights **not directly usable** under defined partial-compromise attacker models.

> ⚠️ EphemeralML does not claim "perfect security." It provides **explicit guarantees under explicit assumptions**, with documented limitations and misuse cases.

---

## 🎯 Why EphemeralML?

### The Problem
Traditional inference deployments expose valuable assets to execution environments:
- **Model IP exposure:** weights are present where admins/operators/host compromise may access them
- **Sensitive prompt/data exposure:** inputs may be visible to the host stack
- **No audit-grade evidence:** teams cannot prove which code actually processed sensitive inference

### Our Approach
EphemeralML productizes a **defense-in-depth** confidential inference architecture:

- 🔐 **Attestation-Bound Secure Sessions**  
  The client verifies a TEE measurement and establishes an **end-to-end encrypted session** bound to the enclave's cryptographic identity.
- 🔑 **Attestation-Gated Key Release**  
  Decryption keys for weights/data are released only to **approved enclave measurements**.
- 🧾 **Attested Execution Receipts (AERs)**  
  Every inference can emit an evidence artifact (measurement/build id, policy id, request hash, timestamp, nonce).
- 🛡️ **Shield Mode (Optional Premium Tier)**  
  Structured weight obfuscation to reduce direct usability of captured weights in partial boundary failures.

---

## 🏗️ Architecture (Host = Blind Relay, TEE = Trust Domain)

```mermaid
graph TB
    subgraph "Client (Verifier)"
        C[Client]
        V[Attestation Verifier]
        S[E2E Session (Noise/HPKE-like)]
        C --> V --> S
    end
    
    subgraph "Untrusted Host (Relay/Orchestrator)"
        H[Host Relay]
        P[VSock Proxy / Transport]
        K[AWS API Access (KMS/S3)]
        H --> P
        H --> K
    end
    
    subgraph "Trusted Domain (AWS Nitro Enclave)"
        E[Enclave Runtime]
        A[Attestation Doc Generator]
        D[Decrypt & Policy Gate]
        M[Model Loader/Runtime]
        R[AER Receipt Generator]
        E --> A
        E --> D --> M --> R
    end

    %% Flow
    C -.->|1) Attestation Challenge| A
    A -.->|2) Attestation Doc| V
    S -.->|3) Ciphertext-only payload| P
    P -.->|4) VSock| E
    K -.->|5) Encrypted weights & wrapped keys| H
    H -.->|6) Stream ciphertext| P
    R -.->|7) Receipt (hashes, measurements)| C

    style E fill:#ff6b6b
    style C fill:#4ecdc4
    style H fill:#45b7d1
```

### Component Roles

* **Client (Verifier):**

  * verifies attestation + allowlist
  * establishes an attestation-bound secure session
  * encrypts sensitive payloads end-to-end
  * verifies AER receipts

* **Host (Untrusted Relay):**

  * networking + storage I/O + AWS API calls
  * **must never see plaintext** model weights or prompts
  * can DoS (availability is not guaranteed)

* **Enclave (Trusted Compute):**

  * holds plaintext secrets only within the trusted boundary
  * enforces policy for key release
  * runs inference and emits receipts

---

## 🔥 What's New vs "TEE wrapper" Projects

✅ **Host is a ciphertext-only blind relay** (not "semi-trusted").
✅ **Key release is gated by attestation policy** (measurement allowlist).
✅ **Evidence is first-class** (AER receipts per inference).
✅ **Shield Mode** adds defense-in-depth when hardware boundaries degrade.

---

## 🛡️ Security Model (Concise)

### Threat Model (v1)

**In scope:**

* malicious/curious host OS and administrators
* tampering with deployment artifacts (blocked via attestation allowlists)
* replay attempts (blocked via freshness challenges)
* partial boundary failures where memory scraping becomes feasible (Shield Mode target)

**Out of scope (v1):**

* black-box distillation via repeated queries (handled via rate limits, monitoring, watermarking)

### Guarantees (v1)

* **G1:** Host cannot read user payload plaintext (E2E session)
* **G2:** Host cannot read model weights plaintext (attestation-gated key release)
* **G4/G5:** Client can verify code identity before releasing secrets
* **G6:** Each inference can produce an Attested Execution Receipt (AER)

### Shield Mode (LRCI) guarantee (v1)

* **G7 (defined attacker model):** Captured weights are **not directly usable** without session secrets / masking factors.

> Full threat model, assumptions, limitations, and misuse cases live in `appendix/`.

---

## 🚀 Quick Start

### Implementation Status

**Current Status:** ✅ **Specification Complete** - Ready for implementation

The system is fully specified with:
- 14 comprehensive requirements with acceptance criteria
- Complete architecture design with Layer 1 (Gateway) + Layer 2 (Shield Mode)
- 18-task implementation plan with 29 property tests
- AWS Nitro Enclaves integration approach

### Begin Implementation

To start building the system:

```bash
# 1. Review the complete specification
ls .kiro/specs/confidential-inference-gateway/
# requirements.md - 14 detailed requirements
# design.md - complete architecture 
# tasks.md - 18-task implementation plan

# 2. Start with Task 1: Set up project structure
# Open .kiro/specs/confidential-inference-gateway/tasks.md
# Click "Start task" next to Task 1
```

### Future: Development Mode (Post-Implementation)

Once implemented, local development with mock transport:

```bash
cargo build

# Terminal 1: mock enclave
cd enclave && cargo run

# Terminal 2: host relay  
cd host && cargo run

# Terminal 3: client
cd client && cargo run
```

### Future: Production Mode (Post-Implementation)

Once implemented, deploy on AWS Nitro Enclaves:

```bash
# Build production artifacts
cargo build --release --features production --no-default-features

# Deploy EIF on Nitro-capable EC2 instance
# See implementation tasks 17.1-17.2 for deployment details
```

---

## 📁 Project Structure

```
EphemeralML/
├── .kiro/specs/confidential-inference-gateway/
│   ├── requirements.md     # 14 comprehensive requirements with acceptance criteria
│   ├── design.md          # complete architecture design (Layer 1 + Layer 2)
│   └── tasks.md           # 18-task implementation plan with property tests
├── appendix/
│   ├── AppendixA.md       # explicit assumptions (A1-A26)
│   ├── AppendixB.md       # assumption-to-guarantee mapping
│   └── AppendixC.md       # misuse cases (MC-01 to MC-15)
├── client/                # [TO BE IMPLEMENTED] verifier + E2E encryption + protocol
├── host/                  # [TO BE IMPLEMENTED] untrusted relay + vsock proxy + AWS I/O
├── enclave/               # [TO BE IMPLEMENTED] trusted runtime (attestation, decrypt, inference)
├── common/                # [TO BE IMPLEMENTED] shared protocol/types
└── tests/                 # [TO BE IMPLEMENTED] integration and property tests
```

---

## 🧪 Testing

**Implementation Status:** Specification includes comprehensive testing strategy

The implementation plan includes:
- **29 Property Tests** for security-critical components
- **Unit Tests** for specific examples and edge cases  
- **Integration Tests** for end-to-end workflows
- **Performance Benchmarks** for v1 model scope

Once implemented:
```bash
cargo test                    # Run all tests
cargo test --features mock    # Run with mock attestation
cargo test --features production  # Run with real Nitro attestation
```

---

## 🔧 Feature Flags

* `mock` (default): Local dev with TCP + mock attestation
* `production`: VSock + real attestation flows for Nitro Enclaves
* `shield_mode` (planned): Enables LRCI primitives and benchmarks

---

## 📚 Documentation

### Specification (Complete)
* `.kiro/specs/confidential-inference-gateway/requirements.md` — 14 comprehensive requirements with acceptance criteria
* `.kiro/specs/confidential-inference-gateway/design.md` — complete architecture design with Layer 1 + Layer 2 security
* `.kiro/specs/confidential-inference-gateway/tasks.md` — 18-task implementation plan with 29 property tests

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

* 📋 **Specification Review**: Review `.kiro/specs/confidential-inference-gateway/` for technical feedback
* 🐛 **Implementation Issues**: Open issues as implementation progresses  
* 🔐 **Security Analysis**: Review `appendix/` for security model feedback
* 📧 **Private Security Reports**: [security@cyntrisec.com](mailto:security@cyntrisec.com)

**Next Steps:**
1. Begin implementation with Task 1 in `tasks.md`
2. Follow the 18-task incremental plan
3. Implement 29 property tests for security validation

---

## 📄 License

MIT. See `LICENSE`.

---

<div align="center">

**🔒 Attested Execution • 🧾 Evidence Receipts • 🛡️ Defense-in-Depth Confidential AI**

</div>