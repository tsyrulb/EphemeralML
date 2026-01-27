# EphemeralML — Investor Narrative (Draft)

## Elevator pitch
EphemeralML is a secure execution layer for AI: it lets companies run sensitive inference (and later training/fine‑tuning) on untrusted infrastructure without exposing prompts, customer data, or model IP—even to the cloud operator or EphemeralML itself. We use hardware‑backed trusted execution environments (AWS Nitro Enclaves) plus remote attestation and “key release only after verification” so encryption keys exist only inside an approved enclave image for a short time. The result is a practical way to deploy privacy‑preserving AI workloads that meet enterprise requirements while keeping performance close to standard cloud inference.

## Five key points
- Solves a real blocker for enterprise AI adoption: sensitive data + AI workloads require too much trust today.
- Hardware‑backed confidentiality by default: encrypted end‑to‑end; keys released only to attested enclaves.
- Simple integration: secure inference endpoint with standard APIs; minimal customer changes.
- Defensible moat: measurement allowlisting + key‑release policy + secure orchestration + operational know‑how.
- Clear path to revenue: secure inference for regulated industries, AI SaaS vendors, and enterprise ML platform teams.

## 1) The problem
AI is moving into sensitive workflows (health, finance, legal, internal code/data). This creates three trust problems:
1) Data confidentiality: decrypted-in-memory on servers controlled by vendors/operators.
2) Model/IP exposure: valuable weights/prompts can leak via privileged access or misconfig.
3) Compliance friction: enterprises need verifiable “no human access” controls and audit trails.

## 2) The solution: EphemeralML
Principle: **no secrets until attestation**.
- Enclave runtime for inference
- Remote attestation (measurement allowlist)
- KMS-backed key release gated on attestation + policy
- HPKE delivery to enclave public key
- Ephemeral sessions; minimal secret exposure

## 3) Architecture (simple)
Client → request → Enclave boots → attestation doc → verify → key release (KMS) → HPKE to enclave → inference → response.

## 4) Market & buyers
- Regulated enterprises (PHI/PII)
- AI SaaS vendors (enterprise sales)
- Internal ML platforms

## 5) Moat
- Attestation + allowlisting pipeline
- KMS-integrated key policies (rotation, revocation)
- Secure channel design (HPKE, replay resistance)
- Operational discipline + evidence package

## 6) Roadmap
- Phase 1: secure inference MVP
- Phase 2: enterprise readiness
- Phase 3: expansion (multi-model, RAG, multi-TEE)

## 7) Milestones
- M1 attestation verify + allowlisting
- M2 KMS-gated key release via HPKE
- M3 stable endpoint + SLOs
- M4 tenant-separated keys + rotation
- M5 external security review

## Architecture diagram (text)
```
Customer App/SDK → (TLS) → Control Plane (verify+policy)
                ↘                 ↘
                 Parent EC2 Host →  Key Release Service → AWS KMS
                       ↓
                 Nitro Enclave (inference; holds secrets)
                       ↓
                 Response → Customer
```

## Pitch deck visuals (suggested)
1. Problem slide (trust boundary)
2. Before/after diagram
3. Architecture diagram
4. Threat model (what we cover)
5. Use-case cards
6. Buyer & GTM
7. Moat
8. Roadmap
9. Benchmarks/SLOs
10. Security proof/audit plan
