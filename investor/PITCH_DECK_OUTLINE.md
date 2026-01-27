# EphemeralML — 10‑slide Pitch Deck Outline (Draft)

1. **Title** — EphemeralML: Confidential AI Compute
   - Tagline: “Run sensitive inference without expanding your trust boundary.”

2. **Problem** — AI adoption is blocked by trust
   - Data is decrypted in memory on infrastructure you don’t control
   - Compliance & procurement delays

3. **Why now**
   - AI in sensitive workflows + regulatory pressure
   - TEEs now practical in major clouds

4. **Solution** — No secrets until attestation
   - Hardware-backed enclaves + verifiable key release

5. **How it works (architecture)**
   - Client → Control Plane verify → KMS-gated key release → HPKE to enclave → inference

6. **Threat model (simple)**
   - Protects against: cloud admin access, host compromise, misconfig/log leakage
   - Doesn’t protect against: client compromise, malicious user inputs beyond model controls

7. **Product**
   - Secure inference endpoint, SDK, policy controls, evidence package

8. **Market & buyers**
   - Regulated industries; AI SaaS; enterprise ML platforms

9. **Moat**
   - Attestation allowlisting pipeline + key-release policy + operational excellence

10. **Roadmap & milestones**
   - MVP → enterprise readiness → expansion; define measurable milestones
