# EphemeralML — One‑pager (Draft)

## What it is
**Confidential Inference Gateway** for running AI on untrusted cloud infrastructure while keeping **prompts, customer data, and model weights** confidential.

## Why it matters
Enterprise AI adoption is blocked by trust: encryption “at rest/in transit” isn’t enough because data is decrypted in memory during compute. Compliance teams also need verifiable controls (“even admins can’t access plaintext”).

## How it works (plain language)
We run the model inside an **AWS Nitro Enclave** (a hardware‑isolated environment). Before any secrets are provided, the enclave proves what code it’s running via **remote attestation**. Only then do we release decryption keys—using **KMS policies**—and deliver them to the enclave via **HPKE**, so only the enclave can decrypt.

## Key benefits
- Data confidentiality even if the host OS is compromised
- Reduced vendor/insider risk
- Faster enterprise security reviews via verifiable evidence

## Target customers
Healthcare/finance/legal enterprises; AI SaaS vendors selling to enterprises; internal ML platform teams.

## Near-term roadmap
Secure inference MVP → enterprise readiness (tenant isolation, audit/evidence) → expansion (RAG pipelines, multi-TEE).
