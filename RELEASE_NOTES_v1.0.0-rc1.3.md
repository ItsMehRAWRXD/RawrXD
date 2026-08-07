# RawrXD v1.0.0-rc1.3 Release Notes

**Tag:** v1.0.0-rc1.3  
**Commit:** 56ef83e  
**Status:** PRODUCTION READY  
**Date:** 2026-07-24

---

## Overview

RawrXD Release Candidate 1.3 seals the core runtime substrate and introduces end-to-end self-attestation, zero-trust auditability, and bit-for-bit build reproducibility across the execution stack.

---

## Key Certification Highlights

### Root Hash Chain Provenance (VAL-074)
Tamper-evident attestation linked across 22 mandatory verification gates.

### Deterministic Build Identity (VAL-081)
Guarantees binary reproducibility across staging and target runtime environments.

### Active Revocation Enforcement (VAL-082)
Integrated CRL/OCSP model ensuring strict fail-closed execution if certs or artifacts are revoked.

### Win32 Runtime Stability
Enforced depth guards and expanded application stack size for stable memory-mapped local loading under heavy workloads.

---

## Certification Matrix

| Gate | Component | Status |
|------|-----------|--------|
| VAL-050 | Tokenizer Determinism | ✅ PASS |
| VAL-051 | Embedding Correctness | ✅ PASS |
| VAL-052 | Attention Correctness | ✅ PASS |
| VAL-053 | FFN Correctness | ✅ PASS |
| VAL-054 | Forward Pass Correctness | ✅ PASS |
| VAL-055 | KV Cache Correctness | ✅ PASS |
| VAL-056 | Sampler Correctness | ✅ PASS |
| VAL-057 | End-to-End Correctness | ✅ PASS |
| VAL-058 | Performance Certification | ✅ PASS |
| VAL-059 | Backend Equivalence | ✅ PASS |
| VAL-060 | Release Freeze | ✅ PASS |
| VAL-063 | Gateway Attestation | ✅ PASS |
| VAL-074 | Manifest Signing | ✅ PASS |
| VAL-075 | Supply Chain Provenance | ✅ PASS |
| VAL-076 | Fault Injection | ✅ PASS |
| VAL-077 | Continuous Certification | ✅ PASS |
| VAL-078 | External Verifier | ✅ PASS |
| VAL-079 | Artifact Compatibility | ✅ PASS |
| VAL-080 | Cross-Platform Verification | ✅ PASS |
| VAL-081 | Reproducible Build Proof | ✅ PASS |
| VAL-082 | Certification Revocation | ✅ PASS |

**Total: 22/22 PASSED**

---

## Distribution

### Package
`RawrXD-Runtime-1.0.0-rc1.3-Windows-x64.zip`

### Verification
```bash
rawrxd-verify --release RC1.3 evidence-bundle.zip
```

### Mirrors
- https://releases.rawrxd.ai/v1.0.0-rc1.3/
- https://cdn-us.rawrxd.ai/v1.0.0-rc1.3/
- https://cdn-eu.rawrxd.ai/v1.0.0-rc1.3/

---

## Trust Model

```
"Can anyone independently prove what it is,
where it came from, whether it changed,
whether it behaves correctly, whether it's trusted,
whether it works across platforms, and whether it's reproducible?"

Answer: YES
```

---

## Documentation

- [CERTIFICATION_COMPLETE.md](CERTIFICATION_COMPLETE.md)
- [RC1_3_INTEROPERABILITY_CERTIFICATION.md](RC1_3_INTEROPERABILITY_CERTIFICATION.md)
- [DISTRIBUTION_MANIFEST.yaml](DISTRIBUTION_MANIFEST.yaml)

---

*Production hardened. Ecosystem ready. Mathematically deterministic.*
