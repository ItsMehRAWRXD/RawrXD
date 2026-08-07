# RawrXD v1.0.0-rc1.3 Staging Rollout Checklist

**Release:** RawrXD-Runtime-1.0.0-rc1.3-Windows-x64  
**Commit:** 56ef83e  
**Date:** 2026-07-24  
**Status:** PRODUCTION READY

---

## Stage 1 - Pre-flight

- [ ] Download RawrXD-Runtime-1.0.0-rc1.3-Windows-x64 to isolated staging mirrors
- [ ] Verify checksums against the distribution manifest
- [ ] Run local hash chain verification

**Verification Command:**
```bash
sha256sum -c DISTRIBUTION_MANIFEST.yaml
cat evidence/EVIDENCE_MANIFEST.json | jq '.root_hash'
```

---

## Stage 2 - Verification

- [ ] Execute `rawrxd-verify --release RC1.3 evidence-bundle.zip` on target staging hardware
- [ ] Confirm all 9 identity and platform checks return PASS with zero warnings

**Expected Output:**
```
CERTIFIED
identity:    PASS
runtime:     PASS
evidence:    PASS
replay:      PASS
signature:   PASS
provenance:  PASS
compatibility: PASS
cross-platform: PASS
revocation:  NOT REVOKED
```

---

## Stage 3 - Isolation Test

- [ ] Spin up canary instances using local GGUF memory-mapped loading routines
- [ ] Monitor initial stack depth allocation
- [ ] Verify Win32 window creation guards
- [ ] Check memory mapped regions

**Metrics to Monitor:**
- Stack depth overhead < 75%
- GGUF memory-map latency < 150ms
- Zero unhandled traps

---

## Stage 4 - Zero-Trust Drill

- [ ] Test active CRL/OCSP lookup paths (VAL-082) against canary endpoints
- [ ] Confirm automatic execution halting on signature invalidation
- [ ] Verify revocation signal handling

**Test Scenarios:**
1. Valid certificate → execution allowed
2. Revoked certificate → execution blocked
3. Unreachable CRL → fail-closed

---

## Stage 5 - Deployment

- [ ] Promote canary runtime artifacts to production CDN nodes
- [ ] Initiate global distribution sync
- [ ] Verify CDN propagation
- [ ] Monitor download integrity

**CDN Endpoints:**
- https://releases.rawrxd.ai/v1.0.0-rc1.3/
- https://cdn.rawrxd.ai/releases/v1.0.0-rc1.3/
- https://github.com/ItsMehRAWRXD/RawrXD/releases/tag/v1.0.0-rc1.3

---

## Post-Deployment Verification

- [ ] Verify telemetry collection active
- [ ] Confirm attestation heartbeats transmitting
- [ ] Check emergency circuit breakers armed
- [ ] Validate revocation checking operational

---

## Rollback Criteria

**Immediate Rollback Required If:**
- Root hash verification fails on any node
- Revocation check fails with valid certificate
- Stack overflow conditions detected
- Memory-mapped loading faults
- IPC gateway attestation < 99.5%

---

## Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Release Engineer | | | |
| Security Reviewer | | | |
| QA Lead | | | |
| Operations Lead | | | |

---

**Status:** ☐ READY FOR STAGING ☐ STAGING COMPLETE ☐ PRODUCTION DEPLOYED
