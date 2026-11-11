# LAW — Previous candidate launch cannot certify newer source

ASOF_UTC=2026-11-11T17:30:00Z  
CERTIFIED=0  
PROMOTE=0  
ROUTING_E2E=NOT_CERTIFIED  
BLOCKED_ON_BATCH17_EXE=1

```text
PREVIOUS_CANDIDATE_LAUNCH_PASS != NEWER_SOURCE_CERT

IF:
  exe_sha256(evidence) != exe_sha256(current rebuilt IDE)
  OR source tree changed after launch-receipt timestamp
  OR REBUILD=FAIL / no new tip SHA
THEN:
  ROUTING_E2E remains NOT_CERTIFIED
  launch-receipt is historical only
  PROMOTE=0 CERTIFIED=0
```

## Binding facts (upper-tier)

| Item | Value |
| --- | --- |
| Hotpatch foundation | SOURCE_IMPLEMENTED |
| ROUTING_E2E | NOT_CERTIFIED |
| Latest native rebuild | FAIL (Batch 17 owns EXE) |
| Prior launch receipts under `RAWRXD_ROUTING_HOTPATCH_001` | Historical; SHA-locked to their EXE only |
| New IDE SHA required for routing E2E | YES — `BLOCKED_ON_BATCH17_EXE` |

## Forbidden claims

- Do not treat a prior candidate's successful GUI launch as acceptance of newer GhostText/routing source.
- Do not invent `ROUTING_E2E=PASS` without a newly rebuilt IDE SHA and correlated Ollama identity evidence for that SHA.
- Do not promote (`PROMOTE=0` held).

## Acceptance path (future)

1. Batch 17 produces clean native EXE + exact SHA-256.
2. Hash-locked launcher starts that EXE only.
3. Validator accepts complete, fresh, SHA-matched routing evidence.
4. GhostText request IDs unique; model-select bumps routing epoch; cancel invalidates outstanding.
5. Logs redact secrets.
6. Only then may ROUTING_E2E be evaluated — still separately from PROMOTE.
