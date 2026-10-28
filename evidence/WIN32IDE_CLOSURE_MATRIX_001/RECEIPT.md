# RECEIPT — WIN32IDE_CLOSURE_MATRIX_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
PERFECT=0
NO_INVENT_PASS=1
MOTD_ACK=1
ASOF_UTC=2026-10-28T10:51:03Z
TIP_SHA=6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2
PRIOR_TIP_SHA=C4FC9AE9A6EAC016A78B0C1BB1690B9C47A46A4B47FC51B1B807E10E14EDC43B
```

## Tip EXE (post TIP_ABSORB_SWARM_002)

| Field | Value |
|-------|-------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331649536 |
| SHA256 | `6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2` |
| Provenance cite | `TIP_ABSORB_SWARM_002` |
| HttpTags linked | **YES** (`appendLocalOllamaHttpTags` in map) |
| A01 | **OPEN** — `WIN32IDE_BINARY_PROVENANCE_002` FAIL_CLOSED (`C4FC9AE9…` vs live `6832F439…`); full provenance MET pending |

## Current tip sibling seals (`6832F439…`)

| Evidence ID | Disposition | Cite |
|-------------|-------------|------|
| `LIVE_TETRAD_POST_SWARM_ABSORB_001` | **PASS** | GENERATED_TOKENS=16 |
| `MULTI_FAMILY_PRODUCT_005` | **PASS** | gemma3 ≠ TinyLlama; GENERATED_TOKENS=16 |
| `TOKEN64_PRODUCT_RUN_005` | **PASS** | GENERATED_TOKENS=64; `TPS_PRODUCT_SEAL=1` |
| A03 | **MET** | triad earned on current tip only |
| `SAFE_WRITE_APPROVAL_TIP_001` | **RUNTIME_REACHED** | A06 deny + A07 isolation negatives; MET=0 (deny rows untouched) |
| `SAFE_WRITE_ATOMIC_001` | **SOURCE_WIRED** | A06 atomic/preview/rollback TUs; RELINK_REQUIRED; RUNTIME NOT_RUN; MET=0 |

## Historical prior tips — untouched

| Tip | Evidence | Disposition |
|-----|----------|-------------|
| `C4FC9AE9…` | LIVE_TETRAD_POST_TIP_ABSORB_001 / MULTI_FAMILY_003 / TOKEN64_004 | PASS (historical) |
| `866E9D1B…` | LIVE_TETRAD_POST_HMAC_ABSORB_001 / MULTI_FAMILY_002 / TOKEN64_003 | PASS (historical) |

## S-002 / S-003 tip linkage

| Item | Disposition |
|------|-------------|
| `SWARM_MODEL_ORCH_001` | SOURCE_WIRED |
| Tip absorb | **PASS** (`TIP_ABSORB_SWARM_002`) |
| Selector + SubAgent + HttpTags | **LINKED** |
| Product swarm tip RUNTIME | **NOT_RUN** (`SWARM_16_RUNTIME_001` INVOKED=0) |
| G07 | **SOURCE_WIRED** — not MET (`SWARM_16_RUNTIME_001` CMD=4111 GUI exit=2 + headless no orch; Ollama HI ≠ tip EXE RUNTIME_PASS) |
| G08 | **SOURCE_WIRED** — topology NOT_OBSERVED at tip runtime |
| G10 | **OPEN** — cancel NOT_ATTEMPTED (no live tip swarm) |

## A05 / S-001 runtime (post TOOL_ACTION_STATUS_E2E_002)

| Item | Disposition |
|------|-------------|
| Tip SHA | `6832F439…` SHA_MATCH |
| E2E | headless `/api/tool` success+failure; GateStub RemoteThread NEG; Admit+cancel unit |
| A05 | **RUNTIME_PARTIAL** (not MET; tip Admit NOT_LINKED) |
| S-001 | **RUNTIME_PARTIAL** (not MET) |
| G14 / G15 | **RUNTIME_PARTIAL** |
| Cite | `TOOL_ACTION_STATUS_E2E_002` (prior `TOOL_ACTION_STATUS_RUNTIME_001`) |
| RELINK | Admit+VSCodeUI+hookToolResult SOURCE_WIRED — tip absorb required for MET |

## Explicit non-claims

```
PROMOTE=0 CERTIFIED=0 PERFECT=0 TIP_CLIMB=HOLD
A03 MET != PROMOTE
A05 RUNTIME_PARTIAL != MET (tip Admit consumer absorb pending; E2E_002)
A01 — see MATRIX (PROVENANCE_003 may supersede OPEN)
G07_MET=0
HTTPTAGS_LINKED=1 (6832F439 sibling tip; GAP on C4FC9AE9)
```

