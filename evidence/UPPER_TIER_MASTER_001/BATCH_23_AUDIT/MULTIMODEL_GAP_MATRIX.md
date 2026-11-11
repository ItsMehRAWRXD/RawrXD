# MULTIMODEL_GAP_MATRIX — Batch 23 prep (READ-ONLY)

```
AUDIT=UPPER_TIER_MASTER_001/BATCH_23_AUDIT/MULTIMODEL_GAP_MATRIX
ASOF_UTC=2026-11-11T17:40:00Z
PRIMARY=F:\rawrxd
CROSS_CHECK=G:\~dev\rawrxd
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
UPPER_TIER=0
SOURCE_WIRED != RUNTIME_REACHED
NOT_RUN != PASS
NO_INVENT_PASS=1
NATIVE_REBUILD=NOT_PERFORMED
WIN32IDE_EDITS=NONE
ESTIMATES_UNCHANGED=1
```

Read-only inventory for Upper-Tier Batch 23 (multi-model routing, capability registry, concurrency, context, fallback). No Win32IDE edits. No native rebuild. No runtime cells executed this audit.

## Controlling blocker — HOTPATCH_SAFEGUARDS_001

```
ROUTING_E2E=NOT_CERTIFIED
BLOCKED_ON_BATCH17_EXE=1
SAFEGUARD_HARNESS=PASS (unit/smoke; != routing E2E)
CERTIFIED=0
PROMOTE=0
RUN=runs/20261111_122954
```

Harness verified launcher hash reject/accept, evidence validator rejects, GhostText request-id uniqueness smoke, model-select/cancel smoke, log redact. That is **not** product `ROUTING_E2E`. Next gate remains Batch 17 new IDE EXE SHA → hash-locked launch → full routing matrix.

## Provider paths (authority)

| Provider | Paths |
|----------|--------|
| GhostText | `Win32IDE_GhostText.cpp/.h`, `Win32IDE_GhostTextIntegration.cpp` |
| Ollama | `backend/ollama_client.*`, `Win32IDE_OllamaClient.h`, `Win32IDE_ChatPanel_Ollama.cpp`, BackendRouter `OllamaBackend`, `AggregateDecodeOllamaBackend` |
| GGUF | `Win32IDE_GGUF_*`, `gguf_loader.h`, `streaming_gguf_loader.*`, `ChatModelEntry::LocalFile` |
| Deep2 | `Win32IDE_Deep2Bridge.*`, `deep2/Deep2Engine*`, BackendRouter `Deep2Backend`, `AggregateDecodeDeep2Backend` |

## Tree delta (F vs G) — routing hotpatch

| Surface | F:\rawrxd | G:\~dev\rawrxd |
|---------|-----------|----------------|
| `setOllamaModelOverride` / `invalidateGhostTextRequests` | **ABSENT** | Present (`Win32IDE_GhostText.cpp`) |
| `m_ghostTextRoutingEpoch` / `m_ghostTextNextRequestId` | **ABSENT** | Present (`Win32IDE.h`) |
| NativeGhostTextController generation / request_id STALE fence | Present | Present |
| HOTPATCH RECEIPT claimed wires | Cite G; not found on F this audit | SOURCE_WIRED |

## Capability matrix

| capability | path (authority) | source_wired | runtime_reached | gaps (short) |
|------------|------------------|-------------:|----------------:|--------------|
| multimodel_catalog_and_selection | `ChatModelEntry` / `ModelDiscoveryPayload`; ModelDiscovery; model combo | 1 | 0 | Identity-only catalog; F missing IDE routing-epoch on select; tip E2E blocked on Batch17 |
| capability_registry | `universal_model_router`; `ModelManager`; agent CAPABILITY_MATRIX | 1 | 0 | No product ModelCapabilityRegistry; thin maps ≠ SSOT caps |
| ghosttext_provider_routing | GhostText + Integration | 1 | 0 | AutoLocal Ollama-first; cloud consent gate; multi-HWND controllers; prior cancel/routing FAIL/UNVERIFIED cited |
| ollama_provider_path | `ollama_client` + ChatPanel + BackendRouter | 1 | 0 | SOURCE_WIRED; tip live bind NOT_RUN |
| gguf_native_provider_path | GGUF reader/inspector/loaders | 1 | 0 | Discovery wired; GhostText does not use LocalFile for AutoLocal |
| deep2_provider_path | Deep2Bridge + Engine + BackendRouter | 1 | 0 | Auto Deep2→Ollama; CPU fallback mode in bridge; tip failover NOT_RUN |
| backend_router_fallback_policy | `BackendRouter.h/.cpp` | 1 | 0 | No mid-stream splice; no cloud failover; tip NOT_RUN |
| concurrency_and_inflight_fencing | multi-controller + hotpatch smoke + aggdec | 1 | 0 | Smoke ≠ IDE E2E; F lacks routingEpoch; concurrent multimodel NOT_RUN |
| context_window_and_budget | `num_ctx` / `m_currentContextTokens`; Deep2 default 8192 | 1 | 0 | Per-model n_ctx not in capability registry; failover context continuity NOT_RUN |
| routing_e2e_certification_gate | HOTPATCH_SAFEGUARDS_001 + TRACKER `native_exe=ABSENT` | 1 | 0 | ROUTING_E2E held; previous candidate ≠ newer source cert |

**Counts:** capabilities=10 · source_wired=10 · runtime_reached=0 · CERTIFIED=0 · PROMOTE=0

## Claims vs reality

| Claim / surface | Reality (this inventory) |
|-----------------|--------------------------|
| Hotpatch safeguards “PASS” | Unit/smoke harness only — `ROUTING_E2E=NOT_CERTIFIED` |
| Multi-model product routing | Catalog + provider paths SOURCE_WIRED; tip EXE ABSENT → runtime_reached=0 |
| Capability registry | Not a first-class product registry; `ChatModelEntry` is Source+id |
| GhostText follows chat / Auto Local | Wired; AutoLocal falls to first Ollama when chat is GGUF/cloud |
| Deep2 primary with Ollama backup | BackendRouter policy SOURCE_WIRED; tip failover NOT_RUN |
| Concurrent GhostText safety | Controller generation fence on F; IDE routingEpoch on G only; product suite NOT_RUN |

## Prior sealed evidence (cited, not re-run)

- `UPPER_TIER_MASTER_001/HOTPATCH_SAFEGUARDS_001` — harness PASS; ROUTING_E2E NOT_CERTIFIED; blocked on Batch17 exe
- `RAWRXD_ROUTING_HOTPATCH_001` — historical launch; routing fields UNVERIFIED; PROMOTE=0
- `F_GHOSTTEXT_CANCEL_ROUTING_CLOSURE_001` — CANCELLATION=FAIL; MODEL_ROUTING=BINARY_UNVERIFIED
- `POST_E59D_CANDIDATE_001/MODEL_ROUTE` — candidate artifacts ≠ tip Batch17 SHA

## Batch 23 prep blockers

1. `ROUTING_E2E=NOT_CERTIFIED` blocked on Batch 17 native EXE.
2. F missing G routing-epoch hotpatch symbols — absorb/port gap.
3. No product ModelCapabilityRegistry.
4. GhostText AutoLocal never completes via native GGUF.
5. All runtime cells this audit: **NOT_RUN** (≠ PASS). Estimates unchanged.

## Next executable gates (explicitly NOT_RUN here)

1. Batch 17 clean native rebuild → new EXE SHA  
2. Hash-locked launch + GhostText/chat/agent routing matrix with Ollama identity  
3. Decide F absorb of G routing-epoch hotpatch  
4. Capability registry: implement or HOLD OPEN  
5. Re-run cancel/stale A/B + Deep2→Ollama failover on new SHA (`PROMOTE=0`)

Machine-readable twin: `MULTIMODEL_GAP_MATRIX.json`
