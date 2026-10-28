# RECEIPT — WIN32IDE_FULL_SOURCE_AUDIT_002

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
PERFECT=0
WORKSPACE=G:\~dev\rawrxd
MOTD_ACK=1
ASOF_UTC=2026-10-28T17:00:00Z
NO_INVENT_PASS=1
CAMPAIGN_PHASE=1
TIP=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
GHOSTTEXT_ABSORB=NOT_AUTHORIZED
```

## Verdict

Phase 1 audit refresh complete fail-closed against PRODUCT_TIP
`TIP_FREEZE_001` SHA `748B210A…`. Inventory + orphan buckets written.
OPEN list non-empty → PERFECT=0 → CERTIFIED=0 → PROMOTE=0.
GhostText witness `B421…` observed in link001 tree pre-rebuild; absorb not authorized.

## Counts (return)

| Scope | Metric | N |
|-------|--------|--:|
| src/ | cpp / c / h / hpp / asm | 5591 / 192 / 1762 / 2758 / 1328 |
| src/ | sum those | 11631 |
| src/ | all files | 15099 |
| win32app/ | linkable TUs | 540 |
| link001 | all .obj | 885 |
| link001 | win32app linked | 217 |
| link001 | win32app orphans | 323 |
| orphans | OPENISH / GATEDISH | 294 / 29 |
| GateFiction | GATED hits | 277 |
| matrix | OPEN (A04,A08,A09,A10,A12,A13,A14) | 7 |
| matrix | BLOCKED | 2 |
| matrix | HELD | 1 |

## Explicit non-claims

```
PERFECT=0
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
OPEN_LIST_EMPTY=0
NOT_RUN != PASS
B421_GHOSTTEXT != TIP
ABSORB_GHOSTTEXT=NOT_AUTHORIZED
A09_MINIDUMP_SOURCE_WIRED != A09_MET
```

## Artifacts

- LAW.txt / INVENTORY.md / MATRIX.md / RECEIPT.md
- linked_win32app_tus.txt / win32app_orphans.txt / orphan_buckets.txt
- SHA_BIND.txt
