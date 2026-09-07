# UCF_AUTHORITY_LOCK_001

## Authority lock

```text
UCF_AUTHORITY_LOCK_001=PASS

Authority:
  src/deep2/rawr_uncoherent_object_fabric.hpp

MASM:
  non-landed / non-authoritative for this gate

Sealed behavior:
  dispatchRWExpected(object, expectedGen, lane, fn)
  expected N → acquire RW → execute → commit → N+1
  stale expected generation throws GenerationMismatch
  resident-but-stale replica is not dispatch-legal
  no latest-pointer-wins fallback
  BounceChain lanes are opaque DeviceIds
```

## Reconciled gates

| Gate | Result |
|------|--------|
| `UCF_BOUNCE_SMOKE` | PASS — hops 8, gen 1→9, mismatch |
| `UCF_NO_STALE_DISPATCH_001` | PASS — A→2, stale B@1 throw, B@2→3 |

## Next

`UCF_LOGITS_RANGE_BOUNCE_001` — bounce **winner index/value/range meta/generation** only; never full F32 logits.
