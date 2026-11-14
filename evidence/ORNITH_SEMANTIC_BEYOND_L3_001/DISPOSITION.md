# ORNITH_SEMANTIC_BEYOND_L3_001 — disposition

```text
SEMANTIC=FAIL
EXE_SHA=340E56D7…
PROMOTE=0
CROSS_SHA vs tip CEBA0DE4 = 0
```

## Verdict

Lane L3 P1 asked for complete Ornith inference **beyond** the sealed L3 ULP close (`BR_ORNITH_PACKED_GEMV_L3_R104`). ULP closure remains held and is **not** semantic certification.

This remasure on pinned MoE EXE `340E56D7…` with `RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM=1`:

| Check | Result |
|-------|--------|
| EXPERIMENTAL_SSM auth | `EXPERIMENTAL_SSM_AUTH_RESUME=1` |
| PROD_DECODE | `0` (`geometry!=scaffold`; REAL=21 unmet) |
| max-tokens 8 | `TOKENS_COMMITTED=0` · stdout empty |
| Exit | `-1073740940` / `0xC0000374` STATUS_HEAP_CORRUPTION |
| CLEAN_EXIT | `0` · `DISPOSITION=INCOMPLETE` |
| PROD_PROVENANCE | `MATCH=0` · `BLOCKED_AT=PROVENANCE_MISMATCH` |
| llama hybrid ref | AFTER still `ORNITH_HYBRID_LOAD=FAIL` (753 vs 749) |

Prior R101 short run (different EXE `E7A7EE9F…`, CROSS_SHA=0) produced TOK=2 with stdout `isos️` for prompt “Say hi…” → coherence fail; does not rescue this pin.

## Related held (not weakened)

- `PACKED_GEMV=ULP_CLOSED_VS_F32_ORACLE` (R104)
- `FFN_NORM=PARTIAL` (R101)
- `ORNITH_REFERENCE_LOAD=BLOCKED`
- Tip baseline `CEBA0DE4…` ≠ Ornith pin — no cross-credit

## Next owner

`DEEP2_ORNITH_PROD_DECODE_OR_HEAP` / `LLAMA_REF_HYBRID_SCHED` / `PROD_PROVENANCE_BIND`

`PROMOTE=0` · `TIP_CLIMB=HOLD`
