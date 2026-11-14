# MINIMAX_REAP_BACKEND_001 — Disposition

```text
MINIMAX_REAP=PARTIAL
PROMOTE=0 CERTIFIED=0 COMPETITIVE_PASS=0
CROSS_SHA_CREDIT=0 TIP_CLIMB=HOLD
```

## Closed on measured EXE
- Physical REAP16 load + decode TOK>0
- Router weight inject (HasRouterWeights false-until-Set)
- topk=8 from expert_used_count
- Explicit BLOCKED for packs with used_count==expert_count

## Open
- Semantic coherence FAIL
- exp_probs_b bias inject
- Fair H2H / competitive TPS
- Provenance mismatch residual

## Unsupported (explicit)
REAP24 / REAP27-16GB / REAP32 MiniMax packs with clobbered expert_used_count — do not silent-route as topk=E.
