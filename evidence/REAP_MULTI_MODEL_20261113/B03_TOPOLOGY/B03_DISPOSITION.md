# B03 Native Attention Topology — Formal Disposition
UTC_LOCAL=2026-11-13
MOTD_ACK=1
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
ORIGINAL_GGUF_INTACT=1
CROSS_SHA_CREDIT=0
NOT_RUN_NE_PASS=1
QUALITY=OPEN
CURRENT_EXE_REBOUND=1

## Controlling EXE (bind all B03-A..E claims here)
EXE=F:\rawrxd\build_reap\bin-msvc\rawr-reap.exe
EXE_SHA256=C9A5564CB03612F3F6AF7F313D55B339AAD65BA6545BA93EC543441396701B16
PRE_RUN_SHA256=C9A5564CB03612F3F6AF7F313D55B339AAD65BA6545BA93EC543441396701B16
POST_RUN_SHA256=C9A5564CB03612F3F6AF7F313D55B339AAD65BA6545BA93EC543441396701B16
CURRENT_EXE_REBOUND=1
REBUILT=0
GIT_SHA=09d166a12e2aefac6d8c288d67d576f3998967af
BRANCH=evidence/reap-multi-model-20261113
PR=https://github.com/ItsMehRAWRXD/RawrXD/pull/82
CMD_PRIOR=rawr-reap runtime <MiniMax-00001-of-00003.gguf> --target 30GB/8 --prompt Hello --max-tokens 2
CMD_ACCEPTANCE=rawr-reap runtime <MiniMax-00001-of-00003.gguf> --target 30GB/8 --prompt Hello --max-tokens 4
EVIDENCE_T2=MINIMAX_PHYSICAL_RECEIPT.json / MINIMAX_PHYSICAL_REAP.txt
EVIDENCE_T4=MINIMAX_PHYSICAL_T4_DUAL_RUN.txt / MINIMAX_PHYSICAL_RECEIPT_T4_R1.json / MINIMAX_PHYSICAL_RECEIPT_T4_R2.json
AUTHORITY=MINIMAX_PHYSICAL_T4_DUAL_RUN.txt + CURRENT_EXE_REBOUND.txt (PHYSICAL_RUNTIME_MINIMAX)
STALE_STATUS_NOTE=layer-0 BLOCKED / physical NOT_RUN controlling status is STALE; superseded by this disposition on C9A5564C

## Non-controlling EXE (do NOT credit)
EXE=G:\~dev\rawrxd\build_ninja\bin\rawr.exe
EXE_SHA256=E86584F758344B1519685F9C7B7658B53ED32A5F2CEB330AE73BCC3ABAE5563C
NOTE=HOST_DECODE MultiShardLayerMaterialize path; showed B03_ATTENTION_BIND_VALID=1 then FFN_SKIP ly=* and EXIT=HEAP_CORRUPTION(0xC0000374). CROSS_SHA_CREDIT=0 vs C9A5564C.

## Inventory authority
GLOBAL_TENSORS=809 (shard0=288 + shard1=299 + shard2=222)
PLAN_TENSORS_FIRST_SHARD_ONLY=288 (!= global; physical receipt tensors=809)
L0_Q=blk.0.attn_q.weight dims=[3072,6144] type=12 shard=0
headDim=128 (Q rows 6144=48*128; K/V rows 1024=8*128)
LAYOUT=split Q/K/V + attn_q_norm/attn_k_norm + MoE ffn_*_exps (not fused QKV, not MLA)

## Gate table (fail-closed; controlling SHA only)

| Gate | Claim | Status | Evidence |
|------|-------|--------|----------|
| B03-A layer-0 inventory | names/shapes/types/shards for L0 + later layers | PASS | L0_TENSOR_INVENTORY.json; physical inventory shards=3 tensors=809 |
| B03-B real Q/K/V bind | descriptor+shape+backing+consumer; no missing-Q | PASS | [MULTISHARD_BIND] layers=62 mappings=560; no TOPOLOGY-CERT-001 on C9A5564C |
| B03_LAYER_TENSORS_VALID | required attn tensors present for topology | PASS | Multishard bind 62 layers; L0 Q/K/V/O + norms in GGUF+index |
| B03_ATTENTION_BIND | attention slots bound for forward | PASS | Multishard bind; forward entered without missing-Q |
| B03-C FORWARD_ENTERED | layer-0 attention+MoE place | PASS | prior LIVE_K2_MOE_PLACE layer=0; T4 GATE_ACQUIRE/HOST_MOE + ACQUIRE_OK |
| B03-D FORWARD_COMPLETED | 62 layers exercised | PASS | T2: LIVE_K2_MOE_PLACE=124; T4: ACQUIRE_OK=1984 (=62*8*4); FFN_SKIP=0 |
| B03-E TOKENS | TOKENS_COMMITTED>=4 same EXE SHA | PASS | dual-run generated_tokens=4 / 4; output=姬被被被 |
| B03-E PHYSICAL | EXPERTS route/acquire >0 | PASS | ROUTE_OK=1984 ACQUIRE_OK=1984 EXCLUDED_ACQUIRES=0 retain=29 |
| B03-E REPEAT | deterministic repetition same EXE | PASS | R1==R2 tokens/output/ROUTE/ACQUIRE on C9A5564C |
| CURRENT_EXE_REBOUND | rehash controlling MiniMax EXE | PASS | CURRENT_EXE_REBOUND.txt =1; SHA unchanged |
| METADATA_NE_MAT | MultiShardLayerMaterialize metadata≠materialization | ENFORCED | bind-only MULTISHARD_BIND; on-demand mat; ready=1 ≠ cert |
| QUALITY | coherence/coding | OPEN | not claimed |
| PROMOTE / CERTIFIED | product promote | 0 / 0 | held |

## Acceptance list (user-required remaining gaps)

| Requirement | Result | Measured |
|-------------|--------|----------|
| TOKENS_COMMITTED>=4 | PASS | 4 (was 2) |
| Deterministic repetition same EXE SHA | PASS | R1/R2 identical output+counters on C9A5564C |
| CURRENT_EXE_REBOUND=1 | PASS | rehash matched; REBUILT=0 |
| metadata≠materialization still enforced | ENFORCED | ready=1 alone not cert |
| EXPERTS_SELECTED/EXECUTED or MOE_PLACE>0 | PASS | ACQUIRE_OK=1984; PLACE_DONE>0; GATE_ACQUIRE>0 |
| ACQUIRE_OK>0 | PASS | 1984 |
| STREAM_CORRECTNESS | PASS | stream_correctness.PASS=true |
| EXCLUDED_ACQUIRES=0 | PASS | ACQUIRE_DENIED=0 |
| QUALITY | OPEN | held |
| PROMOTE / CERTIFIED | 0 / 0 | held |

## FFN_SKIP reconciliation
FFN_SKIP_COUNT_ON_C9A5564C=0
FFN_SKIP_COUNT_ON_E86584F7=62
MOE_PLACE_ON_C9A5564C_T2=124
ACQUIRE_OK_ON_C9A5564C_T4=1984
VERDICT=FFN_SKIP observed only on non-controlling EXE E86584F7. Controlling EXE C9A5564C: FFN_SKIP=0 with MoE acquire/place live.

## Receipt consistency
runtime_global_tensors=809
plan_first_shard_tensors_legacy_risk=288
physical_receipt_plan_tensors=809
ACTIVE_RUNTIME_ROUTER_RESIDENCY=config_ok_NE_physical (physical proved via ROUTE/ACQUIRE)

## TOPOLOGY-CERT-001
STATUS=CLEARED_ON_C9A5564C
PRIOR_FAIL_NOTE=older EXEs (CROSS_SHA_CREDIT=0)

## Out of scope (do not reopen unless blocked)
Kimi / PR81 / Qwen GDN (2ed308e7): NOT REOPENED
