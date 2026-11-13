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

## Controlling EXE (bind all B03-A..E claims here)
EXE=F:\rawrxd\build_reap\bin-msvc\rawr-reap.exe
EXE_SHA256=C9A5564CB03612F3F6AF7F313D55B339AAD65BA6545BA93EC543441396701B16
GIT_SHA=a1409af7f7293e13513f662207d923e2b98ef903
BRANCH=evidence/reap-multi-model-20261113
PR=https://github.com/ItsMehRAWRXD/RawrXD/pull/82
CMD=rawr-reap runtime <MiniMax-00001-of-00003.gguf> --target 30GB/8 --prompt Hello --max-tokens 2
EVIDENCE_LOG=MINIMAX_PHYSICAL_STDERR_v2.log / MINIMAX_PHYSICAL_RECEIPT.json
AUTHORITY=MINIMAX_PHYSICAL_REAP.txt (PHYSICAL_RUNTIME_MINIMAX)

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
| B03_ATTENTION_BIND | attention slots bound for forward | PASS | Multishard bind; forward entered layer 0 without missing-Q |
| B03-C FORWARD_ENTERED | layer-0 attention+MoE place | PASS | LIVE_K2_MOE_PLACE layer=0 n=8 (stderr_v2) |
| B03-D FORWARD_COMPLETED | 62 layers exercised | PASS | LIVE_K2_MOE_PLACE layer=0..61; place_events=124 (=62*2 tokens); FFN_SKIP=0 on C9A5564C |
| B03-E TOKENS | generated_tokens>=2 same EXE SHA | MEASURED | generated_tokens=2 GENERATION_RECEIPT completed=1 |
| B03-E PHYSICAL | EXPERTS route/acquire >0 | MEASURED | ROUTE_OK=992 ACQUIRE_OK=992 EXCLUDED_ACQUIRES=0 retain=29 LIVE_K2_MOE_PLACE=124 |
| QUALITY | coherence/coding | OPEN | not claimed |
| PROMOTE / CERTIFIED | product promote | 0 / 0 | held |

## FFN_SKIP reconciliation
FFN_SKIP_COUNT_ON_C9A5564C=0
FFN_SKIP_COUNT_ON_E86584F7=62
MOE_PLACE_ON_C9A5564C=124
VERDICT=FFN_SKIP observed only on non-controlling EXE E86584F7 (G HOST_DECODE path where MoE dispatch predicate did not fire). Controlling EXE C9A5564C: FFN_SKIP=0 and LIVE_K2_MOE_PLACE=124. Full topology requires attention forward AND moe place AND FFN_SKIP=0 on the SAME exe SHA; C9A5564C satisfies that.

## Receipt consistency
runtime_global_tensors=809
plan_first_shard_tensors_legacy_risk=288
physical_receipt_plan_tensors=809
ACTIVE_RUNTIME_ROUTER_RESIDENCY=config_ok_NE_physical (physical proved separately via ROUTE/ACQUIRE)

## TOPOLOGY-CERT-001
STATUS=CLEARED_ON_C9A5564C
PRIOR_FAIL_NOTE=older EXEs (CROSS_SHA_CREDIT=0)
