#ifndef DEEP2_MISSING15_NODEP_H
#define DEEP2_MISSING15_NODEP_H

/* Deep2 Missing-15 Invariant Enhancements — dependency-free core header. */
typedef unsigned int       d2_u32;
typedef unsigned long long d2_u64;
typedef long long          d2_i64;

/* 01 SURVIVABILITY FIREWALL — lower-order gains are dead unless execution exits cleanly with no allocator/worker/device failure. */
static __inline d2_u32 d2m15_survival_gate(d2_u32 exit_code,d2_u32 acquire_fail,d2_u32 worker_fail,d2_u32 oom,d2_u32 device_loss){return exit_code==0u&&acquire_fail==0u&&worker_fail==0u&&oom==0u&&device_loss==0u;}
/* 02 HARD MEMORY ENVELOPE — scheduling is legal only while pinned/resident usage stays inside the declared per-stick budget. */
static __inline d2_u32 d2m15_budget_gate(d2_u64 used,d2_u64 budget){return used<=budget;}
/* 03 ZERO-RELOAD RESIDENCY GATE — no balance or TPS win may promote while avoidable expert miss bytes remain nonzero. */
static __inline d2_u32 d2m15_residency_gate(d2_u64 reload_miss_bytes){return reload_miss_bytes==0ull;}
/* 04 ATTRIBUTABLE-SAMPLE ONLY — train an expert cell only from timing that belongs uniquely to that expert execution. */
static __inline d2_u32 d2m15_sample_gate(d2_u32 attributable,d2_u64 actual_ns){return attributable!=0u&&actual_ns!=0ull;}
/* 05 CONFIDENCE-GATED WARMUP — V7 authority rises only with real cell coverage instead of switching predictors abruptly. */
static __inline d2_u32 d2m15_confidence_q10(d2_u32 samples,d2_u32 warmup_n){return warmup_n==0u?1024u:(samples>=warmup_n?1024u:(d2_u32)(((d2_u64)samples*1024ull)/(d2_u64)warmup_n));}
/* 06 V6/V7 BLEND — preserve proven V6 behavior while confidence smoothly transfers scheduling authority to measured V7 cost. */
static __inline d2_u64 d2m15_blend_ns(d2_u64 v6_ns,d2_u64 v7_ns,d2_u32 w_q10){return (v6_ns*(1024u-(w_q10>1024u?1024u:w_q10))+v7_ns*(w_q10>1024u?1024u:w_q10))/1024u;}
/* 07 UNCERTAINTY PENALTY — sparse or noisy cells pay a deviation premium so optimistic variance cannot win placement. */
static __inline d2_u64 d2m15_risk_ns(d2_u64 mean_ns,d2_u64 deviation_ns,d2_u32 risk_q10){return mean_ns+(deviation_ns*(d2_u64)risk_q10)/1024ull;}
/* 08 SPLIT COMPUTE/TRANSFER COST — kernel time and miss-transfer time remain separate signals and combine only at decision time. */
static __inline d2_u64 d2m15_execution_cost_ns(d2_u64 kernel_ns,d2_u64 transfer_ns){return kernel_ns+transfer_ns;}
/* 09 EVICTION OPPORTUNITY COST — placement pays for the future reload damage of evicting a high-reuse resident expert. */
static __inline d2_u64 d2m15_opportunity_ns(d2_u64 transfer_ns,d2_u32 reuse_q10){return transfer_ns+(transfer_ns*(d2_u64)(reuse_q10>1024u?1024u:reuse_q10))/1024ull;}
/* 10 PREDICTOR EXCURSION CLAMP — new V7 estimates cannot escape a bounded corridor around trusted V6 until evidence is dense. */
static __inline d2_u64 d2m15_clamp_ns(d2_u64 v7_ns,d2_u64 lo_ns,d2_u64 hi_ns){return v7_ns<lo_ns?lo_ns:(v7_ns>hi_ns?hi_ns:v7_ns);}
/* 11 CONFIDENCE DECAY — stale measurements lose authority as queue pressure, residency, or hardware regime ages away. */
static __inline d2_u32 d2m15_decay_q10(d2_u32 confidence_q10,d2_u32 age_epochs,d2_u32 decay_per_epoch_q10){d2_u64 loss=(d2_u64)age_epochs*(d2_u64)decay_per_epoch_q10;return loss>=confidence_q10?0u:(d2_u32)((d2_u64)confidence_q10-loss);}
/* 12 WEIGHTED FINISH-TIME SCHEDULER — choose the stick with minimum availability + compute + transfer + eviction opportunity cost. */
static __inline d2_u64 d2m15_finish_ns(d2_u64 available_ns,d2_u64 compute_ns,d2_u64 transfer_ns,d2_u64 opportunity_ns){return available_ns+compute_ns+transfer_ns+opportunity_ns;}
/* 13 TAIL/JOIN BALANCE GATE — equal expert counts do not matter; promotion requires <5% completion skew and no join-wait regression. */
static __inline d2_u32 d2m15_balance_gate(d2_u32 skew_pct_x100,d2_u64 join_wait_ns,d2_u64 accepted_join_wait_ns){return skew_pct_x100<500u&&join_wait_ns<=accepted_join_wait_ns;}
/* 14 HIDDEN-DEBT FIREWALL — a local speedup is rejected if it buys time by adding reloads, retries, host fallback, or deferred stalls. */
static __inline d2_u32 d2m15_no_hidden_debt(d2_u64 reload_bytes,d2_u32 retries,d2_u32 host_fallbacks,d2_u64 deferred_stall_ns){return reload_bytes==0ull&&retries==0u&&host_fallbacks==0u&&deferred_stall_ns==0ull;}
/* 15 COMPOSITE TPS MINT — throughput authority exists only after survival, residency, prediction, balance, parity, 2+2 geometry, and full-forward proof all pass. */
static __inline d2_u32 d2m15_promote_gate(d2_u32 survive,d2_u32 resident,d2_u32 predict_err_pct_x100,d2_u32 balance,d2_u32 parity,d2_u32 submits_per_layer,d2_u32 partial_d2h_per_layer,d2_u32 full_forward_authority){return survive&&resident&&predict_err_pct_x100<1000u&&balance&&parity&&submits_per_layer==2u&&partial_d2h_per_layer==2u&&full_forward_authority;}

#endif
