#pragma once
/* Deep2 roofline seams — BYTES_NOT_ALREADY_LOCAL_PER_TOKEN primary.
 * SOURCE plumbing only. Does not mint LIVE/PROMOTE authority.
 * Next live gate after BIND16: DEEP2_ROOFLINE_LOCALITY_001 (64 tokens). */
#include "d2_roofline.h"

namespace Deep2 {

/* MoE design targets (48GB VRAM + 64GB DDR5) — cache-hot ≠ sustained. */
enum {
    D2RF_TARGET_DEEPSEEK_R1_FLOOR_TPS = 10,
    D2RF_TARGET_DEEPSEEK_R1_TPS = 18,
    D2RF_TARGET_DEEPSEEK_R1_STRETCH_TPS = 25,
    D2RF_TARGET_KIMI_K25_FLOOR_TPS = 7,
    D2RF_TARGET_KIMI_K25_TPS = 14,
    D2RF_TARGET_KIMI_K25_STRETCH_TPS = 20
};

inline int RooflinePlanToken(D2RfState* st, const D2RfTokenInput* in,
                             D2RfPlan* plan) {
    return d2rf_plan_token(st, in, plan);
}

inline int RooflineObserve(D2RfState* st, const D2RfTokenInput* in,
                           const D2RfPlan* plan) {
    return d2rf_observe(st, in, plan);
}

inline int RooflineReceipt(const D2RfTokenInput* in, const D2RfPlan* plan,
                           D2RfReceipt* out) {
    return d2rf_receipt(in, plan, out);
}

inline int RooflineAuthoritative(const D2RfReceipt* r) {
    return d2rf_receipt_authoritative(r);
}

} // namespace Deep2
