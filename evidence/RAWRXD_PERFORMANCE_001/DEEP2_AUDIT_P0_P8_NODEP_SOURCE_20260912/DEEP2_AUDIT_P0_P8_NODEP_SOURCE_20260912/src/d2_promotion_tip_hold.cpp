#include "deep2_audit_nodep.h"

static int all_product_ready(const D2AuthorityState* s) {
    return s && s->full_model_tps_authority && s->daily_streamer_ready && s->stage_timing_authority &&
           s->packed_q2k_ready && s->deviceio_ssvk_ready && s->aggregate_bw_authority &&
           s->missing15_ready && s->model_size_next4_ready && s->ide_sse_cancel_ready;
}
extern "C" int d2_compute_promotion(const D2AuthorityState* s, uint32_t explicit_promote_request) {
    if (!explicit_promote_request || !all_product_ready(s)) return 0;
    return 1;
}
extern "C" int d2_compute_tip_climb(const D2AuthorityState* s, uint32_t explicit_tip_request) {
    if (!explicit_tip_request || !s || !s->promote || !all_product_ready(s)) return 0;
    return 1;
}
