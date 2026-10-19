#include "deep2_decode_finish_balance.h"

static uint64_t d2_align_down(uint64_t x, uint64_t a) {
    return a ? (x / a) * a : x;
}
static uint64_t d2_clamp_u64(uint64_t x, uint64_t lo, uint64_t hi) {
    if (x < lo) return lo;
    if (x > hi) return hi;
    return x;
}
static uint64_t d2_cost_q16(uint64_t duration_ns, uint64_t work) {
    if (!duration_ns || !work || duration_ns > (UINT64_MAX >> D2_BAL_Q)) return 0;
    return (duration_ns << D2_BAL_Q) / work;
}
static uint64_t d2_ewma_q16(uint64_t oldv, uint64_t newv, uint32_t old_weight_q16) {
    uint64_t a, b;
    if (!oldv) return newv;
    if (!newv) return oldv;
    a = (oldv * old_weight_q16) >> D2_BAL_Q;
    b = (newv * (D2_BAL_ONE - old_weight_q16)) >> D2_BAL_Q;
    return a + b;
}

int d2_balance_init(D2DecodeBalancer* s, const D2DecodeBalancerConfig* cfg, uint64_t initial_work0) {
    uint64_t minw, maxw, a;
    if (!s || !cfg || !cfg->total_work_units) return D2_EINVAL;
    *s = (D2DecodeBalancer){0};
    s->cfg = *cfg;
    a = cfg->alignment_units ? cfg->alignment_units : 1;
    s->cfg.alignment_units = a;
    minw = (cfg->total_work_units * cfg->min_lane_percent_q16) >> D2_BAL_Q;
    minw = d2_align_down(minw + a - 1, a);
    if (minw < a) minw = a;
    if (minw * 2 >= cfg->total_work_units) return D2_EINVAL;
    maxw = cfg->total_work_units - minw;
    initial_work0 = d2_align_down(initial_work0, a);
    initial_work0 = d2_clamp_u64(initial_work0, minw, maxw);
    s->next_work0 = initial_work0;
    s->next_work1 = cfg->total_work_units - initial_work0;
    s->best_work0 = s->next_work0;
    s->best_work1 = s->next_work1;
    return D2_OK;
}

int d2_balance_observe_and_plan(D2DecodeBalancer* s, const D2TokenTiming* t,
                                uint64_t* out_work0, uint64_t* out_work1) {
    uint64_t dur0, dur1, c0, c1, denom, total, minw, maxw, w0, a, rollback_limit;
    int64_t start_skew, finish_skew, numerator_signed;
    if (!s || !t || !out_work0 || !out_work1) return D2_EINVAL;
    if (!d2_token_authority_safe(t) || !t->gpu0_work_units || !t->gpu1_work_units ||
        t->gpu0_end_ns <= t->gpu0_start_ns || t->gpu1_end_ns <= t->gpu1_start_ns) {
        s->rejected_samples++;
        *out_work0 = s->next_work0;
        *out_work1 = s->next_work1;
        return D2_EAUTH;
    }
    dur0 = t->gpu0_end_ns - t->gpu0_start_ns;
    dur1 = t->gpu1_end_ns - t->gpu1_start_ns;
    c0 = d2_cost_q16(dur0, t->gpu0_work_units);
    c1 = d2_cost_q16(dur1, t->gpu1_work_units);
    if (!c0 || !c1) return D2_EINVAL;
    s->cost0_ns_per_work_q16 = d2_ewma_q16(s->cost0_ns_per_work_q16, c0, s->cfg.ewma_old_q16);
    s->cost1_ns_per_work_q16 = d2_ewma_q16(s->cost1_ns_per_work_q16, c1, s->cfg.ewma_old_q16);
    start_skew = (int64_t)t->gpu1_start_ns - (int64_t)t->gpu0_start_ns;
    finish_skew = (int64_t)t->gpu1_end_ns - (int64_t)t->gpu0_end_ns;
    s->last_start_skew_signed_ns = start_skew;
    s->last_finish_skew_signed_ns = finish_skew;
    if (!s->best_critical_ns || t->critical_path_ns < s->best_critical_ns) {
        s->best_critical_ns = t->critical_path_ns;
        s->best_work0 = t->gpu0_work_units;
        s->best_work1 = t->gpu1_work_units;
    }
    total = s->cfg.total_work_units;
    denom = s->cost0_ns_per_work_q16 + s->cost1_ns_per_work_q16;
    if (!denom) return D2_EINVAL;
    if (s->cost1_ns_per_work_q16 > (uint64_t)INT64_MAX / total) return D2_EINVAL;
    numerator_signed = (int64_t)(s->cost1_ns_per_work_q16 * total) + (start_skew << D2_BAL_Q);
    if (numerator_signed <= 0) w0 = 0;
    else w0 = (uint64_t)numerator_signed / denom;
    a = s->cfg.alignment_units;
    minw = (total * s->cfg.min_lane_percent_q16) >> D2_BAL_Q;
    minw = d2_align_down(minw + a - 1, a);
    if (minw < a) minw = a;
    maxw = total - minw;
    w0 = d2_align_down(w0, a);
    w0 = d2_clamp_u64(w0, minw, maxw);
    if (finish_skew > 0 && w0 + a <= maxw) w0 += a;
    else if (finish_skew < 0 && w0 >= minw + a) w0 -= a;
    if (s->best_critical_ns && s->cfg.rollback_percent_q16) {
        rollback_limit = (s->best_critical_ns * s->cfg.rollback_percent_q16) >> D2_BAL_Q;
        if (t->critical_path_ns > rollback_limit) {
            w0 = d2_align_down(s->best_work0, a);
            w0 = d2_clamp_u64(w0, minw, maxw);
        }
    }
    s->next_work0 = w0;
    s->next_work1 = total - w0;
    s->samples++;
    *out_work0 = s->next_work0;
    *out_work1 = s->next_work1;
    return D2_OK;
}
