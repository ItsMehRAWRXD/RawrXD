#include "d2_roofline.h"

/*
    Product core intentionally uses no malloc, stdio, math library,
    OS API, Vulkan API, or external runtime.
*/

#define D2RF_Q16_ONE 65536u
#define D2RF_Q20_ONE 1048576ull

static uint64_t u64_min(uint64_t a, uint64_t b) { return a < b ? a : b; }
static uint64_t u64_max(uint64_t a, uint64_t b) { return a > b ? a : b; }
static uint64_t u64_absdiff(uint64_t a, uint64_t b) { return a > b ? a-b : b-a; }

static uint64_t sat_add_u64(uint64_t a, uint64_t b) {
    uint64_t c = a + b;
    return c < a ? UINT64_MAX : c;
}

static uint64_t gcd_u64(uint64_t a, uint64_t b) {
    while (b) {
        uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

uint64_t d2rf_muldiv_u64(uint64_t a, uint64_t b, uint64_t d) {
    uint64_t g, q, r, hi, lo;
    if (!d) return UINT64_MAX;
    if (!a || !b) return 0;

    /*
      Reduce denominator against both multiplicands first. This keeps common
      roofline ratios such as bytes*(640GB/s)/(1264GB/s) in 64-bit range
      without requiring __int128 (not portable to MSVC).
    */
    g = gcd_u64(b, d);
    b /= g;
    d /= g;

    g = gcd_u64(a, d);
    a /= g;
    d /= g;

    if (d == 1) {
        if (a > UINT64_MAX / b) return UINT64_MAX;
        return a * b;
    }

    /*
      Decompose only after reduction:
        (a*b)/d = (a/d)*b + ((a%d)*b)/d
    */
    q = a / d;
    r = a % d;

    if (q && b > UINT64_MAX / q) return UINT64_MAX;
    hi = q * b;

    if (r && b > UINT64_MAX / r) {
        /*
          Rare residual overflow. Scale both residual operands by powers of two
          while preserving a conservative lower-bound quotient.
        */
        while (r && b > UINT64_MAX / r) {
            if (r >= b) r >>= 1;
            else b >>= 1;
            d >>= 1;
            if (!d) d = 1;
        }
    }

    lo = (r * b) / d;
    return sat_add_u64(hi, lo);
}

uint64_t d2rf_time_ns_for_bytes(uint64_t bytes, uint64_t bytes_per_s) {
    if (!bytes) return 0;
    if (!bytes_per_s) return UINT64_MAX;
    return d2rf_muldiv_u64(bytes, 1000000000ull, bytes_per_s);
}

uint64_t d2rf_tps_milli_from_ns(uint64_t ns) {
    if (!ns || ns == UINT64_MAX) return 0;
    return 1000000000000ull / ns; /* 1000 * 1e9 / ns */
}

int d2rf_quant_form(uint32_t type_id, D2RfQuantForm* out) {
    if (!out) return D2RF_EINVAL;
    out->type_id = type_id;
    out->row_align = 32;

    switch (type_id) {
        case 2:  out->block_elems=256; out->block_bytes=84;  return D2RF_OK; /* Q2_K */
        case 3:  out->block_elems=256; out->block_bytes=110; return D2RF_OK; /* Q3_K */
        case 4:  out->block_elems=256; out->block_bytes=144; return D2RF_OK; /* Q4_K */
        case 5:  out->block_elems=256; out->block_bytes=176; return D2RF_OK; /* Q5_K */
        case 6:  out->block_elems=256; out->block_bytes=210; return D2RF_OK; /* Q6_K */
        case 8:  out->block_elems=32;  out->block_bytes=34;  return D2RF_OK; /* Q8_0 */
        default:
            out->block_elems=0; out->block_bytes=0; out->row_align=0;
            return D2RF_EAUTH;
    }
}

void d2rf_init(D2RfState* s) {
    if (!s) return;
    s->tokens_seen = 0;
    s->authoritative_tokens = 0;
    s->ewma_gpu0_bw_q20 = 0;
    s->ewma_gpu1_bw_q20 = 0;
    s->ewma_pcie_bw_q20 = 0;
    s->ewma_ram_bw_q20 = 0;
    s->best_critical_ns = UINT64_MAX;
    s->best_local_hit_q16 = 0;
    s->last_gpu0_target_bytes = 0;
    s->last_gpu1_target_bytes = 0;
    s->pin_hysteresis_q16 = 49152u;      /* 75% */
    s->prefetch_margin_q16 = 81920u;      /* 125% */
    s->rollback_threshold_q16 = 68813u;   /* 105% */
    s->initialized = 1;
}

static int input_safe(const D2RfTokenInput* in) {
    if (!in) return 0;
    if (!in->gpu0_bw_bytes_per_s || !in->gpu1_bw_bytes_per_s) return 0;
    if (!in->pcie_bytes_per_s || !in->ram_bytes_per_s || !in->nvme_bytes_per_s) return 0;
    return 1;
}

static uint32_t q16_ratio_u64(uint64_t num, uint64_t den) {
    uint64_t v;
    if (!den) return 0;
    v = d2rf_muldiv_u64(num, D2RF_Q16_ONE, den);
    if (v > D2RF_Q16_ONE) v = D2RF_Q16_ONE;
    return (uint32_t)v;
}

static uint64_t estimate_remote_ns(const D2RfTokenInput* in) {
    uint64_t ns = 0, t;
    t = d2rf_time_ns_for_bytes(in->ram_bytes, in->ram_bytes_per_s);
    ns = sat_add_u64(ns, t);
    t = d2rf_time_ns_for_bytes(in->mmap_bytes, in->ram_bytes_per_s);
    ns = sat_add_u64(ns, t);
    t = d2rf_time_ns_for_bytes(in->nvme_bytes, in->nvme_bytes_per_s);
    ns = sat_add_u64(ns, t);

    /*
      RAM/MMAP/NVMe bytes that must reach a GPU also cross PCIe. Count the
      transport layer separately from source-tier service time.
    */
    t = d2rf_time_ns_for_bytes(
        sat_add_u64(sat_add_u64(in->ram_bytes, in->mmap_bytes), in->nvme_bytes),
        in->pcie_bytes_per_s);
    ns = sat_add_u64(ns, t);
    return ns;
}

static void split_local_work(
    const D2RfTokenInput* in,
    uint64_t bytes,
    uint64_t* b0,
    uint64_t* b1)
{
    uint64_t bw0 = in->gpu0_bw_bytes_per_s;
    uint64_t bw1 = in->gpu1_bw_bytes_per_s;
    uint64_t sum = sat_add_u64(bw0, bw1);
    uint64_t x0;

    if (!sum) {
        *b0 = bytes / 2;
        *b1 = bytes - *b0;
        return;
    }

    x0 = d2rf_muldiv_u64(bytes, bw0, sum);
    if (x0 > bytes) x0 = bytes;
    *b0 = x0;
    *b1 = bytes - x0;

    /*
      Start-skew correction: the earlier lane can absorb work equal to
      approximate bytes executable during the head start.
    */
    if (in->gpu0_start_ns < in->gpu1_start_ns) {
        uint64_t skew = in->gpu1_start_ns - in->gpu0_start_ns;
        uint64_t add = d2rf_muldiv_u64(skew, bw0, 1000000000ull);
        add = u64_min(add, *b1);
        *b0 += add;
        *b1 -= add;
    } else if (in->gpu1_start_ns < in->gpu0_start_ns) {
        uint64_t skew = in->gpu0_start_ns - in->gpu1_start_ns;
        uint64_t add = d2rf_muldiv_u64(skew, bw1, 1000000000ull);
        add = u64_min(add, *b0);
        *b1 += add;
        *b0 -= add;
    }
}

static uint32_t token_authority_input(const D2RfTokenInput* in) {
    return
        in->product_linked &&
        in->packed_native &&
        in->material_overlap &&
        in->output_parity &&
        !in->command_rebuilds &&
        !in->kv_host_roundtrips &&
        !in->critical_path_nvme_reads &&
        !in->host_materializations &&
        !in->cpu_f32_expands &&
        !in->serial_gpu_chain &&
        !in->weight_migration &&
        !in->device_lost;
}

int d2rf_plan_token(
    D2RfState* s,
    const D2RfTokenInput* in,
    D2RfPlan* out)
{
    uint64_t active, local, not_local, local_exec_bytes;
    uint64_t b0, b1, e0, e1, remote_ns, cp;
    uint64_t capacity_free, prefetch;
    uint32_t hit, authority;

    if (!s || !s->initialized || !in || !out) return D2RF_ESTATE;
    if (!input_safe(in)) return D2RF_EINVAL;

    active = 0;
    active = sat_add_u64(active, in->packed_weight_bytes);
    active = sat_add_u64(active, in->kv_bytes);
    active = sat_add_u64(active, in->activation_bytes);
    active = sat_add_u64(active, in->reduction_bytes);
    if (active == UINT64_MAX) return D2RF_EOVERFLOW;

    local = sat_add_u64(in->vram0_local_bytes, in->vram1_local_bytes);
    if (local > active) local = active;
    not_local = active - local;
    hit = q16_ratio_u64(local, active);

    /*
      Local execution work excludes the explicitly remote portion. Remote
      servicing contributes separately to critical-path prediction.
    */
    local_exec_bytes = active - u64_min(not_local, active);
    split_local_work(in, local_exec_bytes, &b0, &b1);

    e0 = sat_add_u64(in->gpu0_start_ns,
                     d2rf_time_ns_for_bytes(b0, in->gpu0_bw_bytes_per_s));
    e1 = sat_add_u64(in->gpu1_start_ns,
                     d2rf_time_ns_for_bytes(b1, in->gpu1_bw_bytes_per_s));

    remote_ns = estimate_remote_ns(in);
    cp = u64_max(e0, e1);
    cp = sat_add_u64(cp, remote_ns);

    capacity_free = sat_add_u64(in->vram0_budget_free, in->vram1_budget_free);
    prefetch = u64_min(not_local, capacity_free);

    /*
      Require a 25% prefetch margin where capacity permits, bounded by the
      amount of bytes that are not yet local.
    */
    if (prefetch) {
        uint64_t enlarged = d2rf_muldiv_u64(prefetch, s->prefetch_margin_q16, D2RF_Q16_ONE);
        prefetch = u64_min(enlarged, not_local);
    }

    authority = token_authority_input(in);

    out->token_index = in->token_index;
    out->active_bytes_total = active;
    out->bytes_already_local = local;
    out->bytes_not_local = not_local;
    out->critical_remote_bytes =
        sat_add_u64(sat_add_u64(in->ram_bytes, in->mmap_bytes), in->nvme_bytes);

    out->gpu0_target_bytes = b0;
    out->gpu1_target_bytes = b1;
    out->prefetch_budget_bytes = prefetch;

    out->predicted_gpu0_end_ns = e0;
    out->predicted_gpu1_end_ns = e1;
    out->predicted_critical_ns = cp;
    out->predicted_finish_skew_ns = u64_absdiff(e0, e1);

    out->roofline_tps_milli = d2rf_tps_milli_from_ns(u64_max(e0, e1));
    out->sustained_tps_milli = d2rf_tps_milli_from_ns(cp);

    out->local_hit_ratio_q16 = hit;

    /*
      remote_penalty = 1 - local hit. It is deliberately simple and
      auditable; measured timing feeds the adaptive state separately.
    */
    out->remote_penalty_q16 = D2RF_Q16_ONE - hit;
    out->prefetch_required = not_local ? 1u : 0u;
    out->pin_selected_experts = (in->selected_experts != 0u);
    out->compact_reduce = (b0 != 0u && b1 != 0u);
    out->authority_eligible = authority;

    /*
      Roll back toward best-known work split if live measured CP has regressed
      by >5% and a best-known split exists.
    */
    if (in->measured_critical_ns &&
        s->best_critical_ns != UINT64_MAX &&
        s->last_gpu0_target_bytes &&
        s->last_gpu1_target_bytes)
    {
        uint64_t limit = d2rf_muldiv_u64(
            s->best_critical_ns,
            s->rollback_threshold_q16,
            D2RF_Q16_ONE);
        if (in->measured_critical_ns > limit) {
            out->gpu0_target_bytes = s->last_gpu0_target_bytes;
            out->gpu1_target_bytes = s->last_gpu1_target_bytes;
        }
    }

    return D2RF_OK;
}

static uint64_t ewma8(uint64_t oldv, uint64_t sample) {
    if (!oldv) return sample;
    return (oldv * 7ull + sample) / 8ull;
}

int d2rf_observe(
    D2RfState* s,
    const D2RfTokenInput* in,
    const D2RfPlan* plan)
{
    uint64_t t0, t1, bw0q20, bw1q20;
    if (!s || !s->initialized || !in || !plan) return D2RF_ESTATE;

    s->tokens_seen++;

    t0 = (in->gpu0_start_ns < plan->predicted_gpu0_end_ns)
       ? plan->predicted_gpu0_end_ns - in->gpu0_start_ns : 0;
    t1 = (in->gpu1_start_ns < plan->predicted_gpu1_end_ns)
       ? plan->predicted_gpu1_end_ns - in->gpu1_start_ns : 0;

    bw0q20 = t0 ? d2rf_muldiv_u64(plan->gpu0_target_bytes, D2RF_Q20_ONE, t0) : 0;
    bw1q20 = t1 ? d2rf_muldiv_u64(plan->gpu1_target_bytes, D2RF_Q20_ONE, t1) : 0;

    if (bw0q20) s->ewma_gpu0_bw_q20 = ewma8(s->ewma_gpu0_bw_q20, bw0q20);
    if (bw1q20) s->ewma_gpu1_bw_q20 = ewma8(s->ewma_gpu1_bw_q20, bw1q20);

    if (plan->authority_eligible) {
        s->authoritative_tokens++;
        if (in->measured_critical_ns &&
            in->measured_critical_ns < s->best_critical_ns)
        {
            s->best_critical_ns = in->measured_critical_ns;
            s->best_local_hit_q16 = plan->local_hit_ratio_q16;
            s->last_gpu0_target_bytes = plan->gpu0_target_bytes;
            s->last_gpu1_target_bytes = plan->gpu1_target_bytes;
        }
    }

    return D2RF_OK;
}

int d2rf_receipt(
    const D2RfTokenInput* in,
    const D2RfPlan* plan,
    D2RfReceipt* out)
{
    if (!in || !plan || !out) return D2RF_EINVAL;

    out->token_index = in->token_index;
    out->active_bytes_total = plan->active_bytes_total;
    out->bytes_already_local = plan->bytes_already_local;
    out->bytes_not_local = plan->bytes_not_local;
    out->critical_remote_bytes = plan->critical_remote_bytes;
    out->gpu0_target_bytes = plan->gpu0_target_bytes;
    out->gpu1_target_bytes = plan->gpu1_target_bytes;
    out->predicted_critical_ns = plan->predicted_critical_ns;
    out->measured_critical_ns = in->measured_critical_ns;
    out->predicted_finish_skew_ns = plan->predicted_finish_skew_ns;
    out->measured_finish_skew_ns = in->measured_finish_skew_ns;
    out->roofline_tps_milli = plan->roofline_tps_milli;
    out->sustained_tps_milli = plan->sustained_tps_milli;
    out->local_hit_ratio_q16 = plan->local_hit_ratio_q16;
    out->authority_eligible = plan->authority_eligible;

    out->command_rebuilds = in->command_rebuilds;
    out->kv_host_roundtrips = in->kv_host_roundtrips;
    out->critical_path_nvme_reads = in->critical_path_nvme_reads;
    out->host_materializations = in->host_materializations;
    out->cpu_f32_expands = in->cpu_f32_expands;
    out->serial_gpu_chain = in->serial_gpu_chain;
    out->weight_migration = in->weight_migration;
    out->device_lost = in->device_lost;
    out->output_parity = in->output_parity;
    out->product_linked = in->product_linked;
    out->packed_native = in->packed_native;
    out->material_overlap = in->material_overlap;
    return D2RF_OK;
}

int d2rf_receipt_authoritative(const D2RfReceipt* r) {
    if (!r) return 0;
    return
        r->authority_eligible &&
        r->product_linked &&
        r->packed_native &&
        r->material_overlap &&
        r->output_parity &&
        !r->command_rebuilds &&
        !r->kv_host_roundtrips &&
        !r->critical_path_nvme_reads &&
        !r->host_materializations &&
        !r->cpu_f32_expands &&
        !r->serial_gpu_chain &&
        !r->weight_migration &&
        !r->device_lost;
}
