/* d2_engine_ssvk_bind16.cpp — 16-token decode bind authority (PROMOTE=0) */
#include "d2_engine_ssvk_bind16.h"
#include <stdio.h>
#include <string.h>

static int product_proof_ok(const D2PackedProductProof* p) {
    if (!p) return 0;
    return p->product_linked && p->packed_q2k_live &&
           p->material_same_token_overlap && p->aggregate_bw_authority &&
           p->gpu0_real_forwards && p->gpu1_real_forwards &&
           p->compact_merge_real && p->output_parity &&
           p->overlap_shorter_pm >= D2_BIND16_MIN_SHORTER_PM &&
           p->overlap_critical_pm >= D2_BIND16_MIN_CRITICAL_PM &&
           !p->full_dequant_buffer && !p->materialized_weight_bytes_nonzero &&
           !p->serial_gpu_chain && !p->weight_migration &&
           !p->synthetic_io && !p->device_lost && !p->critical_path_nvme_reads;
}

void d2bind16_init(D2EngineSsVkBind16* b) {
    if (!b) return;
    memset(b, 0, sizeof(*b));
    b->window.tokens_required = D2_BIND16_REQUIRED_TOKENS;
    b->window.promote = 0;
    b->initialized = 1;
}

void d2bind16_bind(D2EngineSsVkBind16* b, D2PackedProductRunFn fn, void* user) {
    if (!b) return;
    if (!b->initialized) d2bind16_init(b);
    b->run = fn;
    b->user = user;
}

void d2bind16_begin_token(D2EngineSsVkBind16* b, uint64_t token_ordinal,
                          const D2GpuCounterSnapshot* before) {
    if (!b) return;
    memset(&b->token, 0, sizeof(b->token));
    b->token.token_ordinal = token_ordinal;
    b->token.all_ops_ok = 1;
    b->token.min_shorter_pm = 1000;
    b->token.min_critical_pm = 1000;
    b->next_operator_ordinal = 0;
    if (before) b->snap_begin = *before;
    else memset(&b->snap_begin, 0, sizeof(b->snap_begin));
}

int d2bind16_dispatch_q2k(D2EngineSsVkBind16* b,
                          const D2PackedProductRequest* in) {
    if (!b || !in) return 0;
    ++b->token.q2k_ops_seen;
    if (!b->run || !in->packed_weights || !in->input || !in->output ||
        !in->rows || !in->cols || (in->cols % D2_Q2K_BLOCK_ELEMENTS) != 0) {
        b->token.all_ops_ok = 0;
        return 0;
    }
    const uint64_t blocks =
        (in->cols + D2_Q2K_BLOCK_ELEMENTS - 1) / D2_Q2K_BLOCK_ELEMENTS;
    const uint64_t row84 = blocks * (uint64_t)D2_Q2K_BLOCK_BYTES;
    const uint64_t need84 = in->rows * row84;
    const uint64_t row72 = blocks * 72ull;
    if (in->weight_bytes < need84) {
        if (in->weight_bytes >= in->rows * row72)
            b->token.stale_72_byte_path_used = 1;
        b->token.all_ops_ok = 0;
        return 0;
    }
    D2PackedProductRequest req = *in;
    req.token_ordinal = b->token.token_ordinal;
    req.operator_ordinal = b->next_operator_ordinal++;
    D2PackedProductProof p;
    memset(&p, 0, sizeof(p));
    const int rc = b->run ? b->run(b->user, &req, &p) : -1;
    if (rc != 0 || !product_proof_ok(&p)) {
        b->token.all_ops_ok = 0;
        if (p.device_lost) b->token.any_device_lost = 1;
        fprintf(stderr,
            "BIND16_DISPATCH_FAIL rc=%d tok=%llu op=%llu rows=%llu cols=%llu "
            "linked=%u packed=%u overlap=%u agg=%u g0=%u g1=%u compact=%u "
            "parity=%u short_pm=%u crit_pm=%u lost=%u name=%s\n",
            rc, (unsigned long long)req.token_ordinal,
            (unsigned long long)req.operator_ordinal,
            (unsigned long long)in->rows, (unsigned long long)in->cols,
            p.product_linked, p.packed_q2k_live, p.material_same_token_overlap,
            p.aggregate_bw_authority, p.gpu0_real_forwards, p.gpu1_real_forwards,
            p.compact_merge_real, p.output_parity, p.overlap_shorter_pm,
            p.overlap_critical_pm, p.device_lost,
            in->tensor_name ? in->tensor_name : "");
        fflush(stderr);
        return 0;
    }
    ++b->token.q2k_ops_product;
    b->token.gpu0_packed_bytes += p.gpu0_packed_bytes;
    b->token.gpu1_packed_bytes += p.gpu1_packed_bytes;
    b->token.overlap_ns_sum += p.overlap_ns;
    b->token.critical_path_ns_sum += p.critical_path_ns;
    if (p.overlap_shorter_pm < b->token.min_shorter_pm)
        b->token.min_shorter_pm = p.overlap_shorter_pm;
    if (p.overlap_critical_pm < b->token.min_critical_pm)
        b->token.min_critical_pm = p.overlap_critical_pm;
    b->token.any_dual_forward = 1;
    return 1;
}

void d2bind16_end_forward(D2EngineSsVkBind16* b,
                          const D2GpuCounterSnapshot* after,
                          int is_real_gpu_forward) {
    if (!b) return;
    b->token.is_real_gpu_forward = is_real_gpu_forward ? 1u : 0u;
    b->token.full_model_forward = is_real_gpu_forward ? 1u : 0u;
    if (!after) return;
    b->token.host_fwd_delta =
        (uint32_t)(after->host_forward_layer_calls -
                   b->snap_begin.host_forward_layer_calls);
    b->token.host_mat_delta =
        (uint32_t)(after->host_materializations -
                   b->snap_begin.host_materializations);
    b->token.cpu_f32_delta =
        (uint32_t)(after->cpu_f32_expands - b->snap_begin.cpu_f32_expands);
    b->token.slot0_delta =
        (uint32_t)(after->forward_slot0 - b->snap_begin.forward_slot0);
    b->token.slot1_delta =
        (uint32_t)(after->forward_slot1 - b->snap_begin.forward_slot1);
}

void d2bind16_note_tail(D2EngineSsVkBind16* b, int final_norm, int lm_head,
                        int kv_advance, int sampler_commit,
                        int sealed_logits_reuse) {
    if (!b) return;
    b->token.final_norm_real = final_norm ? 1u : 0u;
    b->token.lm_head_real = lm_head ? 1u : 0u;
    b->token.kv_advance_real = kv_advance ? 1u : 0u;
    b->token.sampler_commit_real = sampler_commit ? 1u : 0u;
    b->token.sealed_logits_reuse = sealed_logits_reuse ? 1u : 0u;
}

int d2bind16_commit_token(D2EngineSsVkBind16* b) {
    if (!b || !b->run) return 0;
    const D2DecodeTokenProof* t = &b->token;
    const int ok =
        t->q2k_ops_seen > 0 && t->q2k_ops_product == t->q2k_ops_seen &&
        t->all_ops_ok && t->any_dual_forward && !t->any_device_lost &&
        !t->stale_72_byte_path_used && t->full_model_forward &&
        t->final_norm_real && t->lm_head_real && t->sampler_commit_real &&
        t->kv_advance_real && !t->sealed_logits_reuse &&
        t->host_fwd_delta == 0 && t->host_mat_delta == 0 &&
        t->cpu_f32_delta == 0 && t->slot0_delta > 0 && t->slot1_delta > 0 &&
        t->is_real_gpu_forward &&
        t->min_shorter_pm >= D2_BIND16_MIN_SHORTER_PM &&
        t->min_critical_pm >= D2_BIND16_MIN_CRITICAL_PM;
    b->token.committed_pass = ok ? 1u : 0u;
    ++b->window.tokens_committed;
    if (ok) ++b->window.tokens_pass;
    else
        fprintf(stderr,
            "BIND16_COMMIT_FAIL tok=%llu q2=%llu/%llu ok=%u dual=%u "
            "host=%u/%u/%u slot=%u/%u real=%u short=%u crit=%u "
            "tail=%u/%u/%u/%u\n",
            (unsigned long long)t->token_ordinal,
            (unsigned long long)t->q2k_ops_product,
            (unsigned long long)t->q2k_ops_seen, t->all_ops_ok,
            t->any_dual_forward, t->host_fwd_delta, t->host_mat_delta,
            t->cpu_f32_delta, t->slot0_delta, t->slot1_delta,
            t->is_real_gpu_forward, t->min_shorter_pm, t->min_critical_pm,
            t->final_norm_real, t->lm_head_real, t->kv_advance_real,
            t->sampler_commit_real);
    b->window.authority =
        (b->window.tokens_pass >= b->window.tokens_required &&
         b->window.tokens_pass == b->window.tokens_committed &&
         b->window.tokens_required == D2_BIND16_REQUIRED_TOKENS)
            ? 1u
            : 0u;
    b->window.promote = 0;
    return ok;
}

const D2DecodeTokenProof* d2bind16_token(const D2EngineSsVkBind16* b) {
    return b ? &b->token : 0;
}
const D2Bind16Window* d2bind16_window(const D2EngineSsVkBind16* b) {
    return b ? &b->window : 0;
}
