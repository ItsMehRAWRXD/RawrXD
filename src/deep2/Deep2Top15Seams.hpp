#pragma once
/* Thin seam helpers: Top15 generators ↔ Deep2Engine N>0 decode.
 * SOURCE plumbing only — does not mint LIVE/PROMOTE authority. */
#include "d2_generators.h"

namespace Deep2 {

inline int Top15ValidateTokenTxn(uint64_t tokenIndex, D2GTokenTxn* out) {
    return d2g_token_transaction(tokenIndex, out);
}

inline int Top15AuthorityFromFlags(
    uint32_t product_linked, uint32_t packed_live, uint32_t material_overlap,
    uint32_t full_forward, uint32_t final_norm, uint32_t lm_head,
    uint32_t sampler_commit, uint32_t kv_advance, uint32_t output_parity,
    uint32_t host_fwd, uint32_t host_mat, uint32_t f32_expand,
    uint32_t nvme, uint32_t device_lost, uint32_t ext_rt,
    D2GAuthorityReceipt* out)
{
    D2GAuthorityInput in{};
    in.product_linked = product_linked;
    in.packed_live = packed_live;
    in.material_overlap = material_overlap;
    in.full_forward = full_forward;
    in.final_norm = final_norm;
    in.lm_head = lm_head;
    in.sampler_commit = sampler_commit;
    in.kv_advance = kv_advance;
    in.output_parity = output_parity;
    in.host_forward_calls = host_fwd;
    in.host_materializations = host_mat;
    in.cpu_f32_expands = f32_expand;
    in.critical_nvme_reads = nvme;
    in.device_lost = device_lost;
    in.external_runtime_calls = ext_rt;
    in.gpu0_forwards = 1;
    in.gpu1_forwards = 1;
    return d2g_authority_receipt(&in, out);
}

} // namespace Deep2
