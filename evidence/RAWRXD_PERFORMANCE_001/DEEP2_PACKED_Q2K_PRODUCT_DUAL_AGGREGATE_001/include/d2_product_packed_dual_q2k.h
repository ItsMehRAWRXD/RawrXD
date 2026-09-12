#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Product ABI: packed Q2_K dual aggregate (MATERIALIZED_WEIGHT_BYTES=0) */
struct D2PackedDualResult {
    uint64_t gpu0_bytes, gpu1_bytes;
    uint64_t gpu0_fwd, gpu1_fwd;
    uint64_t overlap_ns, critical_path_ns, aggregate_bps;
    uint32_t serial_chain, weight_migration, synthetic_io, device_lost;
    uint32_t compact_merge, material_overlap, packed_q2k_live, product_linked;
    uint32_t tokens_run, full_dequant, materialized_weight_bytes;
    uint32_t aggregate_bw_authority;
};
int d2_product_packed_dual_q2k_run(const char* gguf_path, uint32_t token_iters,
                                   D2PackedDualResult* out);
#ifdef __cplusplus
}
#endif
