#pragma once
/* Product bridge: same 84-byte Q2_K packed kernel family as aggregate PASS.
 * Aggregate harness ABI (optional witness / dual bandwidth):
 *   evidence/.../DEEP2_PACKED_Q2K_PRODUCT_DUAL_AGGREGATE_001/include/d2_product_packed_dual_q2k.h
 * Product decode GEMV (in-engine): VulkanCompute::DispatchGemvQuant(GGML_TYPE_Q2_K=10)
 *   → gemv_q2k.spv (block stride 84). Never Deep2_Q2_K_GEMV (72).
 * Env: RAWRXD_Q2K_PRODUCT_DECODE=1 */
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Optional: link aggregate object and call for dual BW witness only — never as
 * substitute for full_model_forward. Product path uses DispatchGemvQuant. */
struct D2PackedDualResult;
int d2_product_packed_dual_q2k_run(const char* gguf_path, uint32_t token_iters,
                                   struct D2PackedDualResult* out);
#ifdef __cplusplus
}
#endif
