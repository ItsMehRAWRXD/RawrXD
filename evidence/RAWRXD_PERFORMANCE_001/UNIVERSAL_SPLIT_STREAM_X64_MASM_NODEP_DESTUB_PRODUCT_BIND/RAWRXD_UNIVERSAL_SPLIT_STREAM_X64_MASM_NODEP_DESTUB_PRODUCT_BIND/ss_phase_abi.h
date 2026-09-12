/* C ABI matching ss_real_provider.inc — product-phase + D3D12 materializer */
#ifndef SS_PHASE_ABI_H
#define SS_PHASE_ABI_H
#include <stdint.h>
#define SS_E_DEEP2_INTEROP 100
#define SS_E_PRIMITIVE_HOLD 102
#define SS_E_LOGITS_HOLD 103
#define SS_E_LMHEAD_HOLD 104
#define SS_E_OUTPUT_NORM_HOLD 105
#define SS_E_LMHEAD_HOLD_POST_ONORM 106
#define SS_E_TOKEN_HOLD 107
#define SS_E_DECODE_HOLD 108
#define SS_DEEP2_IMPORTED 2
#define SS_DEEP2_CONSUMED 3
#define SS_DEEP2_MODEL_OP 4
#define SS_DEEP2_BLOCK_OP 5
#define SS_DEEP2_OUTPUT_NORM 6
#define SS_DEEP2_LOGITS 7
#define SS_DEEP2_TOKEN 8
#define SS_TOKEN_COMMIT_OK 2
typedef struct {
    uint64_t completed, gpu, readback_parity, device_id;
    uint64_t allocation_generation, device_handle, bytes, pci_device;
    uint64_t tensor_type, dim0, dim1, which_name, element_count;
} SSDeviceMaterialization;
typedef struct {
    void *ctx;
    int (*promote_fn)(void *, const void *, uint64_t, uint64_t, SSDeviceMaterialization *);
    int (*release_fn)(void *, void *, uint64_t);
    int (*consume_fn)(void *, SSDeviceMaterialization *);
} SSGpuBackend;
typedef struct {
    const char *shard1_path;
    uint64_t model_id, model_generation, op_ticket, owner_cookie;
    uint64_t host_budget, gpu_budget;
    SSGpuBackend *gpu_backend;
} SSPhaseArgs;
typedef struct {
    uint64_t phase_rc, full_model_init_bypassed, gguf_anchor_found, anchor_which;
    uint64_t file_offset, region_bytes, warm_pass, hot_pass, gpu, pci_device;
    uint64_t readback_parity, physical_reads, physical_bytes, mg_loads, mg_bytes;
    uint64_t hot_hits, deep2_consume_status, token_commit_status;
} SSPhaseResult;
#ifdef __cplusplus
extern "C" {
#endif
int ss_product_split_phase(SSPhaseArgs *args, SSPhaseResult *out);
int ss_d3d12_backend_init(void);
void ss_d3d12_backend_shutdown(void);
void ss_d3d12_set_shard(const char *path);
int ss_d3d12_promote(void *ctx, const void *host, uint64_t n, uint64_t gen,
                     SSDeviceMaterialization *out);
int ss_d3d12_release(void *ctx, void *handle, uint64_t agen);
int ss_d3d12_consume(void *ctx, SSDeviceMaterialization *mat);
#ifdef __cplusplus
}
#endif
#endif
