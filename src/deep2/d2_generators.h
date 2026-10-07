#ifndef D2_GENERATORS_H
#define D2_GENERATORS_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

enum { D2G_OK=0, D2G_EINVAL=-1, D2G_ESTATE=-2, D2G_EAUTH=-3, D2G_ECAP=-4 };
enum { D2G_Q_UNKNOWN=0, D2G_Q2_K=2, D2G_Q3_K=3, D2G_Q4_K=4, D2G_Q5_K=5, D2G_Q6_K=6, D2G_Q8_0=8 };
enum { D2G_TIER_VRAM0=0, D2G_TIER_VRAM1=1, D2G_TIER_RAM=2, D2G_TIER_MMAP=3 };
enum { D2G_OP_EMBED=1, D2G_OP_FORWARD=2, D2G_OP_FINAL_NORM=3, D2G_OP_KV_ADVANCE=4, D2G_OP_LM_HEAD=5, D2G_OP_SAMPLE=6, D2G_OP_COMMIT=7, D2G_OP_PREFETCH=8 };

typedef struct { uint32_t ops[8]; uint32_t count; uint64_t token_index; } D2GTokenTxn;
typedef struct { uint64_t work0, work1; uint64_t pred_end0_ns, pred_end1_ns; uint32_t alignment; } D2GDualPlan;
typedef struct { uint64_t signature; uint64_t epoch; uint32_t rebuild; uint32_t command_count; } D2GPersistentPlan;
typedef struct { uint64_t resource_signature; uint64_t descriptor_epoch; uint32_t rebind; uint32_t set_count; } D2GDescriptorPlan;
typedef struct { uint64_t token_pos; uint64_t slot; uint64_t byte_offset; uint64_t bytes; uint32_t wrap; } D2GKvPlan;
typedef struct { uint64_t file_offset; uint64_t bytes; uint64_t deadline_token; uint32_t preferred_tier; uint32_t pin; } D2GResidencyReq;
typedef struct { D2GResidencyReq req[8]; uint32_t count; uint64_t for_token; } D2GPrefetchPlan;
typedef struct { uint32_t expert[8]; uint32_t lane[8]; uint32_t count; } D2GExpertPlan;
typedef struct { uint32_t quant; uint32_t executor_id; uint32_t packed_native; uint32_t fallback_forbidden; } D2GQuantPlan;
typedef struct { uint32_t row0_begin,row0_end,row1_begin,row1_end,tile_rows; } D2GLmHeadPlan;
typedef struct { uint32_t partial_count; uint32_t op; uint64_t bytes_in; uint64_t bytes_out; } D2GReducePlan;
typedef struct { uint32_t token_id; uint32_t valid; uint64_t logits_epoch; uint64_t commit_epoch; } D2GSamplerCommit;
typedef struct { uint32_t offset; uint32_t bytes; uint32_t final_chunk; uint32_t valid_utf8_boundary; } D2GStreamChunk;
typedef struct { uint64_t old_epoch,new_epoch; uint32_t cancel; uint32_t reset; uint32_t reusable; } D2GResetPlan;
typedef struct {
    uint32_t product_linked, packed_live, material_overlap, full_forward;
    uint32_t final_norm, lm_head, sampler_commit, kv_advance, output_parity;
    uint32_t sealed_logits_reuse, host_forward_calls, host_materializations, cpu_f32_expands;
    uint32_t command_rebuilds, kv_host_roundtrips, critical_nvme_reads, serial_gpu_chain;
    uint32_t weight_migration, synthetic_io, device_lost, external_runtime_calls;
    uint32_t gpu0_forwards, gpu1_forwards;
} D2GAuthorityInput;
typedef struct { uint32_t pass; uint32_t first_fail_bit; uint64_t pass_mask; } D2GAuthorityReceipt;

int d2g_token_transaction(uint64_t token_index, D2GTokenTxn* out);
int d2g_dual_finish_plan(uint64_t total_work, uint64_t cost0_q16, uint64_t cost1_q16, int64_t start1_minus_start0_ns, uint32_t alignment, D2GDualPlan* out);
int d2g_persistent_commands(uint64_t signature, uint64_t prior_signature, uint64_t epoch, uint32_t command_count, D2GPersistentPlan* out);
int d2g_descriptor_bind(uint64_t resource_signature, uint64_t prior_signature, uint64_t epoch, uint32_t set_count, D2GDescriptorPlan* out);
int d2g_kv_advance(uint64_t token_pos, uint64_t capacity_tokens, uint64_t bytes_per_token, D2GKvPlan* out);
int d2g_residency_request(uint64_t file_offset, uint64_t bytes, uint64_t deadline_token, uint64_t vram_free0, uint64_t vram_free1, uint32_t pin, D2GResidencyReq* out);
int d2g_prefetch_nplus1(const D2GResidencyReq* candidates, uint32_t count, uint64_t next_token, D2GPrefetchPlan* out);
int d2g_moe_expert_locality(const uint32_t* experts, uint32_t topk, uint32_t lane0_bias_q16, D2GExpertPlan* out);
int d2g_quant_dispatch(uint32_t quant, D2GQuantPlan* out);
int d2g_lm_head_tiles(uint32_t vocab_rows, uint32_t tile_rows, uint32_t lane0_share_q16, D2GLmHeadPlan* out);
int d2g_compact_reduce(uint32_t partial_count, uint64_t element_count, uint32_t element_bytes, D2GReducePlan* out);
int d2g_sampler_commit(uint32_t token_id, uint64_t logits_epoch, uint64_t prior_commit_epoch, D2GSamplerCommit* out);
int d2g_utf8_chunk(const uint8_t* bytes, uint32_t n, uint32_t offset, uint32_t max_chunk, D2GStreamChunk* out);
int d2g_cancel_reset(uint64_t epoch, uint32_t cancel, uint32_t reset, D2GResetPlan* out);
int d2g_authority_receipt(const D2GAuthorityInput* in, D2GAuthorityReceipt* out);

#ifdef __cplusplus
}
#endif
#endif
