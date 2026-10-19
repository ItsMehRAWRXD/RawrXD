#ifndef D2U_H
#define D2U_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define D2U_MAX_DIMS 4u
#define D2U_MAX_PATH 1024u
#define D2U_MAX_NAME 192u
#define D2U_MAX_SHARDS 64u
#define D2U_MAX_TOPK 16u
#define D2U_GGUF_MAGIC 0x46554747u

/* GGML tensor type numbers used by GGUF. */
enum {
    D2U_F32=0, D2U_F16=1, D2U_Q4_0=2, D2U_Q4_1=3,
    D2U_Q5_0=6, D2U_Q5_1=7, D2U_Q8_0=8, D2U_Q8_1=9,
    D2U_Q2_K=10, D2U_Q3_K=11, D2U_Q4_K=12, D2U_Q5_K=13,
    D2U_Q6_K=14, D2U_Q8_K=15, D2U_BF16=30
};

typedef enum {
    D2U_OK=0,
    D2U_E_ARG=-1, D2U_E_IO=-2, D2U_E_FORMAT=-3, D2U_E_OOM=-4,
    D2U_E_RANGE=-5, D2U_E_TYPE=-6, D2U_E_TENSOR=-7, D2U_E_AUTH=-8,
    D2U_E_BUDGET=-9, D2U_E_STATE=-10, D2U_E_NUMERIC=-11
} d2u_status;

typedef struct {
    char path[D2U_MAX_PATH];
    FILE *fp;
    uint64_t size;
    uint64_t data_offset;
    uint64_t tensor_count;
    uint64_t kv_count;
    uint32_t gguf_version;
} d2u_shard;

typedef struct {
    char name[D2U_MAX_NAME];
    uint32_t type;
    uint32_t n_dims;
    uint64_t dims[D2U_MAX_DIMS];
    uint64_t n_elem;
    uint64_t size_bytes;
    uint64_t data_offset;
    uint32_t shard;
} d2u_tensor;

typedef struct {
    char architecture[32];
    char name[128];
    uint32_t alignment;
    uint32_t block_count;
    uint32_t leading_dense_block_count;
    uint32_t embedding_length;
    uint32_t feed_forward_length;
    uint32_t vocab_size;
    uint32_t context_length;
    uint32_t expert_count;
    uint32_t expert_used_count;
    uint32_t expert_shared_count;
    uint32_t q_lora_rank;
    uint32_t kv_lora_rank;
    uint32_t qk_nope_head_dim;
    uint32_t rope_dimension_count;
    uint32_t v_head_dim;
    uint32_t attention_head_count;
    uint32_t attention_key_length;   /* GGUF deepseek2.attention.key_length when present */
    uint32_t attention_value_length; /* GGUF deepseek2.attention.value_length when present */
    uint32_t expert_feed_forward_length;
    uint32_t expert_group_count;
    uint32_t expert_group_used_count;
    float expert_weights_scale;
    float rms_norm_eps;
    float rope_freq_base;
    float rope_scaling_factor;
    float rope_scaling_original_context_length;
    float rope_scaling_beta_fast;
    float rope_scaling_beta_slow;
    float rope_scaling_mscale;
    float rope_scaling_mscale_all_dim;
    uint8_t expert_weights_norm;
    uint8_t has_expert_bias;
    uint8_t derived_qk_nope;
    uint8_t derived_v_head;
} d2u_config;

typedef struct {
    d2u_shard shards[D2U_MAX_SHARDS];
    uint32_t shard_count;
    d2u_tensor *tensors;
    size_t tensor_count;
    size_t tensor_cap;
    d2u_config cfg;
    uint64_t metadata_bytes;
} d2u_model;

typedef enum {
    D2U_OP_NONE=0,
    D2U_OP_EMBED=1,
    D2U_OP_NORM=2,
    D2U_OP_MLA_Q=3,
    D2U_OP_MLA_KV=4,
    D2U_OP_MLA_SCORE=5,
    D2U_OP_MLA_OUT=6,
    D2U_OP_ROUTER=7,
    D2U_OP_EXPERT=8,
    D2U_OP_SHARED_EXPERT=9,
    D2U_OP_DENSE_FFN=10,
    D2U_OP_OUTPUT=11,
    D2U_OP_KV_COMMIT=12,
    D2U_OP_TOKEN_COMMIT=13
} d2u_op_kind;

typedef enum {
    D2U_IO_NONE=0,
    D2U_IO_CURRENT_TENSOR=1,
    D2U_IO_ROUTER_TOPK_EXPERT=2,
    D2U_IO_SHARED_EXPERT=3,
    D2U_IO_CURRENT_TOKEN_EMBED=4,
    D2U_IO_CURRENT_OUTPUT_ROW=5
} d2u_io_reason;

typedef struct {
    uint64_t owner_cookie;
    uint64_t next_ticket;
    uint64_t active_ticket;
    uint32_t token_index;
    uint32_t layer_index;
    d2u_op_kind op;
    d2u_io_reason reason;
    uint8_t scheduler_authority;
    uint8_t op_open;
    uint8_t decode_authority;
    uint8_t token_commit_pass;
    uint8_t product_open_pass;
    uint8_t session_enter_pass;
    uint8_t promoted;
    uint8_t failed;
    uint64_t generated_tokens;
    uint64_t io_reads;
    uint64_t io_bytes;
    uint64_t background_submits;
    uint64_t predictive_loads;
    uint64_t rejected_io;
    uint64_t completed_layers;
} d2u_authority;

typedef struct {
    uint32_t ids[D2U_MAX_TOPK];
    float weights[D2U_MAX_TOPK];
    uint32_t count;
} d2u_route;

typedef struct {
    uint32_t layer, expert;
    uint64_t tick, bytes;
    uint8_t *gate, *up, *down;
    uint64_t gate_bytes, up_bytes, down_bytes;
} d2u_cached_expert;
typedef struct {
    d2u_cached_expert *entries;
    size_t count, cap;
    uint64_t budget_bytes, used_bytes, tick, hits, misses, evictions;
} d2u_expert_cache;

typedef struct {
    uint32_t max_context;
    uint32_t layers;
    uint32_t kv_rank;
    uint32_t rope_dim;
    uint32_t length;
    uint32_t capacity;
    float *latent; /* [layers][max_context][kv_rank] */
    float *pe;     /* [layers][max_context][rope_dim] */
} d2u_mla_cache;

/* GGUF/model index. */
int d2u_model_open(d2u_model *m, int argc, const char **paths);
void d2u_model_close(d2u_model *m);
const d2u_tensor *d2u_tensor_find(const d2u_model *m, const char *name);
int d2u_validate_deepseek2(d2u_model *m, char *why, size_t why_n);

/* Foreground authority and exact reads. */
int d2u_authority_init(d2u_authority *a, uint64_t owner_cookie);
int d2u_scheduler_claim(d2u_authority *a, uint64_t owner_cookie);
int d2u_op_begin(d2u_authority *a, uint64_t owner_cookie, uint32_t token, uint32_t layer, d2u_op_kind op, d2u_io_reason reason, uint64_t *ticket);
int d2u_op_end(d2u_authority *a, uint64_t owner_cookie, uint64_t ticket, int success);
int d2u_tensor_read(const d2u_model *m, d2u_authority *a, uint64_t ticket, const d2u_tensor *t, uint64_t off, void *dst, size_t n, d2u_io_reason required_reason);
int d2u_note_layer_complete(d2u_authority *a, uint32_t layer, uint32_t expected_layers);
int d2u_mint_decode_authority(d2u_authority *a, uint32_t expected_layers, int kv_commit_ok, int logits_ok);
int d2u_commit_token(d2u_authority *a, uint64_t owner_cookie, uint32_t token_id);
int d2u_try_promote(d2u_authority *a, int model_valid);

/* Quant kernels / tensor math. */
size_t d2u_type_block_size(uint32_t type);
size_t d2u_type_bytes_per_block(uint32_t type);
int d2u_dequant_block(uint32_t type, const uint8_t *src, float *dst, size_t dst_cap, size_t *values_out);
int d2u_tensor_dot_row(const d2u_model *m, d2u_authority *a, uint64_t ticket, const d2u_tensor *t, uint64_t row, const float *x, size_t x_n, float *out, d2u_io_reason reason);
int d2u_tensor_gemv(const d2u_model *m, d2u_authority *a, uint64_t ticket, const d2u_tensor *t, const float *x, size_t x_n, float *y, size_t y_n, d2u_io_reason reason);
int d2u_tensor_read_row_f32(const d2u_model *m, d2u_authority *a, uint64_t ticket, const d2u_tensor *t, uint64_t row, float *dst, size_t n, d2u_io_reason reason);

/* Deterministic inference router. */
int d2u_route_deepseek(const d2u_model *m, d2u_authority *a, uint64_t ticket, uint32_t layer, const float *hidden, d2u_route *route);

/* MLA absorb path. */
int d2u_mla_cache_init(d2u_mla_cache *c, uint32_t layers, uint32_t max_context, uint32_t kv_rank, uint32_t rope_dim);
void d2u_mla_cache_free(d2u_mla_cache *c);
int d2u_mla_forward(const d2u_model *m, d2u_authority *a, uint64_t owner, uint32_t token, uint32_t layer, const float *hidden, float *out, d2u_mla_cache *cache);

/* Dense/shared/routed FFN. */
int d2u_expert_cache_init(d2u_expert_cache *c, uint64_t budget_bytes);
void d2u_expert_cache_free(d2u_expert_cache *c);
int d2u_ffn_layer(const d2u_model *m, d2u_authority *a, uint64_t owner, uint32_t token, uint32_t layer, const float *hidden, float *out, d2u_route *route_out, d2u_expert_cache *cache);

/* Runtime product path. */
typedef struct {
    d2u_model model;
    d2u_authority auth;
    d2u_mla_cache cache;
    d2u_expert_cache expert_cache;
    float *hidden;
    float *scratch;
    float *logits;
    uint64_t owner_cookie;
    int model_valid;
} d2u_runtime;
int d2u_runtime_open(d2u_runtime *r, uint64_t owner_cookie, int argc, const char **paths);
void d2u_runtime_close(d2u_runtime *r);
int d2u_runtime_enter(d2u_runtime *r);
int d2u_runtime_step(d2u_runtime *r, uint32_t input_token, uint32_t token_index, uint32_t *output_token);

#ifdef __cplusplus
}
#endif
#endif
