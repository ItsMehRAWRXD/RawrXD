//===============================================================================
// GGML Pure MASM Implementation - C Wrapper
// Provides GGML-compatible API using pure assembly operations
//===============================================================================

#include "ggml_masm_pure.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#endif

//===============================================================================
// Internal Structures
//===============================================================================

typedef struct ggml_masm_context {
    void* mem_buffer;
    size_t mem_size;
    size_t mem_used;
    bool no_alloc;
    void* scratch_buffer;
    size_t scratch_size;
} ggml_masm_context_internal;

typedef struct ggml_masm_cgraph {
    ggml_masm_tensor** nodes;
    int n_nodes;
    int n_nodes_max;
} ggml_masm_cgraph_internal;

//===============================================================================
// Memory Management
//===============================================================================

ggml_masm_context* ggml_masm_init(const ggml_masm_init_params* params) {
    if (!params) return NULL;
    
    ggml_masm_context_internal* ctx = (ggml_masm_context_internal*)malloc(sizeof(ggml_masm_context_internal));
    if (!ctx) return NULL;
    
    ctx->mem_size = params->mem_size;
    ctx->mem_used = 0;
    ctx->no_alloc = params->no_alloc;
    ctx->scratch_size = 1024 * 1024; // 1MB scratch
    
    if (params->mem_buffer) {
        ctx->mem_buffer = params->mem_buffer;
    } else {
        ctx->mem_buffer = malloc(params->mem_size);
        if (!ctx->mem_buffer) {
            free(ctx);
            return NULL;
        }
    }
    
    ctx->scratch_buffer = malloc(ctx->scratch_size);
    if (!ctx->scratch_buffer) {
        if (!params->mem_buffer) free(ctx->mem_buffer);
        free(ctx);
        return NULL;
    }
    
    memset(ctx->mem_buffer, 0, ctx->mem_size);
    
    return (ggml_masm_context*)ctx;
}

void ggml_masm_free(ggml_masm_context* ctx) {
    if (!ctx) return;
    
    ggml_masm_context_internal* ctx_int = (ggml_masm_context_internal*)ctx;
    
    if (ctx_int->scratch_buffer) {
        free(ctx_int->scratch_buffer);
    }
    
    if (!ctx_int->no_alloc && ctx_int->mem_buffer) {
        free(ctx_int->mem_buffer);
    }
    
    free(ctx_int);
}

void* ggml_masm_get_mem_buffer(ggml_masm_context* ctx) {
    if (!ctx) return NULL;
    return ((ggml_masm_context_internal*)ctx)->mem_buffer;
}

size_t ggml_masm_get_mem_size(ggml_masm_context* ctx) {
    if (!ctx) return 0;
    return ((ggml_masm_context_internal*)ctx)->mem_size;
}

//===============================================================================
// Tensor Allocation
//===============================================================================

static size_t ggml_masm_type_size(ggml_masm_type type) {
    switch (type) {
        case GGML_MASM_TYPE_F32: return sizeof(float);
        case GGML_MASM_TYPE_F16: return sizeof(uint16_t);
        case GGML_MASM_TYPE_Q4_0: return sizeof(uint8_t);
        case GGML_MASM_TYPE_Q8_0: return sizeof(uint8_t);
        default: return sizeof(float);
    }
}

static void ggml_masm_set_tensor_params(ggml_masm_tensor* tensor, ggml_masm_type type,
                                         int64_t ne0, int64_t ne1, int64_t ne2, int64_t ne3) {
    tensor->type = type;
    tensor->n_dims = 4;
    tensor->ne[0] = ne0;
    tensor->ne[1] = ne1;
    tensor->ne[2] = ne2;
    tensor->ne[3] = ne3;
    
    size_t type_size = ggml_masm_type_size(type);
    tensor->nb[0] = type_size;
    tensor->nb[1] = tensor->nb[0] * ne0;
    tensor->nb[2] = tensor->nb[1] * ne1;
    tensor->nb[3] = tensor->nb[2] * ne2;
}

ggml_masm_tensor* ggml_masm_new_tensor_1d(ggml_masm_context* ctx, ggml_masm_type type, int64_t ne0) {
    return ggml_masm_new_tensor_4d(ctx, type, ne0, 1, 1, 1);
}

ggml_masm_tensor* ggml_masm_new_tensor_2d(ggml_masm_context* ctx, ggml_masm_type type,
                                           int64_t ne0, int64_t ne1) {
    return ggml_masm_new_tensor_4d(ctx, type, ne0, ne1, 1, 1);
}

ggml_masm_tensor* ggml_masm_new_tensor_3d(ggml_masm_context* ctx, ggml_masm_type type,
                                           int64_t ne0, int64_t ne1, int64_t ne2) {
    return ggml_masm_new_tensor_4d(ctx, type, ne0, ne1, ne2, 1);
}

ggml_masm_tensor* ggml_masm_new_tensor_4d(ggml_masm_context* ctx, ggml_masm_type type,
                                           int64_t ne0, int64_t ne1, int64_t ne2, int64_t ne3) {
    if (!ctx) return NULL;
    
    ggml_masm_context_internal* ctx_int = (ggml_masm_context_internal*)ctx;
    
    size_t tensor_size = sizeof(ggml_masm_tensor);
    size_t data_size = ne0 * ne1 * ne2 * ne3 * ggml_masm_type_size(type);
    size_t total_size = tensor_size + data_size + 64; // 64-byte alignment
    
    if (ctx_int->mem_used + total_size > ctx_int->mem_size) {
        fprintf(stderr, "GGML MASM: Out of memory (requested %zu, available %zu)\n",
                total_size, ctx_int->mem_size - ctx_int->mem_used);
        return NULL;
    }
    
    ggml_masm_tensor* tensor = (ggml_masm_tensor*)((char*)ctx_int->mem_buffer + ctx_int->mem_used);
    ctx_int->mem_used += tensor_size;
    
    // Align data to 64 bytes
    ctx_int->mem_used = (ctx_int->mem_used + 63) & ~63;
    tensor->data = (char*)ctx_int->mem_buffer + ctx_int->mem_used;
    ctx_int->mem_used += data_size;
    
    ggml_masm_set_tensor_params(tensor, type, ne0, ne1, ne2, ne3);
    memset(tensor->name, 0, sizeof(tensor->name));
    
    return tensor;
}

//===============================================================================
// Tensor Data Access
//===============================================================================

void* ggml_masm_get_data(ggml_masm_tensor* tensor) {
    return tensor ? tensor->data : NULL;
}

size_t ggml_masm_nbytes(const ggml_masm_tensor* tensor) {
    if (!tensor) return 0;
    return tensor->ne[0] * tensor->ne[1] * tensor->ne[2] * tensor->ne[3] * 
           ggml_masm_type_size(tensor->type);
}

float* ggml_masm_get_f32_1d(const ggml_masm_tensor* tensor, int i) {
    if (!tensor || tensor->type != GGML_MASM_TYPE_F32) return NULL;
    return (float*)((char*)tensor->data + i * tensor->nb[0]);
}

void ggml_masm_set_f32_1d(ggml_masm_tensor* tensor, int i, float value) {
    if (!tensor || tensor->type != GGML_MASM_TYPE_F32) return;
    *(float*)((char*)tensor->data + i * tensor->nb[0]) = value;
}

int64_t ggml_masm_nelements(const ggml_masm_tensor* tensor) {
    if (!tensor) return 0;
    return tensor->ne[0] * tensor->ne[1] * tensor->ne[2] * tensor->ne[3];
}

int64_t ggml_masm_nrows(const ggml_masm_tensor* tensor) {
    if (!tensor) return 0;
    return tensor->ne[1] * tensor->ne[2] * tensor->ne[3];
}

//===============================================================================
// Tensor Operations (High-level wrappers around assembly)
//===============================================================================

ggml_masm_tensor* ggml_masm_add(ggml_masm_context* ctx, ggml_masm_tensor* a, ggml_masm_tensor* b) {
    if (!ctx || !a || !b) return NULL;
    
    ggml_masm_tensor* result = ggml_masm_new_tensor_4d(ctx, a->type,
                                                        a->ne[0], a->ne[1], a->ne[2], a->ne[3]);
    if (!result) return NULL;
    
    size_t count = ggml_masm_nelements(a);
    ggml_masm_add_f32((float*)result->data, (float*)a->data, (float*)b->data, count);
    
    return result;
}

ggml_masm_tensor* ggml_masm_mul(ggml_masm_context* ctx, ggml_masm_tensor* a, ggml_masm_tensor* b) {
    if (!ctx || !a || !b) return NULL;
    
    ggml_masm_tensor* result = ggml_masm_new_tensor_4d(ctx, a->type,
                                                        a->ne[0], a->ne[1], a->ne[2], a->ne[3]);
    if (!result) return NULL;
    
    size_t count = ggml_masm_nelements(a);
    ggml_masm_mul_f32((float*)result->data, (float*)a->data, (float*)b->data, count);
    
    return result;
}

ggml_masm_tensor* ggml_masm_scale(ggml_masm_context* ctx, ggml_masm_tensor* a, float s) {
    if (!ctx || !a) return NULL;
    
    ggml_masm_tensor* result = ggml_masm_new_tensor_4d(ctx, a->type,
                                                        a->ne[0], a->ne[1], a->ne[2], a->ne[3]);
    if (!result) return NULL;
    
    size_t count = ggml_masm_nelements(a);
    ggml_masm_copy_f32((float*)result->data, (float*)a->data, count);
    ggml_masm_scale_f32((float*)result->data, (float*)result->data, count, s);
    
    return result;
}

ggml_masm_tensor* ggml_masm_silu(ggml_masm_context* ctx, ggml_masm_tensor* a) {
    if (!ctx || !a) return NULL;
    
    ggml_masm_tensor* result = ggml_masm_new_tensor_4d(ctx, a->type,
                                                        a->ne[0], a->ne[1], a->ne[2], a->ne[3]);
    if (!result) return NULL;
    
    size_t count = ggml_masm_nelements(a);
    ggml_masm_silu_f32((float*)result->data, (float*)a->data, count);
    
    return result;
}

ggml_masm_tensor* ggml_masm_softmax(ggml_masm_context* ctx, ggml_masm_tensor* a) {
    if (!ctx || !a) return NULL;
    
    ggml_masm_tensor* result = ggml_masm_new_tensor_4d(ctx, a->type,
                                                        a->ne[0], a->ne[1], a->ne[2], a->ne[3]);
    if (!result) return NULL;
    
    // Softmax is applied per row
    int64_t nrows = ggml_masm_nrows(a);
    int64_t ncols = a->ne[0];
    
    for (int64_t i = 0; i < nrows; i++) {
        float* src_row = (float*)((char*)a->data + i * a->nb[1]);
        float* dst_row = (float*)((char*)result->data + i * result->nb[1]);
        ggml_masm_softmax_f32(dst_row, src_row, ncols);
    }
    
    return result;
}

ggml_masm_tensor* ggml_masm_rms_norm(ggml_masm_context* ctx, ggml_masm_tensor* a, float eps) {
    if (!ctx || !a) return NULL;
    
    ggml_masm_tensor* result = ggml_masm_new_tensor_4d(ctx, a->type,
                                                        a->ne[0], a->ne[1], a->ne[2], a->ne[3]);
    if (!result) return NULL;
    
    // RMS norm is applied per row
    int64_t nrows = ggml_masm_nrows(a);
    int64_t ncols = a->ne[0];
    
    for (int64_t i = 0; i < nrows; i++) {
        float* src_row = (float*)((char*)a->data + i * a->nb[1]);
        float* dst_row = (float*)((char*)result->data + i * result->nb[1]);
        ggml_masm_rms_norm_f32(dst_row, src_row, ncols);
    }
    
    return result;
}

ggml_masm_tensor* ggml_masm_matmul(ggml_masm_context* ctx, ggml_masm_tensor* a, ggml_masm_tensor* b) {
    if (!ctx || !a || !b) return NULL;
    
    // A: [M, K], B: [K, N], Result: [M, N]
    int64_t M = a->ne[1];
    int64_t K = a->ne[0];
    int64_t N = b->ne[0];
    
    ggml_masm_tensor* result = ggml_masm_new_tensor_2d(ctx, a->type, N, M);
    if (!result) return NULL;
    
    ggml_masm_matmul_f32((float*)result->data, (float*)a->data, (float*)b->data, M, N, K);
    
    return result;
}

ggml_masm_tensor* ggml_masm_rope(ggml_masm_context* ctx, ggml_masm_tensor* a, int pos) {
    if (!ctx || !a) return NULL;
    
    ggml_masm_tensor* result = ggml_masm_new_tensor_4d(ctx, a->type,
                                                        a->ne[0], a->ne[1], a->ne[2], a->ne[3]);
    if (!result) return NULL;
    
    // RoPE is applied per head
    int64_t n_heads = a->ne[1];
    int64_t head_dim = a->ne[0];
    
    for (int64_t h = 0; h < n_heads; h++) {
        float* src_head = (float*)((char*)a->data + h * a->nb[1]);
        float* dst_head = (float*)((char*)result->data + h * result->nb[1]);
        ggml_masm_rope_f32(dst_head, src_head, head_dim, pos);
    }
    
    return result;
}

//===============================================================================
// Graph Computation
//===============================================================================

ggml_masm_cgraph* ggml_masm_new_graph(ggml_masm_context* ctx) {
    if (!ctx) return NULL;
    
    ggml_masm_cgraph_internal* cgraph = (ggml_masm_cgraph_internal*)malloc(sizeof(ggml_masm_cgraph_internal));
    if (!cgraph) return NULL;
    
    cgraph->n_nodes = 0;
    cgraph->n_nodes_max = 1024;
    cgraph->nodes = (ggml_masm_tensor**)malloc(cgraph->n_nodes_max * sizeof(ggml_masm_tensor*));
    
    if (!cgraph->nodes) {
        free(cgraph);
        return NULL;
    }
    
    return (ggml_masm_cgraph*)cgraph;
}

void ggml_masm_build_forward_expand(ggml_masm_cgraph* cgraph, ggml_masm_tensor* tensor) {
    if (!cgraph || !tensor) return;
    
    ggml_masm_cgraph_internal* cg = (ggml_masm_cgraph_internal*)cgraph;
    
    if (cg->n_nodes >= cg->n_nodes_max) {
        cg->n_nodes_max *= 2;
        cg->nodes = (ggml_masm_tensor**)realloc(cg->nodes, cg->n_nodes_max * sizeof(ggml_masm_tensor*));
    }
    
    cg->nodes[cg->n_nodes++] = tensor;
}

void ggml_masm_graph_compute(ggml_masm_context* ctx, ggml_masm_cgraph* cgraph) {
    if (!ctx || !cgraph) return;
    
    // In this simplified implementation, operations are computed eagerly
    // A full implementation would build a proper computation graph and schedule execution
    
    ggml_masm_cgraph_internal* cg = (ggml_masm_cgraph_internal*)cgraph;
    
    // Mark all nodes as computed
    for (int i = 0; i < cg->n_nodes; i++) {
        // In a full implementation, this would trigger actual computation
        // For now, operations are computed at creation time
    }
}

//===============================================================================
// KV Cache
//===============================================================================

bool ggml_masm_kv_cache_init(ggml_masm_kv_cache* cache, ggml_masm_context* ctx,
                              int n_ctx, int n_embd, int n_head) {
    if (!cache || !ctx) return false;
    
    int head_dim = n_embd / n_head;
    
    cache->k = ggml_masm_new_tensor_3d(ctx, GGML_MASM_TYPE_F32, head_dim, n_head, n_ctx);
    cache->v = ggml_masm_new_tensor_3d(ctx, GGML_MASM_TYPE_F32, head_dim, n_head, n_ctx);
    
    if (!cache->k || !cache->v) return false;
    
    cache->n_ctx = n_ctx;
    cache->n_used = 0;
    cache->ctx = ctx;
    
    return true;
}

void ggml_masm_kv_cache_free(ggml_masm_kv_cache* cache) {
    if (!cache) return;
    // Memory is freed when context is freed
    cache->k = NULL;
    cache->v = NULL;
    cache->n_used = 0;
}

void ggml_masm_kv_cache_clear(ggml_masm_kv_cache* cache) {
    if (!cache) return;
    cache->n_used = 0;
    if (cache->k) memset(cache->k->data, 0, ggml_masm_nbytes(cache->k));
    if (cache->v) memset(cache->v->data, 0, ggml_masm_nbytes(cache->v));
}

//===============================================================================
// Sampling
//===============================================================================

int ggml_masm_sample_greedy(const float* logits, int n_vocab) {
    if (!logits || n_vocab <= 0) return 0;
    
    int max_idx = 0;
    float max_val = logits[0];
    
    for (int i = 1; i < n_vocab; i++) {
        if (logits[i] > max_val) {
            max_val = logits[i];
            max_idx = i;
        }
    }
    
    return max_idx;
}

void ggml_masm_apply_temperature(float* logits, int n_vocab, float temp) {
    if (!logits || n_vocab <= 0 || temp <= 0) return;
    
    float inv_temp = 1.0f / temp;
    for (int i = 0; i < n_vocab; i++) {
        logits[i] *= inv_temp;
    }
}

int ggml_masm_sample_top_k(const float* logits, int n_vocab, int k) {
    if (!logits || n_vocab <= 0) return 0;
    if (k > n_vocab) k = n_vocab;
    
    // Simple implementation: find k largest and sample from them
    // In production, use a proper sorting algorithm
    
    int* indices = (int*)malloc(k * sizeof(int));
    float* values = (float*)malloc(k * sizeof(float));
    
    if (!indices || !values) {
        free(indices);
        free(values);
        return ggml_masm_sample_greedy(logits, n_vocab);
    }
    
    // Initialize with first k elements
    for (int i = 0; i < k; i++) {
        indices[i] = i;
        values[i] = logits[i];
    }
    
    // Find k largest
    for (int i = k; i < n_vocab; i++) {
        // Find minimum in current top-k
        int min_idx = 0;
        for (int j = 1; j < k; j++) {
            if (values[j] < values[min_idx]) min_idx = j;
        }
        
        // Replace if current is larger
        if (logits[i] > values[min_idx]) {
            values[min_idx] = logits[i];
            indices[min_idx] = i;
        }
    }
    
    // Apply softmax to top-k
    float max_val = values[0];
    for (int i = 1; i < k; i++) {
        if (values[i] > max_val) max_val = values[i];
    }
    
    float sum = 0;
    for (int i = 0; i < k; i++) {
        values[i] = expf(values[i] - max_val);
        sum += values[i];
    }
    
    // Sample
    float r = (float)rand() / RAND_MAX;
    float cumsum = 0;
    int result = indices[0];
    
    for (int i = 0; i < k; i++) {
        cumsum += values[i] / sum;
        if (r <= cumsum) {
            result = indices[i];
            break;
        }
    }
    
    free(indices);
    free(values);
    return result;
}

int ggml_masm_sample_top_p(const float* logits, int n_vocab, float p) {
    if (!logits || n_vocab <= 0 || p <= 0 || p > 1) {
        return ggml_masm_sample_greedy(logits, n_vocab);
    }
    
    // Sort logits in descending order
    int* indices = (int*)malloc(n_vocab * sizeof(int));
    float* sorted = (float*)malloc(n_vocab * sizeof(float));
    
    if (!indices || !sorted) {
        free(indices);
        free(sorted);
        return ggml_masm_sample_greedy(logits, n_vocab);
    }
    
    for (int i = 0; i < n_vocab; i++) {
        indices[i] = i;
        sorted[i] = logits[i];
    }
    
    // Simple bubble sort (for small vocab, use faster algorithm for large)
    for (int i = 0; i < n_vocab - 1; i++) {
        for (int j = 0; j < n_vocab - i - 1; j++) {
            if (sorted[j] < sorted[j + 1]) {
                float temp = sorted[j];
                sorted[j] = sorted[j + 1];
                sorted[j + 1] = temp;
                
                int temp_idx = indices[j];
                indices[j] = indices[j + 1];
                indices[j + 1] = temp_idx;
            }
        }
    }
    
    // Apply softmax
    float max_val = sorted[0];
    float sum = 0;
    for (int i = 0; i < n_vocab; i++) {
        sorted[i] = expf(sorted[i] - max_val);
        sum += sorted[i];
    }
    
    // Normalize
    for (int i = 0; i < n_vocab; i++) {
        sorted[i] /= sum;
    }
    
    // Find nucleus
    float cumsum = 0;
    int nucleus_size = n_vocab;
    for (int i = 0; i < n_vocab; i++) {
        cumsum += sorted[i];
        if (cumsum >= p) {
            nucleus_size = i + 1;
            break;
        }
    }
    
    // Sample from nucleus
    float r = (float)rand() / RAND_MAX;
    cumsum = 0;
    int result = indices[0];
    
    for (int i = 0; i < nucleus_size; i++) {
        cumsum += sorted[i];
        if (r <= cumsum) {
            result = indices[i];
            break;
        }
    }
    
    free(indices);
    free(sorted);
    return result;
}

//===============================================================================
// Library Initialization
//===============================================================================

bool ggml_masm_init_library(void) {
    // Check for AVX support
    // In a real implementation, check CPU features
    return true;
}

void ggml_masm_deinit_library(void) {
    // Cleanup if needed
}

//===============================================================================
// Transformer Operations (High-level)
//===============================================================================

ggml_masm_tensor* ggml_masm_attention(ggml_masm_context* ctx,
                                       ggml_masm_tensor* q,
                                       ggml_masm_tensor* k,
                                       ggml_masm_tensor* v,
                                       int n_head) {
    if (!ctx || !q || !k || !v) return NULL;
    
    // Simplified attention: Q @ K^T @ V
    // In a full implementation, this would include scaling and masking
    
    int64_t head_dim = q->ne[0];
    int64_t n_tokens = q->ne[1];
    
    // Compute attention scores: Q @ K^T
    ggml_masm_tensor* scores = ggml_masm_matmul(ctx, q, k);
    if (!scores) return NULL;
    
    // Scale by sqrt(head_dim)
    float scale = 1.0f / sqrtf((float)head_dim);
    ggml_masm_tensor* scaled = ggml_masm_scale(ctx, scores, scale);
    if (!scaled) return NULL;
    
    // Softmax
    ggml_masm_tensor* weights = ggml_masm_softmax(ctx, scaled);
    if (!weights) return NULL;
    
    // Apply to values: weights @ V
    ggml_masm_tensor* output = ggml_masm_matmul(ctx, weights, v);
    
    return output;
}

ggml_masm_tensor* ggml_masm_ffn(ggml_masm_context* ctx,
                                 ggml_masm_tensor* x,
                                 ggml_masm_tensor* w1,
                                 ggml_masm_tensor* w2,
                                 ggml_masm_tensor* w3) {
    if (!ctx || !x || !w1 || !w2) return NULL;
    
    // SwiGLU FFN: silu(x @ W1) * (x @ W3) @ W2
    
    // gate = x @ W1
    ggml_masm_tensor* gate = ggml_masm_matmul(ctx, x, w1);
    if (!gate) return NULL;
    
    // gate = silu(gate)
    ggml_masm_tensor* gate_silu = ggml_masm_silu(ctx, gate);
    if (!gate_silu) return NULL;
    
    ggml_masm_tensor* up = NULL;
    if (w3) {
        // up = x @ W3
        up = ggml_masm_matmul(ctx, x, w3);
        if (!up) return NULL;
        
        // gate = gate * up
        ggml_masm_tensor* gate_up = ggml_masm_mul(ctx, gate_silu, up);
        if (!gate_up) return NULL;
        
        // output = gate_up @ W2
        return ggml_masm_matmul(ctx, gate_up, w2);
    } else {
        // output = gate_silu @ W2
        return ggml_masm_matmul(ctx, gate_silu, w2);
    }
}
