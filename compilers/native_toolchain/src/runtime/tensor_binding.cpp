// tensor_binding.cpp - GGUF Tensor to TensorView Mapping
// Phase 8.1 - Gate G1: GGUF tensor → TensorView mapping
// NO DEPENDENCIES - Pure Win32 API

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include "sovereign_runtime.h"
#include <windows.h>
#include <string.h>
#include <stdlib.h>

// ============================================================================
// TENSOR NAME MAPPING
// ============================================================================

// Standard GGUF tensor name patterns
static const struct {
    const char* pattern;
    int layer_idx;
    const char* tensor_type;
} g_tensor_patterns[] = {
    // Embeddings
    {"token_embd.weight", -1, "embedding"},
    {"token_embd", -1, "embedding"},
    {"tok_embeddings.weight", -1, "embedding"},
    
    // Position embeddings (optional)
    {"position_embd.weight", -1, "position"},
    {"position_embd", -1, "position"},
    
    // Output
    {"output.weight", -1, "output"},
    {"output_norm.weight", -1, "norm"},
    {"norm.weight", -1, "norm"},
    
    // Per-layer tensors
    {"blk.%d.attn_norm.weight", 0, "attention_norm"},
    {"blk.%d.attn_q.weight", 0, "attention_q"},
    {"blk.%d.attn_k.weight", 0, "attention_k"},
    {"blk.%d.attn_v.weight", 0, "attention_v"},
    {"blk.%d.attn_output.weight", 0, "attention_o"},
    {"blk.%d.ffn_norm.weight", 0, "ffn_norm"},
    {"blk.%d.ffn_gate.weight", 0, "ffn_gate"},
    {"blk.%d.ffn_up.weight", 0, "ffn_up"},
    {"blk.%d.ffn_down.weight", 0, "ffn_down"},
    
    // Alternative naming conventions
    {"layers.%d.attention_norm.weight", 0, "attention_norm"},
    {"layers.%d.attention.q_proj.weight", 0, "attention_q"},
    {"layers.%d.attention.k_proj.weight", 0, "attention_k"},
    {"layers.%d.attention.v_proj.weight", 0, "attention_v"},
    {"layers.%d.attention.o_proj.weight", 0, "attention_o"},
    {"layers.%d.ffn_norm.weight", 0, "ffn_norm"},
    {"layers.%d.feed_forward.w1.weight", 0, "ffn_gate"},
    {"layers.%d.feed_forward.w2.weight", 0, "ffn_down"},
    {"layers.%d.feed_forward.w3.weight", 0, "ffn_up"},
    
    {NULL, 0, NULL}
};

// ============================================================================
// TENSOR SIZE CALCULATION
// ============================================================================

static size_t tensor_type_size(TensorType type) {
    switch (type) {
        case TENSOR_TYPE_F32: return sizeof(float);
        case TENSOR_TYPE_F16: return sizeof(uint16_t);
        case TENSOR_TYPE_Q4_0: return 0; // Variable size
        case TENSOR_TYPE_Q4_1: return 0; // Variable size
        case TENSOR_TYPE_Q5_0: return 0; // Variable size
        case TENSOR_TYPE_Q5_1: return 0; // Variable size
        case TENSOR_TYPE_Q8_0: return sizeof(uint8_t);
        case TENSOR_TYPE_Q2_K: return 0; // Variable size
        case TENSOR_TYPE_Q3_K: return 0; // Variable size
        case TENSOR_TYPE_Q4_K: return 0; // Variable size
        case TENSOR_TYPE_Q5_K: return 0; // Variable size
        case TENSOR_TYPE_Q6_K: return 0; // Variable size
        case TENSOR_TYPE_Q8_K: return 0; // Variable size
        default: return 0;
    }
}

static size_t calculate_tensor_size(TensorType type, uint64_t ne[4], uint32_t n_dims) {
    size_t total_elements = 1;
    for (uint32_t i = 0; i < n_dims; i++) {
        total_elements *= ne[i];
    }
    
    // For quantized types, calculate actual size
    switch (type) {
        case TENSOR_TYPE_F32:
            return total_elements * sizeof(float);
        case TENSOR_TYPE_F16:
            return total_elements * sizeof(uint16_t);
        case TENSOR_TYPE_Q4_0: {
            // Q4_0: block_size = 32, each block is 18 bytes (16 half + 2 scale)
            const size_t block_size = 32;
            const size_t blocks = (total_elements + block_size - 1) / block_size;
            return blocks * (block_size / 2 + sizeof(float));
        }
        case TENSOR_TYPE_Q4_1: {
            // Q4_1: block_size = 32, each block is 20 bytes (16 half + 2 scale + 2 bias)
            const size_t block_size = 32;
            const size_t blocks = (total_elements + block_size - 1) / block_size;
            return blocks * (block_size / 2 + 2 * sizeof(float));
        }
        case TENSOR_TYPE_Q8_0: {
            // Q8_0: block_size = 32, each block is 34 bytes (32 bytes + 2 scale)
            const size_t block_size = 32;
            const size_t blocks = (total_elements + block_size - 1) / block_size;
            return blocks * (block_size + sizeof(float));
        }
        default:
            return total_elements * sizeof(float); // Fallback
    }
}

// ============================================================================
// TENSOR NAME PARSING
// ============================================================================

static int parse_layer_index(const char* name) {
    // Try to extract layer index from tensor name
    // Formats: "blk.0.attn.weight", "layers.0.attention.weight", etc.
    
    for (int i = 0; g_tensor_patterns[i].pattern != NULL; i++) {
        const char* pattern = g_tensor_patterns[i].pattern;
        
        // Check if pattern contains %d (layer index)
        if (strstr(pattern, "%d") != NULL) {
            int layer_idx;
            if (sscanf(name, pattern, &layer_idx) == 1) {
                return layer_idx;
            }
        } else {
            // Direct match
            if (strcmp(name, pattern) == 0) {
                return g_tensor_patterns[i].layer_idx;
            }
        }
    }
    
    return -1; // Not a per-layer tensor
}

static const char* get_tensor_type_name(const char* name) {
    for (int i = 0; g_tensor_patterns[i].pattern != NULL; i++) {
        const char* pattern = g_tensor_patterns[i].pattern;
        
        if (strstr(pattern, "%d") != NULL) {
            // Try to match with layer index
            char buf[256];
            for (int layer = 0; layer < 256; layer++) {
                snprintf(buf, sizeof(buf), pattern, layer);
                if (strcmp(name, buf) == 0) {
                    return g_tensor_patterns[i].tensor_type;
                }
            }
        } else {
            if (strcmp(name, pattern) == 0) {
                return g_tensor_patterns[i].tensor_type;
            }
        }
    }
    
    return "unknown";
}

// ============================================================================
// GGUF TENSOR PARSING
// ============================================================================

extern "C" SovereignRuntimeStatus Sovereign_Runtime_MapTensors(
    ModelContext* ctx,
    const void* gguf_data,
    size_t gguf_size
) {
    if (!ctx || !gguf_data) {
        return SOVEREIGN_RUNTIME_ERROR_NULL_POINTER;
    }
    
    const uint8_t* data = (const uint8_t*)gguf_data;
    const uint8_t* p = data;
    
    // Read GGUF header
    uint32_t magic;
    memcpy(&magic, p, 4);
    p += 4;
    
    if (magic != 0x46554747) { // "GGUF"
        return SOVEREIGN_RUNTIME_ERROR_INVALID_MODEL;
    }
    
    uint32_t version;
    memcpy(&version, p, 4);
    p += 4;
    
    uint64_t n_tensors;
    memcpy(&n_tensors, p, 8);
    p += 8;
    
    uint64_t n_kv;
    memcpy(&n_kv, p, 8);
    p += 8;
    
    // Skip metadata for now (we'll parse it in tokenizer_bridge)
    for (uint64_t i = 0; i < n_kv; i++) {
        // Read key length
        uint64_t key_len;
        memcpy(&key_len, p, 8);
        p += 8 + key_len;
        
        // Read value type
        uint32_t value_type;
        memcpy(&value_type, p, 4);
        p += 4;
        
        // Skip value (simplified - would need full parser for production)
        // This is a placeholder - real implementation would parse all metadata
        p += 8; // Skip approximate size
    }
    
    // Parse tensor info
    for (uint64_t i = 0; i < n_tensors; i++) {
        // Read tensor name length
        uint64_t name_len;
        memcpy(&name_len, p, 8);
        p += 8;
        
        // Read tensor name
        char tensor_name[256];
        memcpy(tensor_name, p, name_len);
        tensor_name[name_len] = '\0';
        p += name_len;
        
        // Read number of dimensions
        uint32_t n_dims;
        memcpy(&n_dims, p, 4);
        p += 4;
        
        // Read shape
        uint64_t ne[4] = {1, 1, 1, 1};
        for (uint32_t d = 0; d < n_dims; d++) {
            memcpy(&ne[d], p, 8);
            p += 8;
        }
        
        // Read tensor type
        uint32_t tensor_type;
        memcpy(&tensor_type, p, 4);
        p += 4;
        
        // Read offset
        uint64_t offset;
        memcpy(&offset, p, 8);
        p += 8;
        
        // Calculate tensor size
        size_t size = calculate_tensor_size((TensorType)tensor_type, ne, n_dims);
        
        // Determine tensor category and assign to context
        int layer_idx = parse_layer_index(tensor_name);
        const char* type_name = get_tensor_type_name(tensor_name);
        
        // Map to appropriate tensor view
        TensorView* view = NULL;
        
        if (strcmp(type_name, "embedding") == 0) {
            ctx->token_embd = (TensorView*)malloc(sizeof(TensorView));
            view = ctx->token_embd;
        } else if (strcmp(type_name, "output") == 0) {
            ctx->output = (TensorView*)malloc(sizeof(TensorView));
            view = ctx->output;
        } else if (strcmp(type_name, "norm") == 0) {
            ctx->norm_final = (TensorView*)malloc(sizeof(TensorView));
            view = ctx->norm_final;
        } else if (layer_idx >= 0) {
            // Allocate layers if needed
            if (ctx->layers == NULL) {
                // Count total layers (simplified - would need proper counting)
                ctx->n_layers = 32; // Default for most models
                ctx->layers = (decltype(ctx->layers))calloc(ctx->n_layers, sizeof(*ctx->layers));
            }
            
            if (layer_idx < ctx->n_layers) {
                if (strcmp(type_name, "attention_norm") == 0) {
                    ctx->layers[layer_idx].attention_norm = (TensorView*)malloc(sizeof(TensorView));
                    view = ctx->layers[layer_idx].attention_norm;
                } else if (strcmp(type_name, "attention_q") == 0) {
                    ctx->layers[layer_idx].attention_q = (TensorView*)malloc(sizeof(TensorView));
                    view = ctx->layers[layer_idx].attention_q;
                } else if (strcmp(type_name, "attention_k") == 0) {
                    ctx->layers[layer_idx].attention_k = (TensorView*)malloc(sizeof(TensorView));
                    view = ctx->layers[layer_idx].attention_k;
                } else if (strcmp(type_name, "attention_v") == 0) {
                    ctx->layers[layer_idx].attention_v = (TensorView*)malloc(sizeof(TensorView));
                    view = ctx->layers[layer_idx].attention_v;
                } else if (strcmp(type_name, "attention_o") == 0) {
                    ctx->layers[layer_idx].attention_o = (TensorView*)malloc(sizeof(TensorView));
                    view = ctx->layers[layer_idx].attention_o;
                } else if (strcmp(type_name, "ffn_norm") == 0) {
                    ctx->layers[layer_idx].ffn_norm = (TensorView*)malloc(sizeof(TensorView));
                    view = ctx->layers[layer_idx].ffn_norm;
                } else if (strcmp(type_name, "ffn_gate") == 0) {
                    ctx->layers[layer_idx].ffn_gate = (TensorView*)malloc(sizeof(TensorView));
                    view = ctx->layers[layer_idx].ffn_gate;
                } else if (strcmp(type_name, "ffn_up") == 0) {
                    ctx->layers[layer_idx].ffn_up = (TensorView*)malloc(sizeof(TensorView));
                    view = ctx->layers[layer_idx].ffn_up;
                } else if (strcmp(type_name, "ffn_down") == 0) {
                    ctx->layers[layer_idx].ffn_down = (TensorView*)malloc(sizeof(TensorView));
                    view = ctx->layers[layer_idx].ffn_down;
                }
            }
        }
        
        // Populate tensor view
        if (view) {
            view->name = _strdup(tensor_name);
            view->type = (TensorType)tensor_type;
            view->n_dims = n_dims;
            for (uint32_t d = 0; d < 4; d++) {
                view->ne[d] = ne[d];
            }
            view->data = (const void*)(data + offset);
            view->size = size;
            view->offset = offset;
        }
    }
    
    // Store model data pointer
    ctx->model_data = (void*)gguf_data;
    ctx->model_size = gguf_size;
    
    return SOVEREIGN_RUNTIME_SUCCESS;
}

// ============================================================================
// TENSOR ACCESS UTILITIES
// ============================================================================

extern "C" TensorView* Sovereign_Runtime_GetTensor(
    ModelContext* ctx,
    const char* name
) {
    if (!ctx || !name) {
        return NULL;
    }
    
    // Check global tensors
    if (ctx->token_embd && strcmp(ctx->token_embd->name, name) == 0) {
        return ctx->token_embd;
    }
    if (ctx->output && strcmp(ctx->output->name, name) == 0) {
        return ctx->output;
    }
    if (ctx->norm_final && strcmp(ctx->norm_final->name, name) == 0) {
        return ctx->norm_final;
    }
    
    // Check per-layer tensors
    for (int i = 0; i < ctx->n_layers; i++) {
        if (ctx->layers[i].attention_norm && 
            strcmp(ctx->layers[i].attention_norm->name, name) == 0) {
            return ctx->layers[i].attention_norm;
        }
        if (ctx->layers[i].attention_q && 
            strcmp(ctx->layers[i].attention_q->name, name) == 0) {
            return ctx->layers[i].attention_q;
        }
        // ... (would check all tensor types)
    }
    
    return NULL;
}

extern "C" void Sovereign_Runtime_FreeTensors(ModelContext* ctx) {
    if (!ctx) {
        return;
    }
    
    // Free global tensors
    if (ctx->token_embd) {
        free((void*)ctx->token_embd->name);
        free(ctx->token_embd);
        ctx->token_embd = NULL;
    }
    if (ctx->output) {
        free((void*)ctx->output->name);
        free(ctx->output);
        ctx->output = NULL;
    }
    if (ctx->norm_final) {
        free((void*)ctx->norm_final->name);
        free(ctx->norm_final);
        ctx->norm_final = NULL;
    }
    
    // Free per-layer tensors
    for (int i = 0; i < ctx->n_layers; i++) {
        if (ctx->layers[i].attention_norm) {
            free((void*)ctx->layers[i].attention_norm->name);
            free(ctx->layers[i].attention_norm);
        }
        if (ctx->layers[i].attention_q) {
            free((void*)ctx->layers[i].attention_q->name);
            free(ctx->layers[i].attention_q);
        }
        if (ctx->layers[i].attention_k) {
            free((void*)ctx->layers[i].attention_k->name);
            free(ctx->layers[i].attention_k);
        }
        if (ctx->layers[i].attention_v) {
            free((void*)ctx->layers[i].attention_v->name);
            free(ctx->layers[i].attention_v);
        }
        if (ctx->layers[i].attention_o) {
            free((void*)ctx->layers[i].attention_o->name);
            free(ctx->layers[i].attention_o);
        }
        if (ctx->layers[i].ffn_norm) {
            free((void*)ctx->layers[i].ffn_norm->name);
            free(ctx->layers[i].ffn_norm);
        }
        if (ctx->layers[i].ffn_gate) {
            free((void*)ctx->layers[i].ffn_gate->name);
            free(ctx->layers[i].ffn_gate);
        }
        if (ctx->layers[i].ffn_up) {
            free((void*)ctx->layers[i].ffn_up->name);
            free(ctx->layers[i].ffn_up);
        }
        if (ctx->layers[i].ffn_down) {
            free((void*)ctx->layers[i].ffn_down->name);
            free(ctx->layers[i].ffn_down);
        }
    }
    
    free(ctx->layers);
    ctx->layers = NULL;
}