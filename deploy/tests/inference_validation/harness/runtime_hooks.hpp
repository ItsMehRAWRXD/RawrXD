/**
 * RawrXD Runtime Validation Hooks
 * 
 * Header-only integration for capturing runtime tensors during inference.
 * Include this in RawrXD runtime builds to enable validation mode.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

// Compile-time enable validation hooks
#ifdef RAWRXD_ENABLE_VALIDATION

namespace rawrxd {
namespace validation {

// Global validation state
struct ValidationState {
    FILE* dump_file = nullptr;
    int current_layer = 0;
    bool enabled = false;
    
    void init(const char* filename) {
        dump_file = fopen(filename, "wb");
        if (dump_file) {
            // Write header: magic + version
            const uint32_t magic = 0x52414452; // "RADR"
            const uint32_t version = 1;
            fwrite(&magic, sizeof(magic), 1, dump_file);
            fwrite(&version, sizeof(version), 1, dump_file);
            enabled = true;
        }
    }
    
    void close() {
        if (dump_file) {
            fclose(dump_file);
            dump_file = nullptr;
        }
        enabled = false;
    }
    
    void dump_tensor(const char* name, const float* data, 
                     const int* shape, int n_dims) {
        if (!enabled || !dump_file) return;
        
        size_t n_elements = 1;
        for (int i = 0; i < n_dims; i++) n_elements *= shape[i];
        
        uint16_t name_len = strlen(name);
        fwrite(&current_layer, sizeof(current_layer), 1, dump_file);
        fwrite(&name_len, sizeof(name_len), 1, dump_file);
        fwrite(name, 1, name_len, dump_file);
        fwrite(&n_dims, sizeof(n_dims), 1, dump_file);
        fwrite(shape, sizeof(int), n_dims, dump_file);
        fwrite(&n_elements, sizeof(n_elements), 1, dump_file);
        fwrite(data, sizeof(float), n_elements, dump_file);
        fflush(dump_file);
    }
};

// Global instance
inline ValidationState& getValidationState() {
    static ValidationState state;
    return state;
}

// Hook functions - call these from runtime
inline void validation_init(const char* filename) {
    getValidationState().init(filename);
}

inline void validation_close() {
    getValidationState().close();
}

inline void validation_set_layer(int layer) {
    getValidationState().current_layer = layer;
}

inline void validation_dump_tensor(const char* name, const float* data,
                                    const int* shape, int n_dims) {
    getValidationState().dump_tensor(name, data, shape, n_dims);
}

// Convenience wrappers for common shapes
inline void validation_dump_1d(const char* name, const float* data, int dim0) {
    int shape[1] = { dim0 };
    validation_dump_tensor(name, data, shape, 1);
}

inline void validation_dump_2d(const char* name, const float* data, 
                                int dim0, int dim1) {
    int shape[2] = { dim0, dim1 };
    validation_dump_tensor(name, data, shape, 2);
}

inline void validation_dump_3d(const char* name, const float* data,
                                int dim0, int dim1, int dim2) {
    int shape[3] = { dim0, dim1, dim2 };
    validation_dump_tensor(name, data, shape, 3);
}

// Layer-specific hooks
inline void validation_dump_rms_norm(const float* data, int n_elements, int layer) {
    validation_set_layer(layer);
    validation_dump_1d("rms_norm", data, n_elements);
}

inline void validation_dump_attention_qkv(const float* q, const float* k, const float* v,
                                          int n_heads, int head_dim, int layer) {
    validation_set_layer(layer);
    validation_dump_2d("attn_q", q, n_heads, head_dim);
    validation_dump_2d("attn_k", k, n_heads, head_dim);
    validation_dump_2d("attn_v", v, n_heads, head_dim);
}

inline void validation_dump_attention_out(const float* data, int n_elements, int layer) {
    validation_set_layer(layer);
    validation_dump_1d("attn_out", data, n_elements);
}

inline void validation_dump_ffn(const float* data, int n_elements, int layer) {
    validation_set_layer(layer);
    validation_dump_1d("ffn_out", data, n_elements);
}

inline void validation_dump_logits(const float* data, int vocab_size) {
    validation_dump_1d("logits", data, vocab_size);
}

} // namespace validation
} // namespace rawrxd

// C-compatible macros for easy integration
#define RAWRXD_VALIDATION_INIT(filename) \
    rawrxd::validation::validation_init(filename)

#define RAWRXD_VALIDATION_CLOSE() \
    rawrxd::validation::validation_close()

#define RAWRXD_VALIDATION_SET_LAYER(layer) \
    rawrxd::validation::validation_set_layer(layer)

#define RAWRXD_VALIDATION_DUMP_RMS_NORM(data, n, layer) \
    rawrxd::validation::validation_dump_rms_norm(data, n, layer)

#define RAWRXD_VALIDATION_DUMP_ATTN_OUT(data, n, layer) \
    rawrxd::validation::validation_dump_attention_out(data, n, layer)

#define RAWRXD_VALIDATION_DUMP_FFN(data, n, layer) \
    rawrxd::validation::validation_dump_ffn(data, n, layer)

#define RAWRXD_VALIDATION_DUMP_LOGITS(data, vocab) \
    rawrxd::validation::validation_dump_logits(data, vocab)

#else // RAWRXD_ENABLE_VALIDATION

// No-op macros when validation disabled
#define RAWRXD_VALIDATION_INIT(filename) ((void)0)
#define RAWRXD_VALIDATION_CLOSE() ((void)0)
#define RAWRXD_VALIDATION_SET_LAYER(layer) ((void)0)
#define RAWRXD_VALIDATION_DUMP_RMS_NORM(data, n, layer) ((void)0)
#define RAWRXD_VALIDATION_DUMP_ATTN_OUT(data, n, layer) ((void)0)
#define RAWRXD_VALIDATION_DUMP_FFN(data, n, layer) ((void)0)
#define RAWRXD_VALIDATION_DUMP_LOGITS(data, vocab) ((void)0)

#endif // RAWRXD_ENABLE_VALIDATION
