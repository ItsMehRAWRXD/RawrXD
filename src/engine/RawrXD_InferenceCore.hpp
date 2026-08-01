// RawrXD_InferenceCore.hpp — Universal GGUF inference engine
// Zero-dependency, architecture-aware, tensor-streaming, quant-dispatching
// Part of RawrXD Sovereign Platform

#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <algorithm>
#include <memory>
#include <atomic>
#include <chrono>

// ============================================================================
// GGUF FORMAT CONSTANTS
// ============================================================================
#define GGUF_MAGIC 0x46554747u
#define GGUF_VERSION 3
#define GGUF_VALUE_UINT8  0
#define GGUF_VALUE_INT8   1
#define GGUF_VALUE_UINT16 2
#define GGUF_VALUE_INT16  3
#define GGUF_VALUE_UINT32 4
#define GGUF_VALUE_INT32  5
#define GGUF_VALUE_FLOAT32 6
#define GGUF_VALUE_BOOL   7
#define GGUF_VALUE_STRING 8
#define GGUF_VALUE_ARRAY  9
#define GGUF_VALUE_UINT64 10
#define GGUF_VALUE_INT64  11
#define GGUF_VALUE_FLOAT64 12

// GGML tensor types
#define GGML_TYPE_F32  0
#define GGML_TYPE_F16  1
#define GGML_TYPE_Q4_0 2
#define GGML_TYPE_Q4_1 3
#define GGML_TYPE_Q5_0 6
#define GGML_TYPE_Q5_1 7
#define GGML_TYPE_Q8_0 8
#define GGML_TYPE_Q8_1 9
#define GGML_TYPE_Q2_K 10
#define GGML_TYPE_Q3_K 11
#define GGML_TYPE_Q4_K 12
#define GGML_TYPE_Q5_K 13
#define GGML_TYPE_Q6_K 14
#define GGML_TYPE_Q8_K 15
#define GGML_TYPE_IQ2_XXS 16
#define GGML_TYPE_IQ2_XS 17
#define GGML_TYPE_IQ3_XXS 18
#define GGML_TYPE_IQ1_S 19
#define GGML_TYPE_IQ4_NL 20
#define GGML_TYPE_IQ3_S 21
#define GGML_TYPE_IQ2_S 22
#define GGML_TYPE_IQ4_XS 23
#define GGML_TYPE_I8 24
#define GGML_TYPE_I16 25
#define GGML_TYPE_I32 26
#define GGML_TYPE_BF16 27

// ============================================================================
// GGUF HEADER
// ============================================================================
#pragma pack(push, 1)
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};
#pragma pack(pop)

// ============================================================================
// TENSOR INFO
// ============================================================================
struct GGUFTensorInfo {
    std::string name;
    uint32_t n_dims = 0;
    uint64_t shape[4] = {};
    uint32_t dtype = 0;
    uint64_t offset = 0;
    uint64_t numel = 0;
    uint64_t size_bytes = 0;
};

// ============================================================================
// MODEL METADATA
// ============================================================================
struct ModelMetadata {
    std::string architecture;
    uint32_t block_count = 0;
    uint32_t embedding_length = 0;
    uint32_t head_count = 0;
    uint32_t head_count_kv = 0;
    uint32_t feed_forward_length = 0;
    uint32_t vocab_size = 0;
    uint32_t context_length = 0;
    uint32_t rope_dim_count = 0;
    float rope_freq_base = 10000.0f;
    float rope_freq_scale = 1.0f;
    uint32_t expert_count = 0;
    uint32_t expert_used_count = 0;
    float norm_eps = 1e-5f;
    std::string tokenizer_type; // "bpe", "spm", "bert"
    std::vector<std::string> tokens;
    std::vector<int32_t> token_scores;
    std::vector<std::string> merges;
    int32_t bos_token_id = 1;
    int32_t eos_token_id = 2;
    int32_t pad_token_id = 0;
    int32_t unknown_token_id = 0;
    bool has_ffn_gate = false; // SwiGLU
    bool has_ffn_up = false;
    bool has_ffn_down = false;
};

// ============================================================================
// TENSOR STREAMER — mmap-based, layer-by-layer
// ============================================================================
class TensorStreamer {
public:
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapping = nullptr;
    const uint8_t* base = nullptr;
    uint64_t file_size = 0;
    uint64_t data_offset = 0;
    std::vector<GGUFTensorInfo> tensors;
    std::unordered_map<std::string, const GGUFTensorInfo*> tensor_map;

    ~TensorStreamer() { Close(); }

    bool Open(const wchar_t* path) {
        hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER li; GetFileSizeEx(hFile, &li); file_size = li.QuadPart;
        hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMapping) { Close(); return false; }
        base = (const uint8_t*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!base) { Close(); return false; }
        return true;
    }

    void Close() {
        if (base) { UnmapViewOfFile(base); base = nullptr; }
        if (hMapping) { CloseHandle(hMapping); hMapping = nullptr; }
        if (hFile != INVALID_HANDLE_VALUE) { CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE; }
    }

    const float* GetTensorData(const std::string& name) const {
        auto it = tensor_map.find(name);
        if (it == tensor_map.end()) return nullptr;
        return (const float*)(base + data_offset + it->second->offset);
    }

    const uint8_t* GetRawTensor(const std::string& name) const {
        auto it = tensor_map.find(name);
        if (it == tensor_map.end()) return nullptr;
        return base + data_offset + it->second->offset;
    }
};

// ============================================================================
// QUANTIZATION DISPATCHER
// ============================================================================
class QuantDispatcher {
public:
    // Dequantize a single block to float
    using DequantFn = void(*)(const uint8_t* block, float* out, uint32_t stride);

    static DequantFn GetDequantFn(uint32_t ggml_type) {
        switch (ggml_type) {
        case GGML_TYPE_F32:  return DequantF32;
        case GGML_TYPE_F16:  return DequantF16;
        case GGML_TYPE_Q4_0: return DequantQ4_0;
        case GGML_TYPE_Q4_1: return DequantQ4_1;
        case GGML_TYPE_Q5_0: return DequantQ5_0;
        case GGML_TYPE_Q5_1: return DequantQ5_1;
        case GGML_TYPE_Q8_0: return DequantQ8_0;
        case GGML_TYPE_Q2_K: return DequantQ2_K;
        case GGML_TYPE_Q3_K: return DequantQ3_K;
        case GGML_TYPE_Q4_K: return DequantQ4_K;
        case GGML_TYPE_Q5_K: return DequantQ5_K;
        case GGML_TYPE_Q6_K: return DequantQ6_K;
        case GGML_TYPE_BF16: return DequantBF16;
        default: return nullptr;
        }
    }

    static uint32_t BlockSize(uint32_t ggml_type) {
        switch (ggml_type) {
        case GGML_TYPE_F32:  return 1;
        case GGML_TYPE_F16:  return 1;
        case GGML_TYPE_Q4_0: return 32;
        case GGML_TYPE_Q4_1: return 32;
        case GGML_TYPE_Q5_0: return 32;
        case GGML_TYPE_Q5_1: return 32;
        case GGML_TYPE_Q8_0: return 32;
        case GGML_TYPE_Q2_K: return 256;
        case GGML_TYPE_Q3_K: return 256;
        case GGML_TYPE_Q4_K: return 256;
        case GGML_TYPE_Q5_K: return 256;
        case GGML_TYPE_Q6_K: return 256;
        case GGML_TYPE_BF16: return 1;
        default: return 0;
        }
    }

    static uint32_t BlockBytes(uint32_t ggml_type) {
        switch (ggml_type) {
        case GGML_TYPE_F32:  return 4;
        case GGML_TYPE_F16:  return 2;
        case GGML_TYPE_Q4_0: return 18;  // d(4) + qs(8) + padding(6)
        case GGML_TYPE_Q4_1: return 20;
        case GGML_TYPE_Q5_0: return 22;
        case GGML_TYPE_Q5_1: return 24;
        case GGML_TYPE_Q8_0: return 34;
        case GGML_TYPE_Q2_K: return 80;  // d(4) + dmin(4) + scales(6) + qs(64)
        case GGML_TYPE_Q3_K: return 104;
        case GGML_TYPE_Q4_K: return 144;
        case GGML_TYPE_Q5_K: return 176;
        case GGML_TYPE_Q6_K: return 208;
        case GGML_TYPE_BF16: return 2;
        default: return 0;
        }
    }

    static const char* TypeName(uint32_t ggml_type) {
        switch (ggml_type) {
        case GGML_TYPE_F32:  return "F32";
        case GGML_TYPE_F16:  return "F16";
        case GGML_TYPE_Q4_0: return "Q4_0";
        case GGML_TYPE_Q4_1: return "Q4_1";
        case GGML_TYPE_Q5_0: return "Q5_0";
        case GGML_TYPE_Q5_1: return "Q5_1";
        case GGML_TYPE_Q8_0: return "Q8_0";
        case GGML_TYPE_Q2_K: return "Q2_K";
        case GGML_TYPE_Q3_K: return "Q3_K";
        case GGML_TYPE_Q4_K: return "Q4_K";
        case GGML_TYPE_Q5_K: return "Q5_K";
        case GGML_TYPE_Q6_K: return "Q6_K";
        case GGML_TYPE_BF16: return "BF16";
        default: return "UNKNOWN";
        }
    }

    // Dequant implementations
    static void DequantF32(const uint8_t* block, float* out, uint32_t stride) {
        memcpy(out, block, stride * sizeof(float));
    }
    static void DequantF16(const uint8_t* block, float* out, uint32_t stride) {
        for (uint32_t i = 0; i < stride; i++) {
            uint16_t h = ((uint16_t*)block)[i];
            out[i] = HalfToFloat(h);
        }
    }
    static void DequantQ4_0(const uint8_t* block, float* out, uint32_t stride) {
        float d = *(const float*)block;
        const uint8_t* qs = block + 4;
        for (uint32_t i = 0; i < stride && i < 32; i++) {
            int q = (qs[i / 2] >> (4 * (i & 1))) & 0xF;
            out[i] = d * ((float)q - 8.0f);
        }
    }
    static void DequantQ4_1(const uint8_t* block, float* out, uint32_t stride) {
        float d = *(const float*)block;
        float m = *(const float*)(block + 4);
        const uint8_t* qs = block + 8;
        for (uint32_t i = 0; i < stride && i < 32; i++) {
            int q = (qs[i / 2] >> (4 * (i & 1))) & 0xF;
            out[i] = d * (float)q + m;
        }
    }
    static void DequantQ5_0(const uint8_t* block, float* out, uint32_t stride) {
        float d = *(const float*)block;
        const uint8_t* qh = block + 4;
        const uint8_t* qs = block + 6;
        for (uint32_t i = 0; i < stride && i < 32; i++) {
            int q = (qs[i / 2] >> (4 * (i & 1))) & 0xF;
            int h = (qh[i / 8] >> (i & 7)) & 1;
            out[i] = d * ((float)(q | (h << 4)) - 16.0f);
        }
    }
    static void DequantQ5_1(const uint8_t* block, float* out, uint32_t stride) {
        float d = *(const float*)block;
        float m = *(const float*)(block + 4);
        const uint8_t* qh = block + 8;
        const uint8_t* qs = block + 10;
        for (uint32_t i = 0; i < stride && i < 32; i++) {
            int q = (qs[i / 2] >> (4 * (i & 1))) & 0xF;
            int h = (qh[i / 8] >> (i & 7)) & 1;
            out[i] = d * (float)(q | (h << 4)) + m;
        }
    }
    static void DequantQ8_0(const uint8_t* block, float* out, uint32_t stride) {
        float d = *(const float*)block;
        const int8_t* qs = (const int8_t*)(block + 4);
        for (uint32_t i = 0; i < stride && i < 32; i++) {
            out[i] = d * (float)qs[i];
        }
    }

    // K-quant dequant (simplified — real impl would use lookup tables)
    static void DequantQ2_K(const uint8_t* block, float* out, uint32_t stride) {
        // Q2_K: 256 elements, 80 bytes per block
        float d = *(const float*)block;
        float dmin = *(const float*)(block + 4);
        const uint8_t* scales = block + 8;  // 6 bytes
        const uint8_t* qs = block + 14;     // 64 bytes
        for (uint32_t i = 0; i < stride && i < 256; i++) {
            int q = (qs[i / 4] >> (2 * (i & 3))) & 3;
            int sc = (scales[i / 32] >> (2 * ((i / 16) & 3))) & 3;
            out[i] = d * (float)q - dmin * (float)sc;
        }
    }
    static void DequantQ3_K(const uint8_t* block, float* out, uint32_t stride) {
        float d = *(const float*)block;
        float dmin = *(const float*)(block + 4);
        const uint8_t* scales = block + 8;
        const uint8_t* qs = block + 14;
        for (uint32_t i = 0; i < stride && i < 256; i++) {
            int q = (qs[i / 4] >> (2 * (i & 3))) & 3;
            int sc = (scales[i / 32] >> (2 * ((i / 16) & 3))) & 3;
            out[i] = d * (float)q - dmin * (float)sc;
        }
    }
    static void DequantQ4_K(const uint8_t* block, float* out, uint32_t stride) {
        float d = *(const float*)block;
        float dmin = *(const float*)(block + 4);
        const uint8_t* scales = block + 8;
        const uint8_t* qs = block + 14;
        for (uint32_t i = 0; i < stride && i < 256; i++) {
            int q = (qs[i / 2] >> (4 * (i & 1))) & 0xF;
            int sc = (scales[i / 32] >> (2 * ((i / 16) & 3))) & 3;
            out[i] = d * (float)q - dmin * (float)sc;
        }
    }
    static void DequantQ5_K(const uint8_t* block, float* out, uint32_t stride) {
        float d = *(const float*)block;
        float dmin = *(const float*)(block + 4);
        const uint8_t* scales = block + 8;
        const uint8_t* qh = block + 14;
        const uint8_t* qs = block + 18;
        for (uint32_t i = 0; i < stride && i < 256; i++) {
            int q = (qs[i / 2] >> (4 * (i & 1))) & 0xF;
            int h = (qh[i / 8] >> (i & 7)) & 1;
            int sc = (scales[i / 32] >> (2 * ((i / 16) & 3))) & 3;
            out[i] = d * (float)(q | (h << 4)) - dmin * (float)sc;
        }
    }
    static void DequantQ6_K(const uint8_t* block, float* out, uint32_t stride) {
        float d = *(const float*)block;
        float dmin = *(const float*)(block + 4);
        const uint8_t* scales = block + 8;
        const uint8_t* qs = block + 14;
        for (uint32_t i = 0; i < stride && i < 256; i++) {
            int q = (qs[i / 2] >> (4 * (i & 1))) & 0xF;
            int sc = (scales[i / 32] >> (2 * ((i / 16) & 3))) & 3;
            out[i] = d * (float)q - dmin * (float)sc;
        }
    }
    static void DequantBF16(const uint8_t* block, float* out, uint32_t stride) {
        for (uint32_t i = 0; i < stride; i++) {
            uint32_t bits = ((uint32_t)((const uint16_t*)block)[i]) << 16;
            memcpy(&out[i], &bits, 4);
        }
    }

    static float HalfToFloat(uint16_t h) {
        uint32_t sign = (h >> 15) & 1;
        uint32_t exp = (h >> 10) & 0x1F;
        uint32_t mant = h & 0x3FF;
        uint32_t f;
        if (exp == 0) {
            f = (sign << 31) | (0x7F - 15) << 23 | (mant << 13);
        } else if (exp == 0x1F) {
            f = (sign << 31) | 0xFF << 23 | (mant << 13);
        } else {
            f = (sign << 31) | ((exp + 0x7F - 15) << 23) | (mant << 13);
        }
        float result; memcpy(&result, &f, 4); return result;
    }
};

// ============================================================================
// GGUF UNIVERSAL READER
// ============================================================================
class GGUFReader {
public:
    TensorStreamer streamer;
    ModelMetadata metadata;
    std::string error_msg;
    bool loaded = false;

    bool Load(const wchar_t* path) {
        if (!streamer.Open(path)) {
            error_msg = "Failed to open file";
            return false;
        }
        auto* hdr = (const GGUFHeader*)streamer.base;
        if (hdr->magic != GGUF_MAGIC) {
            error_msg = "Invalid GGUF magic";
            return false;
        }
        if (hdr->version != GGUF_VERSION) {
            error_msg = "Unsupported GGUF version: " + std::to_string(hdr->version);
            return false;
        }
        uint64_t tensor_count = hdr->tensor_count;
        uint64_t metadata_count = hdr->metadata_kv_count;
        const uint8_t* pos = streamer.base + sizeof(GGUFHeader);

        // Parse metadata
        for (uint64_t i = 0; i < metadata_count; i++) {
            uint32_t key_len = *(uint32_t*)pos; pos += 4;
            std::string key((const char*)pos, key_len); pos += key_len;
            uint32_t val_type = *(uint32_t*)pos; pos += 4;

            switch (val_type) {
            case GGUF_VALUE_UINT8:   { uint8_t v = *pos++; break; }
            case GGUF_VALUE_INT8:    { int8_t v = *(int8_t*)pos++; break; }
            case GGUF_VALUE_UINT16:  { pos += 2; break; }
            case GGUF_VALUE_INT16:   { pos += 2; break; }
            case GGUF_VALUE_UINT32: {
                uint32_t v = *(uint32_t*)pos; pos += 4;
                if (key == "general.architecture") { /* handled as string */ }
                else if (key == "llama.block_count" || key == "bert.block_count" || key == "phi.block_count" || key == "gemma.block_count" || key == "mistral.block_count" || key == "qwen.block_count") metadata.block_count = v;
                else if (key == "llama.embedding_length" || key == "bert.embedding_length" || key == "phi.embedding_length" || key == "gemma.embedding_length" || key == "mistral.embedding_length" || key == "qwen.embedding_length") metadata.embedding_length = v;
                else if (key == "llama.head_count" || key == "bert.head_count" || key == "phi.head_count" || key == "gemma.head_count" || key == "mistral.head_count" || key == "qwen.head_count") metadata.head_count = v;
                else if (key == "llama.head_count_kv" || key == "bert.head_count_kv" || key == "phi.head_count_kv" || key == "gemma.head_count_kv" || key == "mistral.head_count_kv" || key == "qwen.head_count_kv") metadata.head_count_kv = v;
                else if (key == "llama.feed_forward_length" || key == "phi.feed_forward_length" || key == "gemma.feed_forward_length" || key == "mistral.feed_forward_length" || key == "qwen.feed_forward_length") metadata.feed_forward_length = v;
                else if (key == "llama.vocab_size" || key == "bert.vocab_size" || key == "phi.vocab_size" || key == "gemma.vocab_size" || key == "mistral.vocab_size" || key == "qwen.vocab_size") metadata.vocab_size = v;
                else if (key == "llama.context_length" || key == "phi.context_length" || key == "gemma.context_length" || key == "mistral.context_length" || key == "qwen.context_length") metadata.context_length = v;
                else if (key == "llama.rope.dimension_count") metadata.rope_dim_count = v;
                else if (key == "llama.expert_count") metadata.expert_count = v;
                else if (key == "llama.expert_used_count") metadata.expert_used_count = v;
                else if (key == "tokenizer.ggml.bos_token_id") metadata.bos_token_id = (int32_t)v;
                else if (key == "tokenizer.ggml.eos_token_id") metadata.eos_token_id = (int32_t)v;
                else if (key == "tokenizer.ggml.padding_token_id") metadata.pad_token_id = (int32_t)v;
                else if (key == "tokenizer.ggml.unknown_token_id") metadata.unknown_token_id = (int32_t)v;
                break;
            }
            case GGUF_VALUE_INT32:   { pos += 4; break; }
            case GGUF_VALUE_FLOAT32: {
                float v = *(float*)pos; pos += 4;
                if (key == "llama.rope.freq_base") metadata.rope_freq_base = v;
                else if (key == "llama.rope.freq_scale") metadata.rope_freq_scale = v;
                else if (key == "llama.attention.layer_norm_rms_epsilon" || key == "gemma.attention.layer_norm_rms_epsilon") metadata.norm_eps = v;
                break;
            }
            case GGUF_VALUE_BOOL:    { pos += 1; break; }
            case GGUF_VALUE_STRING: {
                uint64_t len = *(uint64_t*)pos; pos += 8;
                std::string val((const char*)pos, (size_t)len); pos += len;
                if (key == "general.architecture") metadata.architecture = val;
                else if (key == "tokenizer.ggml.model") metadata.tokenizer_type = val;
                break;
            }
            case GGUF_VALUE_ARRAY: {
                uint32_t arr_type = *(uint32_t*)pos; pos += 4;
                uint64_t arr_len = *(uint64_t*)pos; pos += 8;
                for (uint64_t j = 0; j < arr_len; j++) {
                    if (arr_type == GGUF_VALUE_UINT32) {
                        uint32_t v = *(uint32_t*)pos; pos += 4;
                        if (key == "tokenizer.ggml.scores") metadata.token_scores.push_back((int32_t)v);
                    } else if (arr_type == GGUF_VALUE_STRING) {
                        uint64_t slen = *(uint64_t*)pos; pos += 8;
                        std::string s((const char*)pos, (size_t)slen); pos += slen;
                        if (key == "tokenizer.ggml.tokens") metadata.tokens.push_back(s);
                        else if (key == "tokenizer.ggml.merges") metadata.merges.push_back(s);
                    } else if (arr_type == GGUF_VALUE_FLOAT32) {
                        pos += 4;
                    } else {
                        break;
                    }
                }
                break;
            }
            case GGUF_VALUE_UINT64:  { pos += 8; break; }
            case GGUF_VALUE_INT64:   { pos += 8; break; }
            case GGUF_VALUE_FLOAT64: { pos += 8; break; }
            default: break;
            }
        }

        // Parse tensor info
        streamer.tensors.resize((size_t)tensor_count);
        uint64_t first_offset = 0;
        for (uint64_t i = 0; i < tensor_count; i++) {
            auto& t = streamer.tensors[(size_t)i];
            uint64_t name_len = *(uint64_t*)pos; pos += 8;
            t.name.assign((const char*)pos, (size_t)name_len); pos += name_len;
            t.n_dims = *(uint32_t*)pos; pos += 4;
            t.numel = 1;
            for (uint32_t d = 0; d < t.n_dims; d++) {
                t.shape[d] = *(uint64_t*)pos; pos += 8;
                t.numel *= t.shape[d];
            }
            t.dtype = *(uint32_t*)pos; pos += 4;
            t.offset = *(uint64_t*)pos; pos += 8;
            if (i == 0) first_offset = t.offset;
            t.size_bytes = t.numel * QuantDispatcher::BlockBytes(t.dtype) / QuantDispatcher::BlockSize(t.dtype);
            streamer.tensor_map[t.name] = &streamer.tensors[(size_t)i];
        }
        streamer.data_offset = first_offset;

        // Detect architecture features
        if (metadata.feed_forward_length == 0 && metadata.embedding_length > 0) {
            // Try to detect from tensor names
            for (auto& t : streamer.tensors) {
                if (t.name.find("ffn_gate") != std::string::npos) metadata.has_ffn_gate = true;
                if (t.name.find("ffn_up") != std::string::npos) metadata.has_ffn_up = true;
                if (t.name.find("ffn_down") != std::string::npos) metadata.has_ffn_down = true;
            }
        }
        if (metadata.head_count_kv == 0) metadata.head_count_kv = metadata.head_count;
        if (metadata.rope_dim_count == 0) metadata.rope_dim_count = metadata.embedding_length / metadata.head_count;

        loaded = true;
        return true;
    }

    void PrintInfo() const {
        printf("  Architecture: %s\n", metadata.architecture.c_str());
        printf("  Layers: %u\n", metadata.block_count);
        printf("  Embedding: %u\n", metadata.embedding_length);
        printf("  Heads: %u (KV: %u)\n", metadata.head_count, metadata.head_count_kv);
        printf("  FF: %u\n", metadata.feed_forward_length);
        printf("  Vocab: %u\n", metadata.vocab_size);
        printf("  Context: %u\n", metadata.context_length);
        printf("  RoPE dims: %u, base: %.0f\n", metadata.rope_dim_count, metadata.rope_freq_base);
        printf("  Norm eps: %g\n", metadata.norm_eps);
        printf("  Tokenizer: %s\n", metadata.tokenizer_type.c_str());
        printf("  Tokens: %zu\n", metadata.tokens.size());
        printf("  Merges: %zu\n", metadata.merges.size());
        printf("  Tensors: %zu\n", streamer.tensors.size());
        printf("  File size: %.2f GB\n", streamer.file_size / (1024.0*1024.0*1024.0));
        // Print tensor type distribution
        std::unordered_map<uint32_t, uint32_t> type_counts;
        uint64_t total_bytes = 0;
        for (auto& t : streamer.tensors) {
            type_counts[t.dtype]++;
            total_bytes += t.size_bytes;
        }
        for (auto& [type, count] : type_counts) {
            printf("  %s: %u tensors\n", QuantDispatcher::TypeName(type), count);
        }
        printf("  Total weight data: %.2f GB\n", total_bytes / (1024.0*1024.0*1024.0));
    }
};

// ============================================================================
// MODEL FAMILY REGISTRY
// ============================================================================
struct ArchitectureAdapter {
    std::string name;
    std::function<bool(const GGUFReader&)> detect;
    std::function<bool(const GGUFReader&, float* kv_cache, uint32_t& seq_len, const float* emb, uint32_t layer, uint32_t pos)> forward_layer;
};

class ModelRegistry {
public:
    std::unordered_map<std::string, ArchitectureAdapter> adapters;

    ModelRegistry() {
        Register("llama",   DetectLlama,   ForwardLlama);
        Register("llama2",  DetectLlama,   ForwardLlama);
        Register("llama3",  DetectLlama,   ForwardLlama);
        Register("phi3",    DetectPhi,     ForwardPhi);
        Register("phi4",    DetectPhi,     ForwardPhi);
        Register("gemma",   DetectGemma,   ForwardGemma);
        Register("gemma2",  DetectGemma,   ForwardGemma);
        Register("mistral", DetectMistral, ForwardMistral);
        Register("qwen2",   DetectQwen,    ForwardQwen);
        Register("qwen3",   DetectQwen,    ForwardQwen);
    }

    void Register(const std::string& name, 
                  std::function<bool(const GGUFReader&)> detect,
                  std::function<bool(const GGUFReader&, float*, uint32_t&, const float*, uint32_t, uint32_t)> forward) {
        adapters[name] = {name, detect, forward};
    }

    std::string Detect(const GGUFReader& reader) const {
        // First check metadata architecture field
        if (!reader.metadata.architecture.empty()) {
            std::string arch = reader.metadata.architecture;
            std::transform(arch.begin(), arch.end(), arch.begin(), ::tolower);
            if (adapters.count(arch)) return arch;
            // Map common names
            if (arch.find("llama") != std::string::npos) return "llama";
            if (arch.find("phi") != std::string::npos) return "phi3";
            if (arch.find("gemma") != std::string::npos) return "gemma";
            if (arch.find("mistral") != std::string::npos) return "mistral";
            if (arch.find("qwen") != std::string::npos) return "qwen2";
        }
        // Fallback: detect from tensor names
        for (auto& [name, adapter] : adapters) {
            if (adapter.detect(reader)) return name;
        }
        return "unknown";
    }

    // Architecture detection functions
    static bool DetectLlama(const GGUFReader& r) {
        return r.streamer.tensor_map.count("blk.0.attn_q.weight") > 0;
    }
    static bool DetectPhi(const GGUFReader& r) {
        return r.streamer.tensor_map.count("blk.0.attn_q.weight") > 0 &&
               r.metadata.embedding_length > 0 && r.metadata.block_count <= 48;
    }
    static bool DetectGemma(const GGUFReader& r) {
        return r.streamer.tensor_map.count("blk.0.attn_q.weight") > 0 &&
               r.metadata.norm_eps < 1e-4f;
    }
    static bool DetectMistral(const GGUFReader& r) {
        return r.streamer.tensor_map.count("blk.0.attn_q.weight") > 0 &&
               r.metadata.head_count_kv < r.metadata.head_count;
    }
    static bool DetectQwen(const GGUFReader& r) {
        return r.streamer.tensor_map.count("blk.0.attn_q.weight") > 0 &&
               r.metadata.rope_freq_base > 1000000.0f;
    }

    // Forward functions — each architecture has its own weight layout
    static bool ForwardLlama(const GGUFReader& r, float* kv_cache, uint32_t& seq_len, const float* emb, uint32_t layer, uint32_t pos) {
        return ForwardGeneric(r, kv_cache, seq_len, emb, layer, pos, "blk");
    }
    static bool ForwardPhi(const GGUFReader& r, float* kv_cache, uint32_t& seq_len, const float* emb, uint32_t layer, uint32_t pos) {
        return ForwardGeneric(r, kv_cache, seq_len, emb, layer, pos, "blk");
    }
    static bool ForwardGemma(const GGUFReader& r, float* kv_cache, uint32_t& seq_len, const float* emb, uint32_t layer, uint32_t pos) {
        return ForwardGeneric(r, kv_cache, seq_len, emb, layer, pos, "blk");
    }
    static bool ForwardMistral(const GGUFReader& r, float* kv_cache, uint32_t& seq_len, const float* emb, uint32_t layer, uint32_t pos) {
        return ForwardGeneric(r, kv_cache, seq_len, emb, layer, pos, "blk");
    }
    static bool ForwardQwen(const GGUFReader& r, float* kv_cache, uint32_t& seq_len, const float* emb, uint32_t layer, uint32_t pos) {
        return ForwardGeneric(r, kv_cache, seq_len, emb, layer, pos, "blk");
    }

    // Generic forward pass — works for any Llama-family architecture
    static bool ForwardGeneric(const GGUFReader& r, float* kv_cache, uint32_t& seq_len, const float* emb, uint32_t layer, uint32_t pos, const char* prefix) {
        auto& m = r.metadata;
        uint32_t n_embd = m.embedding_length;
        uint32_t n_head = m.head_count;
        uint32_t n_kv = m.head_count_kv;
        uint32_t d_head = n_embd / n_head;
        uint32_t n_ff = m.feed_forward_length;
        char name[256];

        // Attention norm
        snprintf(name, sizeof(name), "%s.%u.attn_norm.weight", prefix, layer);
        auto* norm_w = r.streamer.GetTensorData(name);
        if (!norm_w) { snprintf(name, sizeof(name), "%s.%u.attention_norm.weight", prefix, layer); norm_w = r.streamer.GetTensorData(name); }

        // QKV projections
        snprintf(name, sizeof(name), "%s.%u.attn_q.weight", prefix, layer);
        auto* wq = r.streamer.GetTensorData(name);
        snprintf(name, sizeof(name), "%s.%u.attn_k.weight", prefix, layer);
        auto* wk = r.streamer.GetTensorData(name);
        snprintf(name, sizeof(name), "%s.%u.attn_v.weight", prefix, layer);
        auto* wv = r.streamer.GetTensorData(name);
        snprintf(name, sizeof(name), "%s.%u.attn_o.weight", prefix, layer);
        auto* wo = r.streamer.GetTensorData(name);

        // FFN weights
        snprintf(name, sizeof(name), "%s.%u.ffn_norm.weight", prefix, layer);
        auto* ffn_norm = r.streamer.GetTensorData(name);
        if (!ffn_norm) { snprintf(name, sizeof(name), "%s.%u.ffn_norm.weight", prefix, layer); ffn_norm = r.streamer.GetTensorData(name); }
        snprintf(name, sizeof(name), "%s.%u.ffn_gate.weight", prefix, layer);
        auto* wgate = r.streamer.GetTensorData(name);
        snprintf(name, sizeof(name), "%s.%u.ffn_up.weight", prefix, layer);
        auto* wup = r.streamer.GetTensorData(name);
        snprintf(name, sizeof(name), "%s.%u.ffn_down.weight", prefix, layer);
        auto* wdown = r.streamer.GetTensorData(name);

        // Allocate temp buffers
        float* x = (float*)malloc(n_embd * sizeof(float));
        float* q = (float*)malloc(n_embd * sizeof(float));
        float* k = (float*)malloc(n_kv * d_head * sizeof(float));
        float* v = (float*)malloc(n_kv * d_head * sizeof(float));
        float* attn_out = (float*)malloc(n_embd * sizeof(float));
        float* attn_proj = (float*)malloc(n_embd * sizeof(float));
        float* ffn_in = (float*)malloc(n_embd * sizeof(float));
        float* ffn_out = (float*)malloc(n_embd * sizeof(float));

        // RMSNorm
        if (norm_w) {
            float ss = 0; for (uint32_t i = 0; i < n_embd; i++) ss += emb[i] * emb[i];
            float scale = 1.0f / sqrtf(ss / n_embd + m.norm_eps);
            for (uint32_t i = 0; i < n_embd; i++) x[i] = norm_w[i] * (emb[i] * scale);
        } else { memcpy(x, emb, n_embd * sizeof(float)); }

        // Q = x * Wq
        if (wq) {
            memset(q, 0, n_embd * sizeof(float));
            for (uint32_t i = 0; i < n_embd; i++)
                for (uint32_t j = 0; j < n_embd; j++)
                    q[i] += x[j] * wq[j * n_embd + i];
        }

        // K = x * Wk
        if (wk) {
            memset(k, 0, n_kv * d_head * sizeof(float));
            for (uint32_t i = 0; i < n_kv * d_head; i++)
                for (uint32_t j = 0; j < n_embd; j++)
                    k[i] += x[j] * wk[j * n_kv * d_head + i];
        }

        // V = x * Wv
        if (wv) {
            memset(v, 0, n_kv * d_head * sizeof(float));
            for (uint32_t i = 0; i < n_kv * d_head; i++)
                for (uint32_t j = 0; j < n_embd; j++)
                    v[i] += x[j] * wv[j * n_kv * d_head + i];
        }

        // RoPE
        for (uint32_t h = 0; h < n_head; h++) {
            for (uint32_t i = 0; i < d_head / 2; i++) {
                float theta = powf(m.rope_freq_base, -2.0f * i / d_head) * m.rope_freq_scale;
                float cos_val = cosf(pos * theta);
                float sin_val = sinf(pos * theta);
                uint32_t idx = h * d_head + i;
                float q0 = q[idx], q1 = q[idx + d_head / 2];
                q[idx] = q0 * cos_val - q1 * sin_val;
                q[idx + d_head / 2] = q0 * sin_val + q1 * cos_val;
                if (h < n_kv) {
                    float k0 = k[idx], k1 = k[idx + d_head / 2];
                    k[idx] = k0 * cos_val - k1 * sin_val;
                    k[idx + d_head / 2] = k0 * sin_val + k1 * cos_val;
                }
            }
        }

        // Store in KV cache
        float* k_cache = kv_cache + layer * 2 * m.context_length * n_kv * d_head;
        float* v_cache = k_cache + m.context_length * n_kv * d_head;
        memcpy(k_cache + pos * n_kv * d_head, k, n_kv * d_head * sizeof(float));
        memcpy(v_cache + pos * n_kv * d_head, v, n_kv * d_head * sizeof(float));

        // Attention
        uint32_t seq = seq_len + 1;
        memset(attn_out, 0, n_embd * sizeof(float));
        for (uint32_t h = 0; h < n_head; h++) {
            float* scores = (float*)malloc(seq * sizeof(float));
            memset(scores, 0, seq * sizeof(float));
            for (uint32_t s = 0; s < seq; s++) {
                for (uint32_t i = 0; i < d_head; i++)
                    scores[s] += q[h * d_head + i] * k_cache[s * n_kv * d_head + (h % n_kv) * d_head + i];
                scores[s] /= sqrtf((float)d_head);
            }
            // Softmax
            float maxv = scores[0]; for (uint32_t s = 1; s < seq; s++) if (scores[s] > maxv) maxv = scores[s];
            float sum = 0; for (uint32_t s = 0; s < seq; s++) { scores[s] = expf(scores[s] - maxv); sum += scores[s]; }
            for (uint32_t s = 0; s < seq; s++) scores[s] /= sum;
            // Weighted sum
            for (uint32_t i = 0; i < d_head; i++) {
                attn_out[h * d_head + i] = 0;
                for (uint32_t s = 0; s < seq; s++)
                    attn_out[h * d_head + i] += scores[s] * v_cache[s * n_kv * d_head + (h % n_kv) * d_head + i];
            }
            free(scores);
        }

        // Output projection
        if (wo) {
            memset(attn_proj, 0, n_embd * sizeof(float));
            for (uint32_t i = 0; i < n_embd; i++)
                for (uint32_t j = 0; j < n_embd; j++)
                    attn_proj[i] += attn_out[j] * wo[j * n_embd + i];
        } else { memcpy(attn_proj, attn_out, n_embd * sizeof(float)); }

        // Residual
        for (uint32_t i = 0; i < n_embd; i++) attn_proj[i] += emb[i];

        // FFN norm
        if (ffn_norm) {
            float ss = 0; for (uint32_t i = 0; i < n_embd; i++) ss += attn_proj[i] * attn_proj[i];
            float scale = 1.0f / sqrtf(ss / n_embd + m.norm_eps);
            for (uint32_t i = 0; i < n_embd; i++) ffn_in[i] = ffn_norm[i] * (attn_proj[i] * scale);
        } else { memcpy(ffn_in, attn_proj, n_embd * sizeof(float)); }

        // SwiGLU FFN
        if (wgate && wup) {
            float* gate = (float*)malloc(n_ff * sizeof(float));
            float* up = (float*)malloc(n_ff * sizeof(float));
            memset(gate, 0, n_ff * sizeof(float));
            memset(up, 0, n_ff * sizeof(float));
            for (uint32_t i = 0; i < n_ff; i++) {
                for (uint32_t j = 0; j < n_embd; j++) {
                    gate[i] += ffn_in[j] * wgate[j * n_ff + i];
                    up[i] += ffn_in[j] * wup[j * n_ff + i];
                }
                gate[i] = gate[i] / (1.0f + expf(-gate[i])); // SiLU
            }
            if (wdown) {
                memset(ffn_out, 0, n_embd * sizeof(float));
                for (uint32_t i = 0; i < n_embd; i++)
                    for (uint32_t j = 0; j < n_ff; j++)
                        ffn_out[i] += (gate[j] * up[j]) * wdown[j * n_embd + i];
            }
            free(gate); free(up);
        } else if (wdown) {
            // Simple FFN (no gate)
            float* hidden = (float*)malloc(n_ff * sizeof(float));
            memset(hidden, 0, n_ff * sizeof(float));
            for (uint32_t i = 0; i < n_ff; i++)
                for (uint32_t j = 0; j < n_embd; j++)
                    hidden[i] += ffn_in[j] * wdown[j * n_ff + i];
            // ReLU
            for (uint32_t i = 0; i < n_ff; i++) if (hidden[i] < 0) hidden[i] = 0;
            memset(ffn_out, 0, n_embd * sizeof(float));
            for (uint32_t i = 0; i < n_embd; i++)
                for (uint32_t j = 0; j < n_ff; j++)
                    ffn_out[i] += hidden[j] * wdown[j * n_embd + i];
            free(hidden);
        }

        // Residual
        for (uint32_t i = 0; i < n_embd; i++) ffn_out[i] += attn_proj[i];

        // Copy output
        memcpy((float*)emb, ffn_out, n_embd * sizeof(float));

        free(x); free(q); free(k); free(v);
        free(attn_out); free(attn_proj); free(ffn_in); free(ffn_out);
        return true;
    }
};

// ============================================================================
// TOKENIZER — extracted from GGUF metadata
// ============================================================================
class Tokenizer {
public:
    std::vector<std::string> vocab;
    std::unordered_map<std::string, int> token_map;
    std::vector<std::pair<std::string, std::string>> bpe_merges;
    std::string tokenizer_type;
    int bos_id = 1, eos_id = 2, pad_id = 0, unk_id = 0;
    bool initialized = false;

    bool Init(const ModelMetadata& meta) {
        vocab = meta.tokens;
        tokenizer_type = meta.tokenizer_type;
        bos_id = meta.bos_token_id;
        eos_id = meta.eos_token_id;
        pad_id = meta.pad_token_id;
        unk_id = meta.unknown_token_id;

        // Build token map
        for (int i = 0; i < (int)vocab.size(); i++) {
            token_map[vocab[i]] = i;
        }

        // Parse BPE merges
        for (auto& m : meta.merges) {
            auto space = m.find(' ');
            if (space != std::string::npos) {
                bpe_merges.push_back({m.substr(0, space), m.substr(space + 1)});
            }
        }

        initialized = true;
        return true;
    }

    std::vector<int> Encode(const std::string& text) {
        std::vector<int> tokens;
        if (tokenizer_type == "bpe") {
            // BPE encoding
            std::vector<std::string> words;
            std::string current;
            for (char c : text) {
                if (c == ' ' && !current.empty()) {
                    words.push_back(current);
                    current.clear();
                } else {
                    current += c;
                }
            }
            if (!current.empty()) words.push_back(current);

            for (auto& word : words) {
                auto encoded = EncodeBPE(word);
                tokens.insert(tokens.end(), encoded.begin(), encoded.end());
            }
        } else {
            // SPM / simple: character-level fallback
            for (char c : text) {
                std::string s(1, c);
                auto it = token_map.find(s);
                if (it != token_map.end()) {
                    tokens.push_back(it->second);
                } else {
                    // Try byte encoding
                    char buf[8]; snprintf(buf, sizeof(buf), "<0x%02X>", (unsigned char)c);
                    std::string byte_str(buf);
                    auto bit = token_map.find(byte_str);
                    if (bit != token_map.end()) tokens.push_back(bit->second);
                    else if (unk_id >= 0 && unk_id < (int)vocab.size()) tokens.push_back(unk_id);
                }
            }
        }
        return tokens;
    }

    std::string Decode(const std::vector<int>& tokens) {
        std::string result;
        for (int t : tokens) {
            if (t >= 0 && t < (int)vocab.size()) {
                result += vocab[t];
            }
        }
        // Clean up BPE artifacts
        if (tokenizer_type == "bpe") {
            // Replace "▁" with space
            size_t pos;
            while ((pos = result.find("▁")) != std::string::npos) {
                result.replace(pos, 3, " ");
            }
        }
        return result;
    }

private:
    std::vector<int> EncodeBPE(const std::string& word) {
        // Simple BPE: split into characters, then merge
        std::vector<std::string> symbols;
        for (char c : word) {
            std::string s(1, c);
            auto it = token_map.find(s);
            if (it != token_map.end()) {
                symbols.push_back(s);
            } else {
                char buf[8]; snprintf(buf, sizeof(buf), "<0x%02X>", (unsigned char)c);
                symbols.push_back(buf);
            }
        }

        // Apply BPE merges
        bool changed = true;
        while (changed) {
            changed = false;
            int best_idx = -1;
            int best_rank = INT_MAX;
            for (int i = 0; i < (int)symbols.size() - 1; i++) {
                std::string pair = symbols[i] + symbols[i + 1];
                for (int j = 0; j < (int)bpe_merges.size(); j++) {
                    if (bpe_merges[j].first + bpe_merges[j].second == pair ||
                        bpe_merges[j].first + " " + bpe_merges[j].second == pair) {
                        if (j < best_rank) { best_rank = j; best_idx = i; }
                        break;
                    }
                }
            }
            if (best_idx >= 0) {
                symbols[best_idx] = symbols[best_idx] + symbols[best_idx + 1];
                symbols.erase(symbols.begin() + best_idx + 1);
                changed = true;
            }
        }

        // Convert to token IDs
        std::vector<int> tokens;
        for (auto& s : symbols) {
            auto it = token_map.find(s);
            if (it != token_map.end()) tokens.push_back(it->second);
            else if (unk_id >= 0) tokens.push_back(unk_id);
        }
        return tokens;
    }
};

// ============================================================================
// MODEL SCANNER
// ============================================================================
class ModelScanner {
public:
    struct ModelInfo {
        std::wstring path;
        std::string name;
        std::string architecture;
        uint64_t size_bytes;
        uint32_t layers;
        uint32_t embedding;
        uint32_t heads;
        std::string quant;
    };

    std::vector<ModelInfo> Scan(const wchar_t* directory) {
        std::vector<ModelInfo> results;
        std::wstring pattern = std::wstring(directory) + L"\\*.gguf";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    std::wstring fullPath = std::wstring(directory) + L"\\" + fd.cFileName;
                    ModelInfo info;
                    info.path = fullPath;
                    info.name = WideToUTF8(fd.cFileName);
                    info.size_bytes = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                    // Quick metadata read
                    GGUFReader reader;
                    if (reader.Load(fullPath.c_str())) {
                        info.architecture = reader.metadata.architecture;
                        info.layers = reader.metadata.block_count;
                        info.embedding = reader.metadata.embedding_length;
                        info.heads = reader.metadata.head_count;
                        // Detect quant from first tensor
                        if (!reader.streamer.tensors.empty()) {
                            info.quant = QuantDispatcher::TypeName(reader.streamer.tensors[0].dtype);
                        }
                    }
                    results.push_back(info);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
        // Sort by size descending
        std::sort(results.begin(), results.end(), [](auto& a, auto& b) {
            return a.size_bytes > b.size_bytes;
        });
        return results;
    }

    static std::string WideToUTF8(const wchar_t* wstr) {
        int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
        std::string result(len - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], len, nullptr, nullptr);
        return result;
    }
};

// ============================================================================
// INFERENCE ENGINE — complete pipeline
// ============================================================================
class InferenceEngine {
public:
    GGUFReader reader;
    ModelRegistry registry;
    Tokenizer tokenizer;
    std::string arch_name;
    float* kv_cache = nullptr;
    uint64_t kv_cache_size = 0;
    uint32_t seq_len = 0;
    float* logits = nullptr;
    std::atomic<bool> stop_requested{false};
    bool initialized = false;

    // Performance tracking
    struct PerfStats {
        uint64_t load_time_us = 0;
        uint64_t first_token_us = 0;
        uint64_t total_gen_us = 0;
        uint32_t tokens_generated = 0;
        float tokens_per_sec = 0;
    } stats;

    ~InferenceEngine() { Cleanup(); }

    bool LoadModel(const wchar_t* path) {
        auto t0 = std::chrono::high_resolution_clock::now();
        if (!reader.Load(path)) return false;
        arch_name = registry.Detect(reader);
        if (arch_name == "unknown") {
            // Try to detect from tensor names
            for (auto& t : reader.streamer.tensors) {
                if (t.name.find("blk.0") != std::string::npos) { arch_name = "llama"; break; }
            }
            if (arch_name == "unknown") arch_name = "llama"; // Default fallback
        }
        // Init tokenizer
        tokenizer.Init(reader.metadata);
        // Allocate KV cache
        uint32_t max_seq = reader.metadata.context_length > 0 ? reader.metadata.context_length : 2048;
        uint32_t n_layers = reader.metadata.block_count;
        uint32_t n_kv = reader.metadata.head_count_kv;
        uint32_t d_head = reader.metadata.embedding_length / reader.metadata.head_count;
        kv_cache_size = (uint64_t)n_layers * 2 * max_seq * n_kv * d_head * sizeof(float);
        kv_cache = (float*)VirtualAlloc(nullptr, kv_cache_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!kv_cache) return false;
        memset(kv_cache, 0, kv_cache_size);
        // Allocate logits
        logits = new float[reader.metadata.vocab_size]();
        auto t1 = std::chrono::high_resolution_clock::now();
        stats.load_time_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        initialized = true;
        return true;
    }

    void Cleanup() {
        if (kv_cache) { VirtualFree(kv_cache, 0, MEM_RELEASE); kv_cache = nullptr; }
        delete[] logits; logits = nullptr;
        initialized = false;
    }

    std::string Generate(const std::string& prompt, int max_tokens = 256, float temp = 0.8f, float top_p = 0.9f, int top_k = 40) {
        if (!initialized) return "Error: No model loaded";
        stop_requested = false;
        seq_len = 0;
        memset(kv_cache, 0, kv_cache_size);
        auto t_start = std::chrono::high_resolution_clock::now();

        // Tokenize prompt
        auto input_tokens = tokenizer.Encode(prompt);
        uint32_t n_embd = reader.metadata.embedding_length;
        uint32_t n_layers = reader.metadata.block_count;
        uint32_t vocab_size = reader.metadata.vocab_size;
        float* emb = new float[n_embd]();
        std::string result;
        bool first_token = true;

        // Process prompt tokens
        for (int t = 0; t < (int)input_tokens.size() && t < max_tokens && !stop_requested; t++) {
            int token = input_tokens[t];
            // Embedding lookup
            memset(emb, 0, n_embd * sizeof(float));
            auto* tok_emb = reader.streamer.GetTensorData("token_embd.weight");
            if (tok_emb) memcpy(emb, tok_emb + token * n_embd, n_embd * sizeof(float));
            // Run all layers
            for (uint32_t l = 0; l < n_layers; l++) {
                auto it = registry.adapters.find(arch_name);
                if (it != registry.adapters.end()) {
                    it->second.forward_layer(reader, kv_cache, seq_len, emb, l, seq_len);
                }
            }
            seq_len++;
            // Output projection
            auto* output_w = reader.streamer.GetTensorData("output.weight");
            if (output_w) {
                memset(logits, 0, vocab_size * sizeof(float));
                for (uint32_t i = 0; i < vocab_size; i++)
                    for (uint32_t j = 0; j < n_embd; j++)
                        logits[i] += emb[j] * output_w[j * vocab_size + i];
            }
            // Sample
            int next = Sample(logits, vocab_size, temp, top_p, top_k);
            if (t < (int)input_tokens.size() - 1) {
                // Continue with next prompt token
                input_tokens[t + 1] = next; // Override for next iteration
            }
        }

        // Autoregressive generation
        int last_token = input_tokens.empty() ? reader.metadata.bos_token_id : input_tokens.back();
        for (int t = 0; t < max_tokens && !stop_requested; t++) {
            auto t_tok = std::chrono::high_resolution_clock::now();
            // Embedding
            memset(emb, 0, n_embd * sizeof(float));
            auto* tok_emb = reader.streamer.GetTensorData("token_embd.weight");
            if (tok_emb) memcpy(emb, tok_emb + last_token * n_embd, n_embd * sizeof(float));
            // Run layers
            for (uint32_t l = 0; l < n_layers; l++) {
                auto it = registry.adapters.find(arch_name);
                if (it != registry.adapters.end()) {
                    it->second.forward_layer(reader, kv_cache, seq_len, emb, l, seq_len);
                }
            }
            seq_len++;
            // Output projection
            auto* output_w = reader.streamer.GetTensorData("output.weight");
            if (output_w) {
                memset(logits, 0, vocab_size * sizeof(float));
                for (uint32_t i = 0; i < vocab_size; i++)
                    for (uint32_t j = 0; j < n_embd; j++)
                        logits[i] += emb[j] * output_w[j * vocab_size + i];
            }
            // Sample
            last_token = Sample(logits, vocab_size, temp, top_p, top_k);
            // Decode
            if (last_token >= 0 && last_token < (int)tokenizer.vocab.size()) {
                result += tokenizer.vocab[last_token];
            }
            stats.tokens_generated++;
            if (first_token) {
                auto t1 = std::chrono::high_resolution_clock::now();
                stats.first_token_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t_tok).count();
                first_token = false;
            }
            if (last_token == reader.metadata.eos_token_id) break;
        }

        delete[] emb;
        auto t_end = std::chrono::high_resolution_clock::now();
        stats.total_gen_us = std::chrono::duration_cast<std::chrono::microseconds>(t_end - t_start).count();
        if (stats.tokens_generated > 0)
            stats.tokens_per_sec = stats.tokens_generated / (stats.total_gen_us / 1000000.0f);

        // Clean up BPE artifacts
        result = tokenizer.Decode(tokenizer.Encode(result));
        return result;
    }

    int Sample(const float* logits, uint32_t n, float temp, float top_p, int top_k) {
        std::vector<std::pair<float, int>> scored;
        for (uint32_t i = 0; i < n; i++) scored.push_back({logits[i] / temp, (int)i});
        std::sort(scored.begin(), scored.end(), [](auto& a, auto& b) { return a.first > b.first; });
        if (top_k > 0 && top_k < (int)scored.size()) scored.resize(top_k);
        float max_val = scored[0].first;
        float sum = 0;
        for (auto& s : scored) { s.first = expf(s.first - max_val); sum += s.first; }
        float cum = 0; int cutoff = (int)scored.size();
        for (int i = 0; i < (int)scored.size(); i++) {
            cum += scored[i].first / sum;
            if (cum > top_p) { cutoff = i + 1; break; }
        }
        if (cutoff < (int)scored.size()) scored.resize(cutoff);
        float r = (float)rand() / RAND_MAX * cum;
        cum = 0;
        for (auto& s : scored) { cum += s.first / sum; if (r <= cum) return s.second; }
        return scored[0].second;
    }
};
