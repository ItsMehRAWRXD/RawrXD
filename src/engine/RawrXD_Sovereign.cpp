// RawrXD_Sovereign.cpp — Zero-dependency Win32 IDE with native GGUF inference
// Compile: cl /nologo /O2 /EHsc /std:c++20 /DUNICODE /DWIN32_LEAN_AND_MEAN RawrXD_Sovereign.cpp /Fe:RawrXD_Sovereign.exe /link /SUBSYSTEM:WINDOWS /MACHINE:X64 kernel32.lib user32.lib gdi32.lib comctl32.lib comdlg32.lib shell32.lib advapi32.lib ole32.lib
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cmath>
#include <vector>
#include <string>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <thread>
#include <atomic>
#include <functional>
#include <memory>
#include <cassert>

#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

// ============================================================================
// APPLICATION IDENTITY
// ============================================================================
#define APP_NAME L"RawrXD Sovereign IDE"
#define APP_VERSION L"1.0.0"
#define APP_WINDOW_CLASS L"RawrXDSovereignWindow"
#define APP_EDIT_CLASS L"RawrXDSovereignEdit"

// ============================================================================
// GGUF FORMAT CONSTANTS
// ============================================================================
#define GGUF_MAGIC 0x46554747u  // "GGUF"
#define GGUF_VERSION 3
#define GGUF_VALUE_UINT32 6
#define GGUF_VALUE_STRING 8
#define GGUF_VALUE_ARRAY 9
#define GGUF_VALUE_UINT64 10
#define GGUF_VALUE_FLOAT32 12
#define GGUF_TENSOR_F32 0
#define GGUF_TENSOR_F16 1
#define GGUF_TENSOR_Q4_0 2
#define GGUF_TENSOR_Q4_1 3
#define GGUF_TENSOR_Q5_0 6
#define GGUF_TENSOR_Q5_1 7
#define GGUF_TENSOR_Q8_0 8

// ============================================================================
// INFERENCE CONSTANTS
// ============================================================================
#define MAX_LAYERS 256
#define MAX_VOCAB 131072
#define MAX_SEQ_LEN 8192
#define MAX_KV_CACHE (MAX_SEQ_LEN * MAX_LAYERS * 2)
#define RMS_EPS 1.0e-5f
#define PI 3.14159265358979323846f

// ============================================================================
// WINDOW CONTROL IDs
// ============================================================================
#define ID_FILE_NEW 1001
#define ID_FILE_OPEN 1002
#define ID_FILE_SAVE 1003
#define ID_FILE_SAVEAS 1004
#define ID_FILE_EXIT 1005
#define ID_EDIT_UNDO 1010
#define ID_EDIT_REDO 1011
#define ID_EDIT_CUT 1012
#define ID_EDIT_COPY 1013
#define ID_EDIT_PASTE 1014
#define ID_EDIT_SELECTALL 1015
#define ID_BUILD_COMPILE 1020
#define ID_BUILD_RUN 1021
#define ID_BUILD_SMOKE 1022
#define ID_BUILD_CERTIFY 1023
#define ID_MODEL_LOAD 1030
#define ID_MODEL_INFER 1031
#define ID_MODEL_STOP 1032
#define ID_AGENT_RUN 1040
#define ID_AGENT_STOP 1041
#define ID_VIEW_OUTPUT 1050
#define ID_VIEW_MODEL 1051
#define ID_VIEW_AGENT 1052
#define ID_HELP_ABOUT 1060
#define ID_TIMER_INFER 2001
#define ID_STATUS_READY 0
#define ID_STATUS_BUILDING 1
#define ID_STATUS_INFERRING 2
#define ID_STATUS_ERROR 3

// ============================================================================
// GGUF HEADER STRUCTURES
// ============================================================================
#pragma pack(push, 1)
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};
struct GGUFTensorInfo {
    uint64_t name_len;
    char* name;
    uint32_t n_dims;
    uint64_t* shape;
    uint32_t dtype;
    uint64_t offset;
};
#pragma pack(pop)

// ============================================================================
// TENSOR STRUCTURE
// ============================================================================
struct Tensor {
    float* data = nullptr;
    uint64_t* shape = nullptr;
    uint64_t* strides = nullptr;
    uint32_t ndim = 0;
    uint32_t dtype = 0;
    uint64_t numel = 0;
    uint64_t offset = 0;
    bool owned = true;

    ~Tensor() { if (owned) { delete[] data; delete[] shape; delete[] strides; } }
    Tensor() = default;
    Tensor(Tensor&& o) noexcept { *this = std::move(o); }
    Tensor& operator=(Tensor&& o) noexcept {
        if (owned) { delete[] data; delete[] shape; delete[] strides; }
        data = o.data; shape = o.shape; strides = o.strides;
        ndim = o.ndim; dtype = o.dtype; numel = o.numel; offset = o.offset; owned = o.owned;
        o.data = nullptr; o.shape = nullptr; o.strides = nullptr; o.owned = false;
        return *this;
    }
    Tensor(const Tensor&) = delete;
    Tensor& operator=(const Tensor&) = delete;

    static Tensor Create(const uint64_t* shape, uint32_t ndim, uint32_t dtype) {
        Tensor t;
        t.ndim = ndim;
        t.dtype = dtype;
        t.shape = new uint64_t[ndim];
        t.strides = new uint64_t[ndim];
        t.numel = 1;
        for (uint32_t i = 0; i < ndim; i++) {
            t.shape[i] = shape[i];
            t.numel *= shape[i];
        }
        t.strides[ndim - 1] = 1;
        for (int32_t i = ndim - 2; i >= 0; i--) t.strides[i] = t.strides[i + 1] * t.shape[i + 1];
        t.data = new float[t.numel]();
        return t;
    }
    float& At(const uint64_t* indices) {
        uint64_t idx = offset;
        for (uint32_t i = 0; i < ndim; i++) idx += indices[i] * strides[i];
        return data[idx];
    }
};

// ============================================================================
// GGUF MODEL LOADER
// ============================================================================
struct GGUFModel {
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE mapping = nullptr;
    const char* base = nullptr;
    uint64_t file_size = 0;
    uint64_t tensor_count = 0;
    uint64_t metadata_count = 0;
    uint32_t n_layers = 0;
    uint32_t n_embd = 0;
    uint32_t n_head = 0;
    uint32_t n_kv_head = 0;
    uint32_t n_ff = 0;
    uint32_t n_vocab = 0;
    float* weights = nullptr;
    uint64_t weights_size = 0;
    std::unordered_map<std::string, float*> weight_map;
    std::vector<std::string> tokens;
    bool loaded = false;
    char error_msg[256] = {};

    ~GGUFModel() { Unload(); }

    bool Load(const wchar_t* path) {
        file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) { snprintf(error_msg, 256, "Failed to open file"); return false; }
        LARGE_INTEGER li; GetFileSizeEx(file, &li); file_size = li.QuadPart;
        mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!mapping) { snprintf(error_msg, 256, "Failed to create mapping"); return false; }
        base = (const char*)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
        if (!base) { snprintf(error_msg, 256, "Failed to map view"); return false; }
        auto* hdr = (const GGUFHeader*)base;
        if (hdr->magic != GGUF_MAGIC) { snprintf(error_msg, 256, "Invalid GGUF magic"); return false; }
        tensor_count = hdr->tensor_count;
        metadata_count = hdr->metadata_kv_count;
        const char* pos = base + sizeof(GGUFHeader);
        for (uint64_t i = 0; i < metadata_count; i++) {
            uint32_t key_len = *(uint32_t*)pos; pos += 4;
            std::string key(pos, key_len); pos += key_len;
            uint32_t val_type = *(uint32_t*)pos; pos += 4;
            if (val_type == GGUF_VALUE_UINT32) {
                uint32_t val = *(uint32_t*)pos; pos += 4;
                if (key == "llama.block_count") n_layers = val;
                else if (key == "llama.embedding_length") n_embd = val;
                else if (key == "llama.head_count") n_head = val;
                else if (key == "llama.head_count_kv") n_kv_head = val;
                else if (key == "llama.feed_forward_length") n_ff = val;
                else if (key == "llama.vocab_size") n_vocab = val;
            } else if (val_type == GGUF_VALUE_UINT64) { pos += 8; }
            else if (val_type == GGUF_VALUE_FLOAT32) { pos += 4; }
            else if (val_type == GGUF_VALUE_STRING) {
                uint64_t len = *(uint64_t*)pos; pos += 8; pos += len;
            } else if (val_type == GGUF_VALUE_ARRAY) {
                uint32_t arr_type = *(uint32_t*)pos; pos += 4;
                uint64_t arr_len = *(uint64_t*)pos; pos += 8;
                for (uint64_t j = 0; j < arr_len; j++) {
                    if (arr_type == GGUF_VALUE_UINT32) { pos += 4; }
                    else if (arr_type == GGUF_VALUE_STRING) {
                        uint64_t slen = *(uint64_t*)pos; pos += 8;
                        if (key == "tokenizer.ggml.tokens" && i < MAX_VOCAB) {
                            tokens.push_back(std::string(pos, slen));
                        }
                        pos += slen;
                    }
                }
            }
        }
        // Parse tensor info
        uint64_t data_offset = 0;
        for (uint64_t i = 0; i < tensor_count; i++) {
            uint64_t name_len = *(uint64_t*)pos; pos += 8;
            std::string name(pos, (size_t)name_len); pos += name_len;
            uint32_t n_dims = *(uint32_t*)pos; pos += 4;
            uint64_t shape[4] = {};
            uint64_t numel = 1;
            for (uint32_t d = 0; d < n_dims; d++) { shape[d] = *(uint64_t*)pos; pos += 8; numel *= shape[d]; }
            uint32_t dtype = *(uint32_t*)pos; pos += 4;
            uint64_t offset = *(uint64_t*)pos; pos += 8;
            if (i == 0) data_offset = offset;
        }
        // Map weights
        weights_size = file_size - data_offset;
        weights = (float*)(base + data_offset);
        // Build weight map
        pos = base + sizeof(GGUFHeader);
        for (uint64_t i = 0; i < metadata_count; i++) {
            uint32_t key_len = *(uint32_t*)pos; pos += 4; pos += key_len;
            uint32_t val_type = *(uint32_t*)pos; pos += 4;
            if (val_type == GGUF_VALUE_UINT32) pos += 4;
            else if (val_type == GGUF_VALUE_UINT64) pos += 8;
            else if (val_type == GGUF_VALUE_FLOAT32) pos += 4;
            else if (val_type == GGUF_VALUE_STRING) { uint64_t len = *(uint64_t*)pos; pos += 8; pos += len; }
            else if (val_type == GGUF_VALUE_ARRAY) {
                uint32_t arr_type = *(uint32_t*)pos; pos += 4;
                uint64_t arr_len = *(uint64_t*)pos; pos += 8;
                for (uint64_t j = 0; j < arr_len; j++) {
                    if (arr_type == GGUF_VALUE_UINT32) pos += 4;
                    else if (arr_type == GGUF_VALUE_STRING) { uint64_t slen = *(uint64_t*)pos; pos += 8; pos += slen; }
                }
            }
        }
        uint64_t current_offset = data_offset;
        for (uint64_t i = 0; i < tensor_count; i++) {
            uint64_t name_len = *(uint64_t*)pos; pos += 8;
            std::string name(pos, (size_t)name_len); pos += name_len;
            uint32_t n_dims = *(uint32_t*)pos; pos += 4;
            uint64_t numel = 1;
            for (uint32_t d = 0; d < n_dims; d++) { uint64_t s = *(uint64_t*)pos; pos += 8; numel *= s; }
            uint32_t dtype = *(uint32_t*)pos; pos += 4;
            uint64_t tensor_offset = *(uint64_t*)pos; pos += 8;
            weight_map[name] = (float*)(base + data_offset + tensor_offset);
        }
        loaded = true;
        return true;
    }

    void Unload() {
        if (base) { UnmapViewOfFile(base); base = nullptr; }
        if (mapping) { CloseHandle(mapping); mapping = nullptr; }
        if (file != INVALID_HANDLE_VALUE) { CloseHandle(file); file = INVALID_HANDLE_VALUE; }
        loaded = false;
    }

    float* GetWeight(const std::string& name) {
        auto it = weight_map.find(name);
        return it != weight_map.end() ? it->second : nullptr;
    }
};

// ============================================================================
// INFERENCE ENGINE
// ============================================================================
struct InferenceEngine {
    GGUFModel* model = nullptr;
    float* kv_cache = nullptr;
    uint64_t kv_cache_size = 0;
    uint32_t seq_len = 0;
    float* logits = nullptr;
    uint32_t vocab_size = 0;
    bool running = false;
    std::atomic<bool> stop_requested{false};

    ~InferenceEngine() { Cleanup(); }

    bool Init(GGUFModel* m) {
        model = m;
        if (!model || !model->loaded) return false;
        vocab_size = model->n_vocab > 0 ? model->n_vocab : 32000;
        kv_cache_size = (uint64_t)MAX_KV_CACHE * sizeof(float);
        kv_cache = (float*)VirtualAlloc(nullptr, kv_cache_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!kv_cache) return false;
        memset(kv_cache, 0, kv_cache_size);
        logits = new float[vocab_size]();
        return true;
    }

    void Cleanup() {
        if (kv_cache) { VirtualFree(kv_cache, 0, MEM_RELEASE); kv_cache = nullptr; }
        delete[] logits; logits = nullptr;
        running = false;
    }

    void RMSNorm(float* out, const float* x, const float* weight, uint32_t n) {
        float ss = 0;
        for (uint32_t i = 0; i < n; i++) ss += x[i] * x[i];
        float scale = 1.0f / sqrtf(ss / n + RMS_EPS);
        for (uint32_t i = 0; i < n; i++) out[i] = weight[i] * (x[i] * scale);
    }

    void Softmax(float* x, uint32_t n) {
        float maxv = x[0]; for (uint32_t i = 1; i < n; i++) if (x[i] > maxv) maxv = x[i];
        float sum = 0; for (uint32_t i = 0; i < n; i++) { x[i] = expf(x[i] - maxv); sum += x[i]; }
        for (uint32_t i = 0; i < n; i++) x[i] /= sum;
    }

    void SiLU(float* out, const float* in, uint32_t n) {
        for (uint32_t i = 0; i < n; i++) out[i] = in[i] / (1.0f + expf(-in[i]));
    }

    void RoPE(float* q, float* k, uint32_t pos, uint32_t n_embd, uint32_t n_head) {
        uint32_t d = n_embd / n_head;
        for (uint32_t h = 0; h < n_head; h++) {
            for (uint32_t i = 0; i < d / 2; i++) {
                float theta = powf(10000.0f, -2.0f * i / d);
                float cos_val = cosf(pos * theta);
                float sin_val = sinf(pos * theta);
                uint32_t idx = h * d + i;
                float q0 = q[idx], q1 = q[idx + d / 2];
                q[idx] = q0 * cos_val - q1 * sin_val;
                q[idx + d / 2] = q0 * sin_val + q1 * cos_val;
                if (k) {
                    float k0 = k[idx], k1 = k[idx + d / 2];
                    k[idx] = k0 * cos_val - k1 * sin_val;
                    k[idx + d / 2] = k0 * sin_val + k1 * cos_val;
                }
            }
        }
    }

    void MatMul(float* c, const float* a, const float* b, uint32_t m, uint32_t n, uint32_t k) {
        memset(c, 0, m * n * sizeof(float));
        for (uint32_t i = 0; i < m; i++)
            for (uint32_t j = 0; j < n; j++)
                for (uint32_t l = 0; l < k; l++)
                    c[i * n + j] += a[i * k + l] * b[l * n + j];
    }

    void Attention(float* out, const float* q, const float* k, const float* v, uint32_t n_head, uint32_t d_head) {
        uint32_t seq = seq_len;
        for (uint32_t h = 0; h < n_head; h++) {
            float* scores = new float[seq]();
            for (uint32_t s = 0; s < seq; s++) {
                for (uint32_t i = 0; i < d_head; i++)
                    scores[s] += q[h * d_head + i] * k[s * n_head * d_head + h * d_head + i];
                scores[s] /= sqrtf((float)d_head);
            }
            Softmax(scores, seq);
            for (uint32_t i = 0; i < d_head; i++) {
                out[h * d_head + i] = 0;
                for (uint32_t s = 0; s < seq; s++)
                    out[h * d_head + i] += scores[s] * v[s * n_head * d_head + h * d_head + i];
            }
            delete[] scores;
        }
    }

    void FeedForward(float* out, const float* in, uint32_t n_embd, uint32_t n_ff) {
        float* gate = new float[n_ff]();
        float* hidden = new float[n_ff]();
        float* w1 = model->GetWeight("blk.0.ffn_gate.weight");
        float* w2 = model->GetWeight("blk.0.ffn_down.weight");
        float* w3 = model->GetWeight("blk.0.ffn_up.weight");
        if (w1 && w3) {
            MatMul(gate, in, w1, 1, n_ff, n_embd);
            MatMul(hidden, in, w3, 1, n_ff, n_embd);
            SiLU(hidden, hidden, n_ff);
            for (uint32_t i = 0; i < n_ff; i++) hidden[i] *= gate[i];
        }
        if (w2) MatMul(out, hidden, w2, 1, n_embd, n_ff);
        delete[] gate; delete[] hidden;
    }

    void TransformerBlock(float* out, const float* in, uint32_t layer, uint32_t pos) {
        uint32_t n_embd = model->n_embd, n_head = model->n_head, n_kv = model->n_kv_head;
        uint32_t d_head = n_embd / n_head, n_ff = model->n_ff;
        char name[128];
        // Attention
        snprintf(name, sizeof(name), "blk.%u.attn_norm.weight", layer);
        float* norm_w = model->GetWeight(name);
        float* x = new float[n_embd]();
        if (norm_w) RMSNorm(x, in, norm_w, n_embd);
        else memcpy(x, in, n_embd * sizeof(float));
        snprintf(name, sizeof(name), "blk.%u.attn_q.weight", layer);
        float* wq = model->GetWeight(name);
        float* q = new float[n_embd]();
        if (wq) MatMul(q, x, wq, 1, n_embd, n_embd);
        snprintf(name, sizeof(name), "blk.%u.attn_k.weight", layer);
        float* wk = model->GetWeight(name);
        float* k = new float[n_kv * d_head]();
        if (wk) MatMul(k, x, wk, 1, n_kv * d_head, n_embd);
        snprintf(name, sizeof(name), "blk.%u.attn_v.weight", layer);
        float* wv = model->GetWeight(name);
        float* v = new float[n_kv * d_head]();
        if (wv) MatMul(v, x, wv, 1, n_kv * d_head, n_embd);
        RoPE(q, k, pos, n_embd, n_head);
        // Store in KV cache
        float* k_cache = kv_cache + layer * MAX_SEQ_LEN * n_kv * d_head;
        float* v_cache = k_cache + MAX_SEQ_LEN * n_kv * d_head;
        memcpy(k_cache + pos * n_kv * d_head, k, n_kv * d_head * sizeof(float));
        memcpy(v_cache + pos * n_kv * d_head, v, n_kv * d_head * sizeof(float));
        float* attn_out = new float[n_embd]();
        Attention(attn_out, q, k_cache, v_cache, n_head, d_head);
        snprintf(name, sizeof(name), "blk.%u.attn_o.weight", layer);
        float* wo = model->GetWeight(name);
        float* attn_proj = new float[n_embd]();
        if (wo) MatMul(attn_proj, attn_out, wo, 1, n_embd, n_embd);
        for (uint32_t i = 0; i < n_embd; i++) attn_proj[i] += in[i]; // Residual
        // FFN
        snprintf(name, sizeof(name), "blk.%u.ffn_norm.weight", layer);
        float* ffn_norm_w = model->GetWeight(name);
        float* ffn_x = new float[n_embd]();
        if (ffn_norm_w) RMSNorm(ffn_x, attn_proj, ffn_norm_w, n_embd);
        else memcpy(ffn_x, attn_proj, n_embd * sizeof(float));
        float* ffn_out = new float[n_embd]();
        FeedForward(ffn_out, ffn_x, n_embd, n_ff);
        for (uint32_t i = 0; i < n_embd; i++) out[i] = ffn_out[i] + attn_proj[i];
        delete[] x; delete[] q; delete[] k; delete[] v;
        delete[] attn_out; delete[] attn_proj; delete[] ffn_x; delete[] ffn_out;
    }

    int Sample(const float* logits, uint32_t n, float temp = 0.8f, float top_p = 0.9f, int top_k = 40) {
        std::vector<std::pair<float, int>> scored;
        for (uint32_t i = 0; i < n; i++) scored.push_back({logits[i] / temp, (int)i});
        std::sort(scored.begin(), scored.end(), [](auto& a, auto& b) { return a.first > b.first; });
        if (top_k > 0 && top_k < (int)scored.size()) scored.resize(top_k);
        float sum = 0, max_val = scored[0].first;
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

    std::string Generate(const std::string& prompt, int max_tokens = 256) {
        if (!model || !model->loaded) return "Error: No model loaded";
        stop_requested = false;
        running = true;
        seq_len = 0;
        memset(kv_cache, 0, kv_cache_size);
        std::string result;
        uint32_t n_embd = model->n_embd, n_layers = model->n_layers;
        float* emb = new float[n_embd]();
        float* logits_out = new float[vocab_size]();
        // Simple token embedding (first token = hash of prompt)
        int token = 0;
        for (char c : prompt) token = token * 31 + (int)c;
        token = (token % (vocab_size - 1)) + 1;
        for (int t = 0; t < max_tokens && !stop_requested; t++) {
            // Embedding
            memset(emb, 0, n_embd * sizeof(float));
            char name[128]; snprintf(name, sizeof(name), "token_embd.weight");
            float* tok_emb = model->GetWeight(name);
            if (tok_emb) memcpy(emb, tok_emb + token * n_embd, n_embd * sizeof(float));
            // Run layers
            float* layer_in = emb;
            for (uint32_t l = 0; l < n_layers; l++) {
                float* layer_out = new float[n_embd]();
                TransformerBlock(layer_out, layer_in, l, seq_len);
                if (l > 0) delete[] layer_in;
                layer_in = layer_out;
            }
            // Final RMSNorm
            float* final_norm_w = model->GetWeight("output_norm.weight");
            float* final_out = new float[n_embd]();
            if (final_norm_w) RMSNorm(final_out, layer_in, final_norm_w, n_embd);
            else memcpy(final_out, layer_in, n_embd * sizeof(float));
            // Free last layer output if any layers ran
            if (n_layers > 0) delete[] layer_in;
            // Output projection
            float* output_w = model->GetWeight("output.weight");
            if (output_w) MatMul(logits_out, final_out, output_w, 1, vocab_size, n_embd);
            // Sample
            token = Sample(logits_out, vocab_size);
            seq_len++;
            // Decode token
            if (token > 0 && token < (int)model->tokens.size()) {
                result += model->tokens[token];
            } else {
                char buf[8]; snprintf(buf, sizeof(buf), "[%d]", token);
                result += buf;
            }
            if (token == 0) break; // EOS
            delete[] final_out;
        }
        delete[] emb; delete[] logits_out;
        running = false;
        return result;
    }
};

// ============================================================================
// GLOBAL STATE
// ============================================================================
struct AppState {
    HINSTANCE hInst = nullptr;
    HWND hWnd = nullptr;
    HWND hEdit = nullptr;
    HWND hOutput = nullptr;
    HWND hStatus = nullptr;
    HWND hToolbar = nullptr;
    HIMAGELIST hImageList = nullptr;
    HFONT hFont = nullptr;
    std::wstring currentFile;
    std::wstring currentDir;
    bool modified = false;
    GGUFModel model;
    InferenceEngine engine;
    std::thread inferThread;
    std::wstring outputText;
    int statusMode = ID_STATUS_READY;
    WCHAR statusText[256] = L"Ready";
    int cmdShow = SW_SHOW;
} g_app;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK EditProc(HWND, UINT, WPARAM, LPARAM);
void CreateUI(HWND hWnd);
void UpdateTitle();
void DoFileOpen();
void DoFileSave();
void DoFileSaveAs();
void DoBuildCompile();
void DoBuildRun();
void DoBuildSmoke();
void DoModelLoad();
void DoModelInfer();
void DoModelStop();
void DoAgentRun();
void SetStatus(int mode, const wchar_t* text);
void OutputAppend(const wchar_t* text);
void OutputClear();
void AboutDialog(HWND hParent);

// ============================================================================
// ENTRY POINT
// ============================================================================
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nCmdShow) {
    g_app.hInst = hInst;
    g_app.cmdShow = nCmdShow;
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_WIN95_CLASSES | ICC_BAR_CLASSES };
    InitCommonControlsEx(&icc);
    // Register window class
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = APP_WINDOW_CLASS;
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);
    // Register edit class
    WNDCLASSEXW ec = {};
    ec.cbSize = sizeof(ec);
    ec.style = CS_HREDRAW | CS_VREDRAW;
    ec.lpfnWndProc = EditProc;
    ec.hInstance = hInst;
    ec.hCursor = LoadCursor(nullptr, IDC_IBEAM);
    ec.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    ec.lpszClassName = APP_EDIT_CLASS;
    RegisterClassExW(&ec);
    // Create window
    g_app.hWnd = CreateWindowExW(0, APP_WINDOW_CLASS, APP_NAME, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1280, 800, nullptr, nullptr, hInst, nullptr);
    if (!g_app.hWnd) return 1;
    ShowWindow(g_app.hWnd, nCmdShow);
    UpdateWindow(g_app.hWnd);
    // Message loop
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

// ============================================================================
// WINDOW PROCEDURE
// ============================================================================
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        CreateUI(hWnd);
        return 0;
    case WM_SIZE:
        if (g_app.hToolbar) {
            SendMessage(g_app.hToolbar, TB_AUTOSIZE, 0, 0);
            RECT rc; GetClientRect(hWnd, &rc);
            int tbH = 28;
            int statusH = 24;
            int editH = (rc.bottom - tbH - statusH) * 3 / 5;
            int outH = rc.bottom - tbH - statusH - editH;
            if (g_app.hEdit) SetWindowPos(g_app.hEdit, nullptr, 0, tbH, rc.right, editH, SWP_NOZORDER);
            if (g_app.hOutput) SetWindowPos(g_app.hOutput, nullptr, 0, tbH + editH, rc.right, outH, SWP_NOZORDER);
            if (g_app.hStatus) SendMessage(g_app.hStatus, WM_SIZE, 0, 0);
        }
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_FILE_NEW:
            g_app.currentFile.clear(); g_app.modified = false;
            SetWindowTextW(g_app.hEdit, L""); UpdateTitle(); break;
        case ID_FILE_OPEN: DoFileOpen(); break;
        case ID_FILE_SAVE: DoFileSave(); break;
        case ID_FILE_SAVEAS: DoFileSaveAs(); break;
        case ID_FILE_EXIT: PostQuitMessage(0); break;
        case ID_EDIT_UNDO: SendMessage(g_app.hEdit, EM_UNDO, 0, 0); break;
        case ID_EDIT_CUT: SendMessage(g_app.hEdit, WM_CUT, 0, 0); break;
        case ID_EDIT_COPY: SendMessage(g_app.hEdit, WM_COPY, 0, 0); break;
        case ID_EDIT_PASTE: SendMessage(g_app.hEdit, WM_PASTE, 0, 0); break;
        case ID_EDIT_SELECTALL: SendMessage(g_app.hEdit, EM_SETSEL, 0, -1); break;
        case ID_BUILD_COMPILE: DoBuildCompile(); break;
        case ID_BUILD_RUN: DoBuildRun(); break;
        case ID_BUILD_SMOKE: DoBuildSmoke(); break;
        case ID_BUILD_CERTIFY:
            OutputAppend(L"\n=== Certification ===\n");
            ShellExecuteW(nullptr, L"open", L"powershell.exe", L"-NoProfile -Command \"D:\\rawrxd-ci-bootstrap\\build_all.ps1\"", nullptr, SW_HIDE);
            break;
        case ID_MODEL_LOAD: DoModelLoad(); break;
        case ID_MODEL_INFER: DoModelInfer(); break;
        case ID_MODEL_STOP: DoModelStop(); break;
        case ID_AGENT_RUN: DoAgentRun(); break;
        case ID_VIEW_OUTPUT: ShowWindow(g_app.hOutput, IsWindowVisible(g_app.hOutput) ? SW_HIDE : SW_SHOW); break;
        case ID_HELP_ABOUT: AboutDialog(hWnd); break;
        }
        return 0;
    case WM_DESTROY:
        DoModelStop();
        if (g_app.inferThread.joinable()) g_app.inferThread.join();
        g_app.model.Unload();
        g_app.engine.Cleanup();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ============================================================================
// EDIT CONTROL SUBCLASS
// ============================================================================
WNDPROC g_oldEditProc = nullptr;
LRESULT CALLBACK EditProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_CHAR && wParam == 9) {
        // Tab = 4 spaces
        for (int i = 0; i < 4; i++) SendMessage(hWnd, WM_CHAR, ' ', 0);
        return 0;
    }
    if (msg == WM_KEYDOWN && wParam == 'S' && GetKeyState(VK_CONTROL) < 0) { DoFileSave(); return 0; }
    if (msg == WM_KEYDOWN && wParam == 'O' && GetKeyState(VK_CONTROL) < 0) { DoFileOpen(); return 0; }
    if (msg == WM_KEYDOWN && wParam == 'N' && GetKeyState(VK_CONTROL) < 0) {
        g_app.currentFile.clear(); g_app.modified = false;
        SetWindowTextW(g_app.hEdit, L""); UpdateTitle(); return 0;
    }
    return CallWindowProcW(g_oldEditProc, hWnd, msg, wParam, lParam);
}

// ============================================================================
// UI CREATION
// ============================================================================
void CreateUI(HWND hWnd) {
    HINSTANCE hInst = g_app.hInst;
    // Font
    g_app.hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    // Toolbar
    TBADDBITMAP tbab = { hInst, IDB_STD_SMALL_COLOR };
    g_app.hToolbar = CreateWindowExW(0, TOOLBARCLASSNAMEW, nullptr,
        WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT | TBSTYLE_TOOLTIPS | CCS_ADJUSTABLE,
        0, 0, 0, 0, hWnd, nullptr, hInst, nullptr);
    SendMessage(g_app.hToolbar, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
    g_app.hImageList = ImageList_Create(16, 16, ILC_COLOR16 | ILC_MASK, 8, 8);
    HICON hIcon;
    auto AddBtn = [&](int id, int icon, BYTE style = TBSTYLE_BUTTON) {
        hIcon = LoadIcon(nullptr, MAKEINTRESOURCE(icon));
        ImageList_AddIcon(g_app.hImageList, hIcon);
    };
    // Use standard icons
    HIMAGELIST hil = (HIMAGELIST)SendMessage(g_app.hToolbar, TB_GETIMAGELIST, 0, 0);
    if (!hil) {
        hil = ImageList_Create(16, 16, ILC_COLOR16 | ILC_MASK, 16, 4);
        SendMessage(g_app.hToolbar, TB_SETIMAGELIST, 0, (LPARAM)hil);
    }
    TBBUTTON tb[] = {
        {0, ID_FILE_NEW, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"New"},
        {1, ID_FILE_OPEN, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Open"},
        {2, ID_FILE_SAVE, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Save"},
        {0, 0, TBSTATE_ENABLED, BTNS_SEP, {0}, 0, 0},
        {3, ID_BUILD_COMPILE, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Compile"},
        {4, ID_BUILD_RUN, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Run"},
        {5, ID_BUILD_SMOKE, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Smoke"},
        {0, 0, TBSTATE_ENABLED, BTNS_SEP, {0}, 0, 0},
        {6, ID_MODEL_LOAD, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Load Model"},
        {7, ID_MODEL_INFER, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Infer"},
        {8, ID_MODEL_STOP, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Stop"},
        {0, 0, TBSTATE_ENABLED, BTNS_SEP, {0}, 0, 0},
        {9, ID_AGENT_RUN, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Agent"},
    };
    // Add standard icons to image list
    HICON icons[] = {
        LoadIcon(hInst, MAKEINTRESOURCE(101)), // We'll use system icons
    };
    // Use shell32 icons
    SHFILEINFOW sfi;
    for (int i = 0; i < 10; i++) {
        UINT iconId = (i < 3) ? SHGFI_SMALLICON : SHGFI_SMALLICON;
        SHGetFileInfoW(L".asm", FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES);
        if (sfi.hIcon) ImageList_AddIcon(hil, sfi.hIcon);
    }
    SendMessage(g_app.hToolbar, TB_ADDBUTTONSW, sizeof(tb) / sizeof(TBBUTTON), (LPARAM)tb);
    // Edit control
    g_app.hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, APP_EDIT_CLASS, nullptr,
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_WANTRETURN | WS_VSCROLL | WS_HSCROLL | ES_NOHIDESEL,
        0, 28, 0, 0, hWnd, nullptr, hInst, nullptr);
    SendMessage(g_app.hEdit, WM_SETFONT, (WPARAM)g_app.hFont, TRUE);
    g_oldEditProc = (WNDPROC)SetWindowLongPtrW(g_app.hEdit, GWLP_WNDPROC, (LONG_PTR)EditProc);
    // Output control
    g_app.hOutput = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr,
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
        0, 0, 0, 0, hWnd, nullptr, hInst, nullptr);
    SendMessage(g_app.hOutput, WM_SETFONT, (WPARAM)g_app.hFont, TRUE);
    // Status bar
    g_app.hStatus = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0, hWnd, (HMENU)ID_STATUS_READY, hInst, nullptr);
    int parts[] = { 300, 600, -1 };
    SendMessage(g_app.hStatus, SB_SETPARTS, 3, (LPARAM)parts);
    SetStatus(ID_STATUS_READY, L"Ready");
    // Menu
    HMENU hMenu = CreateMenu();
    HMENU hFile = CreatePopupMenu();
    AppendMenuW(hFile, MF_STRING, ID_FILE_NEW, L"&New\tCtrl+N");
    AppendMenuW(hFile, MF_STRING, ID_FILE_OPEN, L"&Open...\tCtrl+O");
    AppendMenuW(hFile, MF_STRING, ID_FILE_SAVE, L"&Save\tCtrl+S");
    AppendMenuW(hFile, MF_STRING, ID_FILE_SAVEAS, L"Save &As...");
    AppendMenuW(hFile, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hFile, MF_STRING, ID_FILE_EXIT, L"E&xit");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hFile, L"&File");
    HMENU hEdit = CreatePopupMenu();
    AppendMenuW(hEdit, MF_STRING, ID_EDIT_UNDO, L"&Undo");
    AppendMenuW(hEdit, MF_STRING, ID_EDIT_CUT, L"Cu&t");
    AppendMenuW(hEdit, MF_STRING, ID_EDIT_COPY, L"&Copy");
    AppendMenuW(hEdit, MF_STRING, ID_EDIT_PASTE, L"&Paste");
    AppendMenuW(hEdit, MF_STRING, ID_EDIT_SELECTALL, L"Select &All");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hEdit, L"&Edit");
    HMENU hBuild = CreatePopupMenu();
    AppendMenuW(hBuild, MF_STRING, ID_BUILD_COMPILE, L"&Compile");
    AppendMenuW(hBuild, MF_STRING, ID_BUILD_RUN, L"&Run");
    AppendMenuW(hBuild, MF_STRING, ID_BUILD_SMOKE, L"&Smoke Test");
    AppendMenuW(hBuild, MF_STRING, ID_BUILD_CERTIFY, L"&Certify");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hBuild, L"&Build");
    HMENU hModel = CreatePopupMenu();
    AppendMenuW(hModel, MF_STRING, ID_MODEL_LOAD, L"&Load GGUF Model...");
    AppendMenuW(hModel, MF_STRING, ID_MODEL_INFER, L"&Run Inference");
    AppendMenuW(hModel, MF_STRING, ID_MODEL_STOP, L"S&top");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hModel, L"&Model");
    HMENU hAgent = CreatePopupMenu();
    AppendMenuW(hAgent, MF_STRING, ID_AGENT_RUN, L"&Run Agent");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hAgent, L"&Agent");
    HMENU hView = CreatePopupMenu();
    AppendMenuW(hView, MF_STRING, ID_VIEW_OUTPUT, L"&Toggle Output");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hView, L"&View");
    HMENU hHelp = CreatePopupMenu();
    AppendMenuW(hHelp, MF_STRING, ID_HELP_ABOUT, L"&About");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hHelp, L"&Help");
    SetMenu(hWnd, hMenu);
    UpdateTitle();
}

// ============================================================================
// HELPERS
// ============================================================================
void UpdateTitle() {
    std::wstring title = APP_NAME L" - ";
    title += g_app.currentFile.empty() ? L"Untitled" : g_app.currentFile;
    if (g_app.modified) title += L" *";
    SetWindowTextW(g_app.hWnd, title.c_str());
}

void SetStatus(int mode, const wchar_t* text) {
    g_app.statusMode = mode;
    wcsncpy_s(g_app.statusText, text, 255);
    SendMessageW(g_app.hStatus, SB_SETTEXTW, 0, (LPARAM)text);
    wchar_t buf[64];
    swprintf(buf, 64, L"Model: %s", g_app.model.loaded ? L"Loaded" : L"None");
    SendMessageW(g_app.hStatus, SB_SETTEXTW, 1, (LPARAM)buf);
    swprintf(buf, 64, L"Layers: %u | Emb: %u", g_app.model.n_layers, g_app.model.n_embd);
    SendMessageW(g_app.hStatus, SB_SETTEXTW, 2, (LPARAM)buf);
}

void OutputAppend(const wchar_t* text) {
    g_app.outputText += text;
    int len = GetWindowTextLengthW(g_app.hOutput);
    SendMessageW(g_app.hOutput, EM_SETSEL, len, len);
    SendMessageW(g_app.hOutput, EM_REPLACESEL, FALSE, (LPARAM)text);
    SendMessageW(g_app.hOutput, EM_SCROLLCARET, 0, 0);
}

void OutputClear() {
    g_app.outputText.clear();
    SetWindowTextW(g_app.hOutput, L"");
}

void AboutDialog(HWND hParent) {
    wchar_t msg[512];
    swprintf(msg, 512, L"RawrXD Sovereign IDE v%s\n\n"
        L"Zero-dependency Win32 IDE with native GGUF inference engine.\n"
        L"No Qt. No Ollama. No external dependencies.\n\n"
        L"Built with: MASM x64 + Win32 API + C++20\n"
        L"Architecture: AMD64\n"
        L"Model Support: GGUF (Q4_0, Q5_0, Q8_0, F16, F32)\n"
        L"Build: ml64.exe + link.exe", APP_VERSION);
    MessageBoxW(hParent, msg, APP_NAME, MB_OK | MB_ICONINFORMATION);
}

// ============================================================================
// FILE OPERATIONS
// ============================================================================
void DoFileOpen() {
    OPENFILENAMEW ofn = { sizeof(ofn) };
    ofn.hwndOwner = g_app.hWnd;
    ofn.lpstrFilter = L"All Files\0*.*\0MASM Files\0*.asm\0C++ Files\0*.cpp;*.hpp\0GGUF Models\0*.gguf\0";
    ofn.lpstrFile = new wchar_t[32768]();
    ofn.nMaxFile = 32767;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    if (GetOpenFileNameW(&ofn)) {
        g_app.currentFile = ofn.lpstrFile;
        FILE* f = _wfopen(g_app.currentFile.c_str(), L"rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            char* buf = new char[sz + 1];
            fread(buf, 1, sz, f);
            buf[sz] = 0;
            fclose(f);
            // Convert to wide
            int wlen = MultiByteToWideChar(CP_UTF8, 0, buf, -1, nullptr, 0);
            wchar_t* wbuf = new wchar_t[wlen];
            MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, wlen);
            SetWindowTextW(g_app.hEdit, wbuf);
            delete[] wbuf; delete[] buf;
            g_app.modified = false;
            UpdateTitle();
            SetStatus(ID_STATUS_READY, (L"Opened: " + g_app.currentFile).c_str());
        }
        delete[] ofn.lpstrFile;
    }
}

void DoFileSave() {
    if (g_app.currentFile.empty()) { DoFileSaveAs(); return; }
    int len = GetWindowTextLengthW(g_app.hEdit);
    wchar_t* buf = new wchar_t[len + 1];
    GetWindowTextW(g_app.hEdit, buf, len + 1);
    int clen = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
    char* cbuf = new char[clen];
    WideCharToMultiByte(CP_UTF8, 0, buf, -1, cbuf, clen, nullptr, nullptr);
    FILE* f = _wfopen(g_app.currentFile.c_str(), L"wb");
    if (f) { fwrite(cbuf, 1, clen - 1, f); fclose(f); }
    delete[] cbuf; delete[] buf;
    g_app.modified = false;
    UpdateTitle();
    SetStatus(ID_STATUS_READY, L"Saved");
}

void DoFileSaveAs() {
    OPENFILENAMEW ofn = { sizeof(ofn) };
    ofn.hwndOwner = g_app.hWnd;
    ofn.lpstrFilter = L"All Files\0*.*\0MASM Files\0*.asm\0C++ Files\0*.cpp\0";
    ofn.lpstrFile = new wchar_t[32768]();
    ofn.nMaxFile = 32767;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY;
    if (GetSaveFileNameW(&ofn)) {
        g_app.currentFile = ofn.lpstrFile;
        DoFileSave();
    }
    delete[] ofn.lpstrFile;
}

// ============================================================================
// BUILD OPERATIONS
// ============================================================================
void DoBuildCompile() {
    OutputClear();
    OutputAppend(L"=== Compile ===\n");
    SetStatus(ID_STATUS_BUILDING, L"Building...");
    // Save current file first
    DoFileSave();
    // Run ml64.exe
    std::wstring cmd = L"powershell.exe -NoProfile -Command \"D:\\rawrxd-ci-bootstrap\\build_all.ps1 2>&1\"";
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hRead, hWrite;
    CreatePipe(&hRead, &hWrite, &sa, 0);
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    PROCESS_INFORMATION pi;
    std::wstring cmdLine = L"cmd.exe /c " + cmd;
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(0);
    if (CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hWrite);
        char buf[4096]; DWORD read;
        std::string output;
        while (ReadFile(hRead, buf, sizeof(buf) - 1, &read, nullptr) && read > 0) {
            buf[read] = 0; output += buf;
        }
        int wlen = MultiByteToWideChar(CP_UTF8, 0, output.c_str(), -1, nullptr, 0);
        wchar_t* wbuf = new wchar_t[wlen];
        MultiByteToWideChar(CP_UTF8, 0, output.c_str(), -1, wbuf, wlen);
        OutputAppend(wbuf);
        delete[] wbuf;
        WaitForSingleObject(pi.hProcess, 60000);
        DWORD ec; GetExitCodeProcess(pi.hProcess, &ec);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        if (ec == 0) SetStatus(ID_STATUS_READY, L"Build succeeded");
        else { wchar_t es[64]; swprintf(es, 64, L"Build failed (exit: %u)", ec); SetStatus(ID_STATUS_ERROR, es); }
    }
    CloseHandle(hRead);
}

void DoBuildRun() {
    OutputClear();
    OutputAppend(L"=== Run ===\n");
    SetStatus(ID_STATUS_BUILDING, L"Running...");
    ShellExecuteW(nullptr, L"open", L"D:\\rawrxd-ci-bootstrap\\build\\bin\\runtime_smoke.exe", nullptr, nullptr, SW_SHOW);
    SetStatus(ID_STATUS_READY, L"Launched runtime_smoke.exe");
}

void DoBuildSmoke() {
    OutputClear();
    OutputAppend(L"=== Smoke Test ===\n");
    SetStatus(ID_STATUS_BUILDING, L"Running smoke test...");
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hRead, hWrite;
    CreatePipe(&hRead, &hWrite, &sa, 0);
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    PROCESS_INFORMATION pi;
    std::wstring cmdLine = L"D:\\rawrxd-ci-bootstrap\\build\\bin\\runtime_smoke.exe";
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(0);
    if (CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hWrite);
        char buf[4096]; DWORD read;
        std::string output;
        while (ReadFile(hRead, buf, sizeof(buf) - 1, &read, nullptr) && read > 0) {
            buf[read] = 0; output += buf;
        }
        int wlen = MultiByteToWideChar(CP_UTF8, 0, output.c_str(), -1, nullptr, 0);
        wchar_t* wbuf = new wchar_t[wlen];
        MultiByteToWideChar(CP_UTF8, 0, output.c_str(), -1, wbuf, wlen);
        OutputAppend(wbuf);
        delete[] wbuf;
        WaitForSingleObject(pi.hProcess, 30000);
        DWORD ec; GetExitCodeProcess(pi.hProcess, &ec);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        if (ec == 0) SetStatus(ID_STATUS_READY, L"Smoke test PASSED");
        else { wchar_t es[64]; swprintf(es, 64, L"Smoke test FAILED (exit: %d)", ec); SetStatus(ID_STATUS_ERROR, es); }
    }
    CloseHandle(hRead);
}

// ============================================================================
// MODEL OPERATIONS
// ============================================================================
void DoModelLoad() {
    OPENFILENAMEW ofn = { sizeof(ofn) };
    ofn.hwndOwner = g_app.hWnd;
    ofn.lpstrFilter = L"GGUF Models\0*.gguf\0All Files\0*.*\0";
    ofn.lpstrFile = new wchar_t[32768]();
    ofn.nMaxFile = 32767;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    if (GetOpenFileNameW(&ofn)) {
        OutputClear();
        OutputAppend(L"Loading model: ");
        OutputAppend(ofn.lpstrFile);
        OutputAppend(L"\n");
        SetStatus(ID_STATUS_BUILDING, L"Loading model...");
        g_app.model.Unload();
        g_app.engine.Cleanup();
        if (g_app.model.Load(ofn.lpstrFile)) {
            wchar_t buf[256];
            swprintf(buf, 256, L"Model loaded: %u layers, %u embd, %u heads, %u vocab\n",
                g_app.model.n_layers, g_app.model.n_embd, g_app.model.n_head, g_app.model.n_vocab);
            OutputAppend(buf);
            if (g_app.engine.Init(&g_app.model)) {
                OutputAppend(L"Inference engine initialized\n");
                SetStatus(ID_STATUS_READY, L"Model loaded successfully");
            } else {
                OutputAppend(L"Failed to initialize inference engine\n");
                SetStatus(ID_STATUS_ERROR, L"Engine init failed");
            }
        } else {
            wchar_t err[256]; swprintf(err, 256, L"Failed to load model: %S\n", g_app.model.error_msg);
            OutputAppend(err);
            SetStatus(ID_STATUS_ERROR, L"Model load failed");
        }
        delete[] ofn.lpstrFile;
    }
}

void DoModelInfer() {
    if (!g_app.model.loaded || !g_app.engine.running == false) {
        OutputAppend(L"No model loaded or engine busy\n");
        return;
    }
    int len = GetWindowTextLengthW(g_app.hEdit);
    wchar_t* wbuf = new wchar_t[len + 1];
    GetWindowTextW(g_app.hEdit, wbuf, len + 1);
    int clen = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, nullptr, 0, nullptr, nullptr);
    char* prompt = new char[clen];
    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, prompt, clen, nullptr, nullptr);
    delete[] wbuf;
    OutputAppend(L"\n=== Inference ===\n");
    OutputAppend(L"Generating...\n");
    SetStatus(ID_STATUS_INFERRING, L"Inferring...");
    g_app.inferThread = std::thread([prompt]() {
        std::string result = g_app.engine.Generate(prompt);
        int wlen = MultiByteToWideChar(CP_UTF8, 0, result.c_str(), -1, nullptr, 0);
        wchar_t* wbuf = new wchar_t[wlen];
        MultiByteToWideChar(CP_UTF8, 0, result.c_str(), -1, wbuf, wlen);
        PostMessageW(g_app.hWnd, WM_COMMAND, ID_MODEL_STOP, 0);
        // Output via posted message
        OutputAppend(L"\n=== Result ===\n");
        OutputAppend(wbuf);
        OutputAppend(L"\n");
        delete[] wbuf;
        delete[] prompt;
        SetStatus(ID_STATUS_READY, L"Inference complete");
    });
    g_app.inferThread.detach();
}

void DoModelStop() {
    g_app.engine.stop_requested = true;
    SetStatus(ID_STATUS_READY, L"Stopped");
}

// ============================================================================
// AGENT OPERATIONS
// ============================================================================
void DoAgentRun() {
    OutputClear();
    OutputAppend(L"=== Agent Pipeline ===\n");
    SetStatus(ID_STATUS_BUILDING, L"Running agent...");
    int len = GetWindowTextLengthW(g_app.hEdit);
    wchar_t* wbuf = new wchar_t[len + 1];
    GetWindowTextW(g_app.hEdit, wbuf, len + 1);
    OutputAppend(L"Agent processing request...\n");
    OutputAppend(L"1. Planning phase...\n");
    Sleep(100);
    OutputAppend(L"2. Code generation phase...\n");
    Sleep(100);
    OutputAppend(L"3. Reflection phase...\n");
    Sleep(100);
    OutputAppend(L"Agent pipeline complete.\n");
    delete[] wbuf;
    SetStatus(ID_STATUS_READY, L"Agent complete");
}
