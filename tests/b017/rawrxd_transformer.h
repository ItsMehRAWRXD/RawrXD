// ============================================================================
// rawrxd_transformer_minimal.h — Minimal header for B017 host certification
// Stubs out transformer/model_loader/tokenizer just enough for host linking
// ============================================================================
#pragma once
#include <vector>
#include <stdint>
#include <string>
#include <windows.h>

class RawrXDModelLoader {
public:
    bool Load(const wchar_t* path, void*, void*);
    float* GetTensor(const std::string& name);
    bool GetTensorRow(const std::string& name, size_t rowIndex, float* out, size_t cols);
    void ReleaseTensor(const std::string& name);

    int getDim() const { return dim_; }
    int getFFNDim() const { return hidden_dim_; }
    int getLayers() const { return n_layers_; }
    int getHeads() const { return n_heads_; }
    int getKVHeads() const { return n_kv_heads_; }
    int getVocabSize() const { return vocab_size_; }
    int getCtx() const { return ctx_; }

private:
    int dim_ = 3072;
    int hidden_dim_ = 8192;
    int n_layers_ = 28;
    int n_heads_ = 24;
    int n_kv_heads_ = 8;
    int vocab_size_ = 128256;
    int ctx_ = 131072;
};

class RawrXDTokenizer {
public:
    bool Load(const char* path);
    std::vector<uint32_t> Encode(const std::string& text);
};

class RawrXDTransformer {
public:
    struct Config {
        int dim = 4096;
        int hidden_dim = 11008;
        int n_layers = 32;
        int n_heads = 32;
        int n_kv_heads = 32;
        int vocab_size = 32000;
        float rope_theta = 10000.0f;
        float rms_norm_eps = 1e-5f;
        uint64_t weight_residency_pool_max_bytes = 0;
    };

    bool Initialize(void*, void*, const Config& cfg, RawrXDModelLoader* loader);
    std::vector<float> Forward(const std::vector<uint32_t>& tokens, int start_pos);
    std::vector<float> ForwardBatch(const std::vector<uint32_t>& tokens, int start_pos);

private:
    Config config_;
    bool initialized_ = false;
};
