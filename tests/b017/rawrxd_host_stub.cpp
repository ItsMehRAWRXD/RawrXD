// ============================================================================
// rawrxd_host_stub.cpp — Minimal stub for B017 host certification
// Only implements the C ABI functions, no engine internals
// ============================================================================
#include "rawrxd_host.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

// Minimal model loader stub
class StubModelLoader {
public:
    bool Load(const wchar_t*) { return true; }
    int getDim() const { return 3072; }
    int getFFNDim() const { return 8192; }
    int getLayers() const { return 28; }
    int getHeads() const { return 24; }
    int getKVHeads() const { return 8; }
    int getVocabSize() const { return 128256; }
    int getCtx() const { return 131072; }
};

// Minimal transformer stub
class StubTransformer {
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

    bool Initialize(void*, void*, const Config& cfg, StubModelLoader*) {
        config_ = cfg;
        return true;
    }

    std::vector<float> Forward(const std::vector<uint32_t>&, int) {
        return std::vector<float>(config_.vocab_size, 0.0f);
    }

    std::vector<float> ForwardBatch(const std::vector<uint32_t>&, int) {
        return std::vector<float>(config_.vocab_size, 0.0f);
    }

private:
    Config config_;
};

struct RawrXDHost {
    rawrxd_host_config_t config{};
    std::vector<StubModelLoader> loaders;
    std::vector<StubTransformer> transformers;
    std::vector<rawrxd_host_model_info_t> registry;
    rawrxd_host_stats_t stats{};
    bool initialized = false;
};

extern "C" {

rawrxd_host_t rawrxd_host_create(const rawrxd_host_config_t* config)
{
    if (!config || config->version != 0x00010000) return nullptr;
    RawrXDHost* host = new (std::nothrow) RawrXDHost();
    if (!host) return nullptr;
    host->config = *config;
    host->initialized = true;
    return host;
}

int rawrxd_host_load_model(rawrxd_host_t host, const char* model_path, uint32_t* out_model_id)
{
    if (!host || !model_path || !out_model_id) return RAWRXD_ERR_INVALID_PARAM;
    if (!host->initialized) return RAWRXD_ERR_ENGINE_INIT;

    StubModelLoader loader;
    if (!loader.Load(nullptr)) return RAWRXD_ERR_MODEL_NOT_FOUND;

    StubTransformer transformer;
    StubTransformer::Config cfg{};
    cfg.dim = loader.getDim();
    cfg.hidden_dim = loader.getFFNDim();
    cfg.n_layers = loader.getLayers();
    cfg.n_heads = loader.getHeads();
    cfg.n_kv_heads = loader.getKVHeads();
    cfg.vocab_size = loader.getVocabSize();
    cfg.weight_residency_pool_max_bytes = host->config.weight_residency_max_bytes;
    transformer.Initialize(nullptr, nullptr, cfg, &loader);

    rawrxd_host_model_info_t info{};
    info.model_id = static_cast<uint32_t>(host->registry.size());
    std::strncpy(info.path, model_path, sizeof(info.path) - 1);
    std::strncpy(info.architecture, "llama", sizeof(info.architecture) - 1);
    info.context_length = loader.getCtx();
    std::strncpy(info.quantization, "Q4_K_M", sizeof(info.quantization) - 1);

    *out_model_id = info.model_id;
    host->registry.push_back(info);
    host->loaders.push_back(loader);
    host->transformers.push_back(transformer);

    return RAWRXD_OK;
}

int rawrxd_host_generate(rawrxd_host_t host, uint32_t model_id,
    const uint32_t* prompt_tokens, size_t prompt_count, size_t max_new_tokens,
    float* out_logits, size_t* out_logits_count)
{
    (void)max_new_tokens;
    if (!host || !prompt_tokens || !out_logits || !out_logits_count) return RAWRXD_ERR_INVALID_PARAM;
    if (model_id >= host->transformers.size()) return RAWRXD_ERR_INVALID_PARAM;

    std::vector<uint32_t> tokens(prompt_tokens, prompt_tokens + prompt_count);
    std::vector<float> logits = host->transformers[model_id].Forward(tokens, 0);
    if (logits.empty()) return RAWRXD_ERR_INFERENCE;

    size_t copy_count = std::min(logits.size(), *out_logits_count);
    std::memcpy(out_logits, logits.data(), copy_count * sizeof(float));
    *out_logits_count = copy_count;
    host->stats.total_prompt_tokens_processed += prompt_count;
    host->stats.total_tokens_generated += 1;
    return RAWRXD_OK;
}

int rawrxd_host_generate_batch(rawrxd_host_t host, uint32_t model_id,
    const uint32_t* prompt_tokens, size_t prompt_count, size_t max_new_tokens,
    float* out_logits, size_t* out_logits_count)
{
    (void)max_new_tokens;
    if (!host || !prompt_tokens || !out_logits || !out_logits_count) return RAWRXD_ERR_INVALID_PARAM;
    if (model_id >= host->transformers.size()) return RAWRXD_ERR_INVALID_PARAM;

    std::vector<uint32_t> tokens(prompt_tokens, prompt_tokens + prompt_count);
    std::vector<float> logits = host->transformers[model_id].ForwardBatch(tokens, 0);
    if (logits.empty()) return RAWRXD_ERR_INFERENCE;

    size_t copy_count = std::min(logits.size(), *out_logits_count);
    std::memcpy(out_logits, logits.data(), copy_count * sizeof(float));
    *out_logits_count = copy_count;
    host->stats.total_prompt_tokens_processed += prompt_count;
    host->stats.total_tokens_generated += 1;
    return RAWRXD_OK;
}

int rawrxd_host_reset(rawrxd_host_t host, uint32_t model_id)
{
    if (!host) return RAWRXD_ERR_INVALID_PARAM;
    if (model_id >= host->transformers.size()) return RAWRXD_ERR_INVALID_PARAM;

    StubModelLoader& loader = host->loaders[model_id];
    StubTransformer& transformer = host->transformers[model_id];

    StubTransformer::Config cfg{};
    cfg.dim = loader.getDim();
    cfg.hidden_dim = loader.getFFNDim();
    cfg.n_layers = loader.getLayers();
    cfg.n_heads = loader.getHeads();
    cfg.n_kv_heads = loader.getKVHeads();
    cfg.vocab_size = 128256;
    cfg.weight_residency_pool_max_bytes = host->config.weight_residency_max_bytes;
    transformer.Initialize(nullptr, nullptr, cfg, &loader);

    return RAWRXD_OK;
}

int rawrxd_host_get_stats(rawrxd_host_t host, uint32_t, rawrxd_host_stats_t* out_stats)
{
    if (!host || !out_stats) return RAWRXD_ERR_INVALID_PARAM;
    *out_stats = host->stats;
    return RAWRXD_OK;
}

void rawrxd_host_destroy(rawrxd_host_t host)
{
    if (!host) return;
    delete host;
}

const char* rawrxd_host_strerror(int error_code)
{
    switch (error_code) {
        case RAWRXD_OK:                    return "OK";
        case RAWRXD_ERR_INVALID_PARAM:     return "Invalid parameter";
        case RAWRXD_ERR_OUT_OF_MEMORY:     return "Out of memory";
        case RAWRXD_ERR_MODEL_NOT_FOUND:   return "Model not found";
        case RAWRXD_ERR_ENGINE_INIT:       return "Engine initialization failed";
        case RAWRXD_ERR_INFERENCE:         return "Inference failed";
        case RAWRXD_ERR_NOT_IMPLEMENTED:   return "Not implemented";
        case RAWRXD_ERR_PIPE_IO:           return "Pipe I/O error";
        case RAWRXD_ERR_PROTOCOL:          return "Protocol error";
        default:                           return "Unknown error";
    }
}

} // extern "C"
