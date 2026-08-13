#include "rawrxd_host.hpp"
#include "rawrxd_transformer.h"
#include "rawrxd_model_loader.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <windows.h>

// ============================================================================
// RawrXD Native Host Control Plane — Implementation
// B017: Thin translation layer, zero inference duplication
// ============================================================================
// Architecture invariant:
//   Host owns: process lifecycle, IPC, model registry, GPU selection
//   Host does NOT own: tokenizer, GGUF parsing, GEMM, attention, KV cache
//   All inference delegated to certified engine via C++ API
// ============================================================================

struct RawrXDHost {
    rawrxd_host_config_t config{};
    std::vector<std::unique_ptr<RawrXDModelLoader>> loaders;
    std::vector<std::unique_ptr<RawrXDTransformer>> transformers;
    std::vector<rawrxd_host_model_info_t> registry;
    rawrxd_host_stats_t stats{};
    bool initialized = false;
};

// ============================================================================
// C ABI Implementation
// ============================================================================

rawrxd_host_t rawrxd_host_create(const rawrxd_host_config_t* config)
{
    if (!config || config->version != 0x00010000) {
        return nullptr;
    }

    RawrXDHost* host = new (std::nothrow) RawrXDHost();
    if (!host) {
        return nullptr;
    }

    host->config = *config;
    host->initialized = true;

    return host;
}

int rawrxd_host_load_model(
    rawrxd_host_t host,
    const char* model_path,
    uint32_t* out_model_id)
{
    if (!host || !model_path || !out_model_id) {
        return RAWRXD_ERR_INVALID_PARAM;
    }
    if (!host->initialized) {
        return RAWRXD_ERR_ENGINE_INIT;
    }

    // Validate path exists
    if (GetFileAttributesA(model_path) == INVALID_FILE_ATTRIBUTES) {
        return RAWRXD_ERR_MODEL_NOT_FOUND;
    }

    // Create loader (certified GGUF parser)
    auto loader = std::make_unique<RawrXDModelLoader>();
    std::wstring wPath(model_path, model_path + std::strlen(model_path));
    if (!loader->Load(wPath.c_str(), nullptr, nullptr)) {
        return RAWRXD_ERR_MODEL_NOT_FOUND;
    }

    // Build engine config from loader metadata
    RawrXDTransformer::Config cfg{};
    cfg.dim = loader->getDim();
    cfg.hidden_dim = loader->getFFNDim();
    cfg.n_layers = loader->getLayers();
    cfg.n_heads = loader->getHeads();
    cfg.n_kv_heads = loader->getKVHeads();
    cfg.vocab_size = loader->getVocabSize();
    cfg.rope_theta = 10000.0f;
    cfg.rms_norm_eps = 1e-5f;

    if (cfg.dim == 0) cfg.dim = 4096;
    if (cfg.n_layers == 0) cfg.n_layers = 32;
    if (cfg.n_heads == 0) cfg.n_heads = 32;
    if (cfg.n_kv_heads == 0) cfg.n_kv_heads = cfg.n_heads;

    // B015: Enable weight residency pool
    cfg.weight_residency_pool_max_bytes = host->config.weight_residency_max_bytes;

    // Create transformer (certified inference engine)
    auto transformer = std::make_unique<RawrXDTransformer>();
    transformer->Initialize(nullptr, nullptr, cfg, loader.get());

    // Populate shallow registry entry
    rawrxd_host_model_info_t info{};
    info.model_id = static_cast<uint32_t>(host->registry.size());
    std::strncpy(info.path, model_path, sizeof(info.path) - 1);
    info.path[sizeof(info.path) - 1] = '\0';
    std::strncpy(info.architecture, "llama", sizeof(info.architecture) - 1);
    info.context_length = loader->getCtx();
    info.parameter_count = 0; // TODO: extract from metadata
    std::strncpy(info.quantization, "Q4_K_M", sizeof(info.quantization) - 1);
    std::memset(info.metadata_checksum, 0, sizeof(info.metadata_checksum));

    *out_model_id = info.model_id;
    host->registry.push_back(info);
    host->loaders.push_back(std::move(loader));
    host->transformers.push_back(std::move(transformer));

    return RAWRXD_OK;
}

int rawrxd_host_generate(
    rawrxd_host_t host,
    uint32_t model_id,
    const uint32_t* prompt_tokens,
    size_t prompt_count,
    size_t max_new_tokens,
    float* out_logits,
    size_t* out_logits_count)
{
    if (!host || !prompt_tokens || !out_logits || !out_logits_count) {
        return RAWRXD_ERR_INVALID_PARAM;
    }
    if (model_id >= host->transformers.size()) {
        return RAWRXD_ERR_INVALID_PARAM;
    }

    RawrXDTransformer* transformer = host->transformers[model_id].get();
    if (!transformer) {
        return RAWRXD_ERR_ENGINE_INIT;
    }

    // Delegate to certified engine Forward()
    std::vector<uint32_t> tokens(prompt_tokens, prompt_tokens + prompt_count);
    std::vector<float> logits = transformer->Forward(tokens, 0);

    if (logits.empty()) {
        return RAWRXD_ERR_INFERENCE;
    }

    size_t copy_count = std::min(logits.size(), static_cast<size_t>(*out_logits_count));
    std::memcpy(out_logits, logits.data(), copy_count * sizeof(float));
    *out_logits_count = copy_count;

    // Update telemetry
    host->stats.total_prompt_tokens_processed += prompt_count;
    host->stats.total_tokens_generated += 1;

    return RAWRXD_OK;
}

int rawrxd_host_generate_batch(
    rawrxd_host_t host,
    uint32_t model_id,
    const uint32_t* prompt_tokens,
    size_t prompt_count,
    size_t max_new_tokens,
    float* out_logits,
    size_t* out_logits_count)
{
    if (!host || !prompt_tokens || !out_logits || !out_logits_count) {
        return RAWRXD_ERR_INVALID_PARAM;
    }
    if (model_id >= host->transformers.size()) {
        return RAWRXD_ERR_INVALID_PARAM;
    }

    RawrXDTransformer* transformer = host->transformers[model_id].get();
    if (!transformer) {
        return RAWRXD_ERR_ENGINE_INIT;
    }

    // Delegate to certified B009 ForwardBatch()
    std::vector<uint32_t> tokens(prompt_tokens, prompt_tokens + prompt_count);
    std::vector<float> logits = transformer->ForwardBatch(tokens, 0);

    if (logits.empty()) {
        return RAWRXD_ERR_INFERENCE;
    }

    size_t copy_count = std::min(logits.size(), static_cast<size_t>(*out_logits_count));
    std::memcpy(out_logits, logits.data(), copy_count * sizeof(float));
    *out_logits_count = copy_count;

    // Update telemetry
    host->stats.total_prompt_tokens_processed += prompt_count;
    host->stats.total_tokens_generated += 1;

    return RAWRXD_OK;
}

int rawrxd_host_reset(rawrxd_host_t host, uint32_t model_id)
{
    if (!host) {
        return RAWRXD_ERR_INVALID_PARAM;
    }
    if (model_id >= host->transformers.size()) {
        return RAWRXD_ERR_INVALID_PARAM;
    }

    // Re-initialize transformer with same config (clears KV cache)
    RawrXDTransformer* transformer = host->transformers[model_id].get();
    RawrXDModelLoader* loader = host->loaders[model_id].get();
    if (!transformer || !loader) {
        return RAWRXD_ERR_ENGINE_INIT;
    }

    RawrXDTransformer::Config cfg{};
    cfg.dim = loader->getDim();
    cfg.hidden_dim = loader->getFFNDim();
    cfg.n_layers = loader->getLayers();
    cfg.n_heads = loader->getHeads();
    cfg.n_kv_heads = loader->getKVHeads();
    cfg.vocab_size = loader->getVocabSize();
    cfg.rope_theta = 10000.0f;
    cfg.rms_norm_eps = 1e-5f;
    cfg.weight_residency_pool_max_bytes = host->config.weight_residency_max_bytes;

    transformer->Initialize(nullptr, nullptr, cfg, loader);

    return RAWRXD_OK;
}

int rawrxd_host_get_stats(
    rawrxd_host_t host,
    uint32_t model_id,
    rawrxd_host_stats_t* out_stats)
{
    if (!host || !out_stats) {
        return RAWRXD_ERR_INVALID_PARAM;
    }

    // Copy accumulated telemetry
    *out_stats = host->stats;

    // TODO: Query engine-specific stats (residency hits/misses, KV cache size)
    // These should be exposed by the certified engine, not computed in host

    return RAWRXD_OK;
}

void rawrxd_host_destroy(rawrxd_host_t host)
{
    if (!host) {
        return;
    }

    // Explicit cleanup order: transformers → loaders
    for (auto& t : host->transformers) {
        t.reset();
    }
    for (auto& l : host->loaders) {
        l.reset();
    }

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
