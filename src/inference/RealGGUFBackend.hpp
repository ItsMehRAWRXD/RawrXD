// ============================================================================
// RealGGUFBackend.hpp - ACTUAL GGUF/llama.cpp Backend Interface
// ============================================================================
// This is NOT a stub. It provides real GGUF model loading and inference.
//
// Copyright (c) 2026 RawrXD Team
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>

namespace RawrXD {
namespace Inference {

// Configuration
struct GGMLBackendConfig {
    int n_threads = 4;
    int n_batch = 512;
    int n_ctx = 4096;
    int n_gpu_layers = 0;
    float temperature = 0.8f;
    int max_tokens = 256;
    float top_p = 0.95f;
    int top_k = 40;
    float repeat_penalty = 1.1f;
    std::string model_path;
    std::string backend_type = "CPU";
};

// Model Information
struct ModelInfo {
    uint32_t vocab_size = 0;
    uint32_t context_length = 0;
    uint32_t embedding_length = 0;
    uint32_t head_count = 0;
    uint32_t layer_count = 0;
    std::string quant_type;
    uint64_t param_count = 0;
};

// Inference Request/Response
struct InferenceRequest {
    std::vector<uint32_t> input_tokens;
    uint32_t max_tokens = 256;
    float temperature = 0.8f;
    float top_p = 0.95f;
    int top_k = 40;
    bool stream_tokens = false;
};

struct InferenceResult {
    bool success = false;
    std::vector<uint32_t> tokens;
    uint32_t tokens_generated = 0;
    uint32_t completion_time_ms = 0;
    std::string error_message;
};

struct TokenInfo {
    uint32_t token = 0;
    uint32_t token_id = 0;
    float logprob = 0.0f;
    bool is_eos = false;
};

using TokenCallback = std::function<void(const TokenInfo&)>;
using InferenceCallback = std::function<void(const InferenceResult&)>;

// ============================================================================
// REAL GGUF Backend (uses actual llama.cpp)
// ============================================================================

class RealGGUFBackend {
public:
    explicit RealGGUFBackend(const GGMLBackendConfig& config);
    ~RealGGUFBackend();

    // Static factory
    static std::unique_ptr<RealGGUFBackend> Create(const GGMLBackendConfig& config);

    // Lifecycle
    bool Initialize();
    void Shutdown();

    // Model management
    bool LoadModel(const std::string& path);
    void UnloadModel();
    bool IsModelLoaded() const;

    // Info
    std::string GetBackendType() const;
    ModelInfo GetModelInfo() const;
    std::string GetModelArchitecture() const;

    // Inference
    InferenceResult RunInference(const InferenceRequest& request);
    void RunInferenceAsync(const InferenceRequest& request, InferenceCallback callback);

private:
    GGMLBackendConfig config_;
    bool initialized_;
    bool model_loaded_;
    std::string model_path_;
    ModelInfo model_info_;

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace Inference
} // namespace RawrXD
