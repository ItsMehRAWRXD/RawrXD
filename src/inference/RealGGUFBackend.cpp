// ============================================================================
// RealGGUFBackend.cpp - ACTUAL GGUF/llama.cpp Backend Implementation
// ============================================================================
// This is NOT a stub. It uses real llama.cpp to load and run GGUF models.
//
// Copyright (c) 2026 RawrXD Team
// ============================================================================

#include "RealGGUFBackend.hpp"
#include <llama.h>
#include <iostream>
#include <cstring>

namespace RawrXD {
namespace Inference {

// Real implementation using llama.cpp
struct RealGGUFBackend::Impl {
    llama_model* model = nullptr;
    llama_context* ctx = nullptr;
    llama_vocab* vocab = nullptr;
    bool initialized = false;
    GGMLBackendConfig config;
};

RealGGUFBackend::RealGGUFBackend(const GGMLBackendConfig& config)
    : config_(config)
    , initialized_(false)
    , model_loaded_(false)
    , impl_(std::make_unique<Impl>()) {
    impl_->config = config;
}

RealGGUFBackend::~RealGGUFBackend() {
    if (initialized_) {
        Shutdown();
    }
}

std::unique_ptr<RealGGUFBackend> RealGGUFBackend::Create(const GGMLBackendConfig& config) {
    return std::unique_ptr<RealGGUFBackend>(new RealGGUFBackend(config));
}

bool RealGGUFBackend::Initialize() {
    std::cout << "[RealGGUFBackend::Initialize] Initializing llama.cpp backend..." << std::endl;
    
    // Initialize llama.cpp
    llama_backend_init();
    
    impl_->initialized = true;
    initialized_ = true;
    
    std::cout << "[RealGGUFBackend::Initialize] llama.cpp backend initialized" << std::endl;
    return true;
}

void RealGGUFBackend::Shutdown() {
    std::cout << "[RealGGUFBackend::Shutdown] Shutting down..." << std::endl;
    
    if (impl_->ctx) {
        llama_free(impl_->ctx);
        impl_->ctx = nullptr;
    }
    
    if (impl_->model) {
        llama_model_free(impl_->model);
        impl_->model = nullptr;
    }
    
    llama_backend_free();
    
    impl_->initialized = false;
    initialized_ = false;
    model_loaded_ = false;
}

bool RealGGUFBackend::LoadModel(const std::string& path) {
    std::cout << "[RealGGUFBackend::LoadModel] Loading model: " << path << std::endl;
    
    if (!initialized_) {
        std::cerr << "[RealGGUFBackend::LoadModel] ERROR: Backend not initialized" << std::endl;
        return false;
    }
    
    // Load the model
    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = config_.n_gpu_layers;
    model_params.main_gpu = 0;
    
    impl_->model = llama_model_load_from_file(path.c_str(), model_params);
    if (!impl_->model) {
        std::cerr << "[RealGGUFBackend::LoadModel] ERROR: Failed to load model from " << path << std::endl;
        return false;
    }
    
    // Get vocab
    impl_->vocab = llama_model_get_vocab(impl_->model);
    
    // Create context
    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = config_.n_ctx;
    ctx_params.n_batch = config_.n_batch;
    ctx_params.n_threads = config_.n_threads;
    ctx_params.n_threads_batch = config_.n_threads;
    
    impl_->ctx = llama_init_from_model(impl_->model, ctx_params);
    if (!impl_->ctx) {
        std::cerr << "[RealGGUFBackend::LoadModel] ERROR: Failed to create context" << std::endl;
        llama_model_free(impl_->model);
        impl_->model = nullptr;
        return false;
    }
    
    // Get model info
    const llama_model* model = llama_get_model(impl_->ctx);
    const llama_hparams* hparams = llama_model_get_hparams(model);
    
    model_info_.vocab_size = llama_vocab_n_tokens(impl_->vocab);
    model_info_.context_length = llama_model_n_ctx_train(model);
    model_info_.embedding_length = hparams ? hparams->n_embd : 0;
    model_info_.head_count = hparams ? hparams->n_head : 0;
    model_info_.layer_count = hparams ? hparams->n_layer : 0;
    model_info_.quant_type = llama_model_quantization_type(model);
    
    model_path_ = path;
    model_loaded_ = true;
    
    std::cout << "[RealGGUFBackend::LoadModel] Model loaded successfully:" << std::endl;
    std::cout << "  Vocab size: " << model_info_.vocab_size << std::endl;
    std::cout << "  Context length: " << model_info_.context_length << std::endl;
    std::cout << "  Embedding length: " << model_info_.embedding_length << std::endl;
    std::cout << "  Layers: " << model_info_.layer_count << std::endl;
    
    return true;
}

void RealGGUFBackend::UnloadModel() {
    std::cout << "[RealGGUFBackend::UnloadModel] Unloading model..." << std::endl;
    
    if (impl_->ctx) {
        llama_free(impl_->ctx);
        impl_->ctx = nullptr;
    }
    
    if (impl_->model) {
        llama_model_free(impl_->model);
        impl_->model = nullptr;
    }
    
    impl_->vocab = nullptr;
    model_loaded_ = false;
    model_path_.clear();
}

bool RealGGUFBackend::IsModelLoaded() const {
    return model_loaded_ && impl_->model != nullptr;
}

std::string RealGGUFBackend::GetBackendType() const {
    return "GGML_REAL";
}

ModelInfo RealGGUFBackend::GetModelInfo() const {
    return model_info_;
}

std::string RealGGUFBackend::GetModelArchitecture() const {
    if (!impl_->model) return "unknown";
    
    const char* arch = llama_model_get_arch(impl_->model);
    return arch ? arch : "unknown";
}

InferenceResult RealGGUFBackend::RunInference(const InferenceRequest& request) {
    InferenceResult result;
    
    if (!IsModelLoaded()) {
        result.success = false;
        result.error_message = "No model loaded";
        return result;
    }
    
    auto start_time = std::chrono::steady_clock::now();
    
    // Tokenize input
    std::vector<llama_token> tokens;
    tokens.reserve(request.input_tokens.size());
    for (auto token : request.input_tokens) {
        tokens.push_back(static_cast<llama_token>(token));
    }
    
    if (tokens.empty()) {
        // Use BOS token if no input
        tokens.push_back(llama_vocab_bos(impl_->vocab));
    }
    
    // Evaluate initial tokens
    llama_batch batch = llama_batch_init(tokens.size(), 0, 1);
    for (size_t i = 0; i < tokens.size(); i++) {
        batch.token[i] = tokens[i];
        batch.pos[i] = i;
        batch.n_seq_id[i] = 1;
        batch.seq_id[i][0] = 0;
        batch.logits[i] = 0;
    }
    batch.logits[tokens.size() - 1] = 1; // Compute logits for last token
    batch.n_tokens = tokens.size();
    
    if (llama_decode(impl_->ctx, batch) != 0) {
        result.success = false;
        result.error_message = "Failed to decode initial tokens";
        llama_batch_free(batch);
        return result;
    }
    
    // Generate tokens
    result.tokens.reserve(request.max_tokens);
    
    for (uint32_t i = 0; i < request.max_tokens; i++) {
        // Sample next token
        llama_token new_token;
        
        float* logits = llama_get_logits(impl_->ctx);
        int n_vocab = llama_vocab_n_tokens(impl_->vocab);
        
        // Simple greedy sampling for now
        float max_logit = -1e10f;
        int max_idx = 0;
        for (int j = 0; j < n_vocab; j++) {
            if (logits[j] > max_logit) {
                max_logit = logits[j];
                max_idx = j;
            }
        }
        new_token = max_idx;
        
        // Check for EOS
        if (llama_vocab_is_eog(impl_->vocab, new_token)) {
            break;
        }
        
        result.tokens.push_back(static_cast<uint32_t>(new_token));
        
        // Prepare next batch
        llama_batch_clear(batch);
        llama_batch_add(batch, new_token, tokens.size() + i, {0}, true);
        
        if (llama_decode(impl_->ctx, batch) != 0) {
            result.success = false;
            result.error_message = "Failed to decode token " + std::to_string(i);
            llama_batch_free(batch);
            return result;
        }
    }
    
    llama_batch_free(batch);
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    result.success = true;
    result.tokens_generated = result.tokens.size();
    result.completion_time_ms = static_cast<uint32_t>(duration.count());
    
    std::cout << "[RealGGUFBackend::RunInference] Generated " << result.tokens_generated 
              << " tokens in " << result.completion_time_ms << "ms" << std::endl;
    
    return result;
}

void RealGGUFBackend::RunInferenceAsync(const InferenceRequest& request, 
                                       InferenceCallback callback) {
    // For now, just run synchronously and call callback
    InferenceResult result = RunInference(request);
    callback(result);
}

} // namespace Inference
} // namespace RawrXD
