// ============================================================================
// RawrXD Phase 7D: InferenceEngine Checkpoint Wrapper Implementation
// ============================================================================

#include "InferenceEngine_checkpoint_wrapper.hpp"
#include <cstdio>
#include <chrono>

namespace RawrXD {
namespace Integration {

// ============================================================================
// CheckpointedInferenceEngine Implementation
// ============================================================================

CheckpointedInferenceEngine::CheckpointedInferenceEngine() = default;
CheckpointedInferenceEngine::~CheckpointedInferenceEngine() = default;

bool CheckpointedInferenceEngine::Initialize(const std::string& model_path,
                                              const std::string& model_version,
                                              const std::string& fabric_policy) {
    // Create underlying engine
    Inference::EngineConfig config;
    config.modelPath = model_path;
    config.useGPU = false;  // CPU-only for determinism
    config.numThreads = 1;  // Single-threaded for determinism
    
    engine_ = Inference::InferenceEngine::Create(config);
    if (!engine_) {
        fprintf(stderr, "[CheckpointedEngine] Failed to create inference engine\n");
        return false;
    }
    
    // Load model
    if (!engine_->LoadModel(model_path)) {
        fprintf(stderr, "[CheckpointedEngine] Failed to load model: %s\n", model_path.c_str());
        return false;
    }
    
    // Initialize checkpoint context
    checkpoint_ctx_ = std::make_unique<GGUFCheckpointContext>();
    if (!GGUFCheckpoint_Init(checkpoint_ctx_.get(), model_path.c_str(), 
                              model_version.c_str(), fabric_policy.c_str())) {
        fprintf(stderr, "[CheckpointedEngine] Failed to initialize checkpoint context\n");
        return false;
    }
    
    initialized_ = true;
    printf("[CheckpointedEngine] Initialized with model: %s\n", model_path.c_str());
    printf("[CheckpointedEngine] Model hash: 0x%016llX\n", checkpoint_ctx_->model_hash);
    
    return true;
}

Inference::GenerationResult CheckpointedInferenceEngine::Generate(
    const std::string& prompt,
    const Inference::GenerationParams& params) {
    
    return GenerateInternal(prompt, params, nullptr);
}

Inference::GenerationResult CheckpointedInferenceEngine::GenerateStreaming(
    const std::string& prompt,
    const Inference::GenerationParams& params,
    std::function<bool(const Inference::TokenInfo&)> callback) {
    
    return GenerateInternal(prompt, params, callback);
}

Inference::GenerationResult CheckpointedInferenceEngine::GenerateInternal(
    const std::string& prompt,
    const Inference::GenerationParams& params,
    std::function<bool(const Inference::TokenInfo&)> callback) {
    
    if (!initialized_ || !engine_ || !checkpoint_ctx_) {
        Inference::GenerationResult result;
        result.success = false;
        result.errorMessage = "Engine not initialized";
        return result;
    }
    
    // Hash the prompt for verification
    uint64_t prompt_hash = 0;
    for (char c : prompt) {
        prompt_hash = prompt_hash * 31 + static_cast<uint64_t>(c);
    }
    checkpoint_ctx_->prompt_hash = prompt_hash;
    
    printf("[CheckpointedEngine] Generating with prompt hash: 0x%016llX\n", prompt_hash);
    printf("[CheckpointedEngine] Max tokens: %d, Seed: %d\n", params.maxTokens, params.seed);
    
    // Track tokens for checkpointing
    std::vector<int32_t> generated_tokens;
    uint32_t token_pos = 0;
    
    // Wrap callback to capture tokens
    auto wrapped_callback = [&](const Inference::TokenInfo& token_info) -> bool {
        generated_tokens.push_back(token_info.tokenId);
        
        // Checkpoint sampler state
        #ifdef RAWRXD_ENABLE_CHECKPOINTS
        if (checkpoint_ctx_->checkpoint_mgr) {
            // Note: We don't have access to logits here, so we checkpoint token only
            // Full checkpointing would require modifying the engine internals
            RAWRXD_CHECKPOINT_SAMPLER(checkpoint_ctx_.get(), 
                                     token_info.tokenId,
                                     params.temperature,
                                     params.topP,
                                     params.topK,
                                     token_pos++);
        }
        #endif
        
        if (callback) {
            return callback(token_info);
        }
        return true;
    };
    
    // Run generation
    auto start_time = std::chrono::high_resolution_clock::now();
    
    Inference::GenerationResult result;
    if (callback) {
        result = engine_->GenerateStreaming(prompt, params, wrapped_callback);
    } else {
        result = engine_->Generate(prompt, params);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // Export proof
    if (result.success) {
        std::string proof_path = "inference_" + std::to_string(prompt_hash) + ".rawrproof";
        if (ExportProof(proof_path)) {
            printf("[CheckpointedEngine] Proof exported: %s\n", proof_path.c_str());
        }
        
        // Print statistics
        uint32_t tensors = 0;
        uint64_t bytes = 0;
        double hash_time = 0.0;
        GetCheckpointStats(&tensors, &bytes, &hash_time);
        
        printf("[CheckpointedEngine] Generation complete:\n");
        printf("  Tokens generated: %zu\n", generated_tokens.size());
        printf("  Time: %lld ms\n", duration.count());
        printf("  TPS: %.2f\n", generated_tokens.size() * 1000.0 / duration.count());
        printf("  Checkpoints: %u tensors, %llu bytes\n", tensors, bytes);
    }
    
    return result;
}

bool CheckpointedInferenceEngine::ExportProof(const std::string& filepath) {
    if (!checkpoint_ctx_) {
        return false;
    }
    
    return GGUFCheckpoint_ExportProof(checkpoint_ctx_.get(), filepath.c_str());
}

void CheckpointedInferenceEngine::GetCheckpointStats(uint32_t* out_tensors,
                                                      uint64_t* out_bytes,
                                                      double* out_time_ms) const {
    if (checkpoint_ctx_) {
        GGUFCheckpoint_GetStats(checkpoint_ctx_.get(), out_tensors, out_bytes, out_time_ms);
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

bool GenerateWithProof(const std::string& model_path,
                       const std::string& prompt,
                       const Inference::GenerationParams& params,
                       const std::string& proof_output_path,
                       std::string* out_generated_text) {
    
    CheckpointedInferenceEngine engine;
    
    if (!engine.Initialize(model_path)) {
        fprintf(stderr, "Failed to initialize engine\n");
        return false;
    }
    
    auto result = engine.Generate(prompt, params);
    
    if (!result.success) {
        fprintf(stderr, "Generation failed: %s\n", result.errorMessage.c_str());
        return false;
    }
    
    if (out_generated_text) {
        *out_generated_text = result.text;
    }
    
    // Export to specified path
    return engine.ExportProof(proof_output_path);
}

bool GenerateBatchWithProofs(const std::string& model_path,
                              const std::vector<std::string>& prompts,
                              const Inference::GenerationParams& params,
                              const std::string& proof_output_dir,
                              std::vector<std::string>* out_generated_texts) {
    
    CheckpointedInferenceEngine engine;
    
    if (!engine.Initialize(model_path)) {
        return false;
    }
    
    out_generated_texts->clear();
    out_generated_texts->reserve(prompts.size());
    
    for (size_t i = 0; i < prompts.size(); ++i) {
        auto result = engine.Generate(prompts[i], params);
        
        if (result.success) {
            out_generated_texts->push_back(result.text);
            
            std::string proof_path = proof_output_dir + "/proof_" + std::to_string(i) + ".rawrproof";
            engine.ExportProof(proof_path);
        } else {
            out_generated_texts->push_back("");
        }
    }
    
    return true;
}

} // namespace Integration
} // namespace RawrXD
