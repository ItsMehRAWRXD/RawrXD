// ============================================================================
// RawrXD Phase 7D: InferenceEngine Checkpoint Wrapper
// ============================================================================
// Wraps the existing InferenceEngine to add checkpoint hooks
// This is a non-invasive integration that doesn't require modifying core files
// ============================================================================

#pragma once

#include "../inference/InferenceEngine.h"
#include "gguf_checkpoint_hooks.hpp"
#include <memory>
#include <string>

namespace RawrXD {
namespace Integration {

// ============================================================================
// Checkpoint-Enabled Inference Engine
// Wraps the standard InferenceEngine and adds cryptographic verification
// ============================================================================

class CheckpointedInferenceEngine {
public:
    CheckpointedInferenceEngine();
    ~CheckpointedInferenceEngine();

    // Initialize with model path and checkpoint configuration
    bool Initialize(const std::string& model_path, 
                    const std::string& model_version = "unknown",
                    const std::string& fabric_policy = "default");

    // Generate with checkpoint capture
    Inference::GenerationResult Generate(
        const std::string& prompt,
        const Inference::GenerationParams& params);

    // Generate with streaming and checkpoints
    Inference::GenerationResult GenerateStreaming(
        const std::string& prompt,
        const Inference::GenerationParams& params,
        std::function<bool(const Inference::TokenInfo&)> callback);

    // Export proof to file
    bool ExportProof(const std::string& filepath);

    // Get checkpoint statistics
    void GetCheckpointStats(uint32_t* out_tensors, 
                           uint64_t* out_bytes, 
                           double* out_time_ms) const;

    // Get underlying engine (for advanced use)
    Inference::InferenceEngine* GetEngine() { return engine_.get(); }

    // Check if initialized
    bool IsInitialized() const { return initialized_; }

private:
    std::unique_ptr<Inference::InferenceEngine> engine_;
    std::unique_ptr<GGUFCheckpointContext> checkpoint_ctx_;
    bool initialized_ = false;
    std::string last_proof_path_;

    // Internal generation with checkpointing
    Inference::GenerationResult GenerateInternal(
        const std::string& prompt,
        const Inference::GenerationParams& params,
        std::function<bool(const Inference::TokenInfo&)> callback);
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick generation with proof export
bool GenerateWithProof(const std::string& model_path,
                       const std::string& prompt,
                       const Inference::GenerationParams& params,
                       const std::string& proof_output_path,
                       std::string* out_generated_text);

// Batch generation with proofs
bool GenerateBatchWithProofs(const std::string& model_path,
                              const std::vector<std::string>& prompts,
                              const Inference::GenerationParams& params,
                              const std::string& proof_output_dir,
                              std::vector<std::string>* out_generated_texts);

} // namespace Integration
} // namespace RawrXD
