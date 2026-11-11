//============================================================================
// speculative_execution_integration.hpp
//
// VAL-032: Integration Layer
//
// Connects:
//   - SpeculativeDecoder (high-level API)
//   - TreeAttentionDispatcher (kernel selection)
//   - SpeculativeExecutionEngine (execution + telemetry)
//   - B008 TensorResidencyPlanner (memory fabric)
//============================================================================

#pragma once
#include "../kernels/tree_attention_dispatch.hpp"
#include "../memory/RawrXD_SpeculativeScheduler.hpp"
#include "../memory/tensor_residency_planner.hpp"
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Inference {

//============================================================================
// Speculative Configuration
//============================================================================
struct SpeculativeConfig {
    // Draft model settings
    uint32_t draft_tokens = 4;              // Tokens to speculate ahead
    float acceptance_threshold = 0.6f;      // Prob threshold for acceptance
    bool enable_tree_attention = true;      // Use VAL-032 kernel
    
    // Performance tuning
    uint32_t max_batch_size = 16;           // 4x4 tree structure
    bool enable_kernel_telemetry = true;    // Cycle counting
    bool enable_residency_hooks = true;     // B008 integration
    
    // Fallback behavior
    bool fallback_to_scalar = true;         // Use scalar if AVX-512 unavailable
    uint32_t max_rollback_depth = 5;        // Max tokens to roll back
};

//============================================================================
// Draft Model Interface
//============================================================================
class IDraftModel {
public:
    virtual ~IDraftModel() = default;
    
    // Generate next draft token given context
    virtual uint32_t Predict(const std::vector<uint32_t>& context) = 0;
    
    // Get probability distribution for token
    virtual float GetProbability(uint32_t token) = 0;
    
    // Batch prediction for tree generation
    virtual std::vector<uint32_t> PredictBatch(
        const std::vector<uint32_t>& context,
        uint32_t count
    ) = 0;
    
    // Model metadata
    virtual std::vector<std::string> GetWeightIds() const = 0;
    virtual bool IsReady() const = 0;
};

//============================================================================
// Target Model Interface
//============================================================================
class ITargetModel {
public:
    virtual ~ITargetModel() = default;
    
    // Verify draft tokens (main forward pass)
    virtual bool VerifyBatch(
        const std::vector<uint32_t>& draft_tokens,
        std::vector<float>& out_logits
    ) = 0;
    
    // Generate single token (fallback)
    virtual uint32_t Generate(const std::vector<uint32_t>& context) = 0;
    
    // Model metadata
    virtual bool IsReady() const = 0;
};

//============================================================================
// Speculative Execution Result
//============================================================================
struct SpeculativeResult {
    std::vector<uint32_t> accepted_tokens;
    uint32_t rollback_count = 0;
    bool used_speculation = false;
    float acceptance_rate = 0.0f;
    
    // Timing (microseconds)
    uint64_t draft_time_us = 0;
    uint64_t verify_time_us = 0;
    uint64_t rollback_time_us = 0;
};

//============================================================================
// Integrated Speculative Decoder
//============================================================================
class SpeculativeExecutionPipeline {
public:
    SpeculativeExecutionPipeline(
        std::unique_ptr<IDraftModel> draft_model,
        std::unique_ptr<ITargetModel> target_model,
        const SpeculativeConfig& config = {}
    );
    
    ~SpeculativeExecutionPipeline();
    
    // Disable copy/move
    SpeculativeExecutionPipeline(const SpeculativeExecutionPipeline&) = delete;
    SpeculativeExecutionPipeline& operator=(const SpeculativeExecutionPipeline&) = delete;
    
    // Initialize (must call before use)
    bool Initialize();
    
    // Core API: Generate tokens with speculation
    SpeculativeResult Generate(
        const std::vector<uint32_t>& prompt,
        uint32_t max_new_tokens
    );
    
    // Single step (for streaming)
    uint32_t Step(uint32_t last_token);
    
    // Residency fabric integration
    void SetResidencyPlanner(Memory::TensorResidencyPlanner* planner);
    Memory::TensorResidencyPlanner* GetResidencyPlanner() const;
    
    // Telemetry
    const Kernels::SpeculativeTelemetry& GetTelemetry() const;
    void ResetTelemetry();
    
    // Configuration
    const SpeculativeConfig& GetConfig() const { return config_; }
    const Kernels::TreeAttentionKernel& GetKernel() const;
    
    // Status
    bool IsReady() const;
    const char* GetKernelName() const;
    
private:
    SpeculativeConfig config_;
    std::unique_ptr<IDraftModel> draft_model_;
    std::unique_ptr<ITargetModel> target_model_;
    
    // Kernel execution engine
    std::unique_ptr<Kernels::SpeculativeExecutionEngine> execution_engine_;
    
    // B008 residency fabric
    Memory::TensorResidencyPlanner* residency_planner_ = nullptr;
    
    // Internal state
    std::vector<uint32_t> current_context_;
    bool initialized_ = false;
    
    // Helper methods
    std::vector<uint32_t> GenerateDraftTokens(uint32_t count);
    Kernels::VerificationResult VerifyDraftTokens(
        const std::vector<uint32_t>& draft_tokens
    );
    void RollbackRejectedTokens(uint32_t rejection_mask);
    void CommitAcceptedTokens(const std::vector<uint32_t>& tokens);
};

//============================================================================
// Factory Functions
//============================================================================

// Create with N-gram draft model (no training required)
std::unique_ptr<SpeculativeExecutionPipeline> CreateNGramSpeculativePipeline(
    std::unique_ptr<ITargetModel> target_model,
    size_t ngram_size = 3,
    const SpeculativeConfig& config = {}
);

// Create with Medusa draft model (requires trained heads)
std::unique_ptr<SpeculativeExecutionPipeline> CreateMedusaSpeculativePipeline(
    std::unique_ptr<ITargetModel> target_model,
    const std::string& medusa_model_path,
    const SpeculativeConfig& config = {}
);

//============================================================================
// Telemetry Export
//============================================================================

// Export telemetry to JSON for analysis
std::string ExportTelemetryToJSON(
    const Kernels::SpeculativeTelemetry& telemetry
);

// Print telemetry summary
void PrintTelemetrySummary(
    const Kernels::SpeculativeTelemetry& telemetry,
    FILE* output = stdout
);

} // namespace Inference
} // namespace RawrXD
