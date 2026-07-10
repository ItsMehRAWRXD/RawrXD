//==============================================================================
// SovereignGraphRunner_v2.hpp
// Backend-Agnostic Transformer Orchestrator
//
// Uses KernelRegistry for all kernel dispatch.
// No architecture-specific kernel calls - completely backend-agnostic.
//
// Date: July 10, 2026
// Phase: 7C.1 - Registry Integration
//==============================================================================

#pragma once

#include "KernelRegistry.hpp"
#include "SovereignKernelTypes.hpp"
#include <memory>
#include <vector>
#include <string>

namespace sovereign {

//==============================================================================
// Transformer Configuration
//==============================================================================
struct TransformerConfig {
    uint32_t hiddenSize{4096};
    uint32_t numHeads{32};
    uint32_t headDim{128};
    uint32_t intermediateSize{11008};
    uint32_t maxSeqLen{4096};
    float rmsNormEps{1e-6f};
    float ropeTheta{10000.0f};
};

//==============================================================================
// Execution Context
// Unified context for all kernel executions
//==============================================================================
struct ExecutionContext {
    // Input/output buffers
    void* input{nullptr};
    void* output{nullptr};
    size_t inputSize{0};
    size_t outputSize{0};
    
    // Tensor views (for multi-dimensional operations)
    TensorDesc inputTensor;
    TensorDesc outputTensor;
    TensorDesc weightTensor;
    TensorDesc biasTensor;
    
    // Parameters
    KernelParams params;
    MatMulParams matmulParams;
    AttentionParams attentionParams;
    
    // Position info
    uint32_t position{0};
    uint32_t seqLen{0};
    
    // Cache pointers
    void* kCache{nullptr};
    void* vCache{nullptr};
    
    // RoPE tables
    const float* ropeSin{nullptr};
    const float* ropeCos{nullptr};
};

//==============================================================================
// Validation Mode
//==============================================================================
enum class ValidationMode {
    NONE,           // Normal execution
    REFERENCE,      // Always use reference backend
    COMPARE,        // Execute all backends and compare
    BENCHMARK       // Run performance comparison
};

//==============================================================================
// Execution Result
//==============================================================================
struct GraphExecutionResult {
    bool success{false};
    uint32_t outputToken{0};
    uint64_t totalTimeUs{0};
    std::string backendUsed;
    ExecutionStats stats;
    
    // Validation results (when in COMPARE mode)
    struct ValidationEntry {
        std::string backendName;
        double maxError;
        double rmsError;
        bool passed;
    };
    std::vector<ValidationEntry> validationResults;
};

//==============================================================================
// Sovereign Graph Runner v2
//
// Completely backend-agnostic transformer orchestrator.
// All kernel dispatch goes through KernelRegistry.
//==============================================================================
class SovereignGraphRunner {
public:
    SovereignGraphRunner();
    ~SovereignGraphRunner();
    
    //======================================================================
    // Initialization
    //======================================================================
    bool Initialize(const TransformerConfig& config);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    //======================================================================
    // Core Execution
    //======================================================================
    
    // Full forward pass: token -> next_token
    GraphExecutionResult Forward(
        int32_t inputToken,
        uint32_t position,
        ValidationMode validation = ValidationMode::NONE
    );
    
    // Multi-token generation
    std::vector<GraphExecutionResult> Generate(
        int32_t startToken,
        uint32_t maxNewTokens,
        ValidationMode validation = ValidationMode::NONE
    );
    
    //======================================================================
    // Layer-by-Layer (for debugging/profiling)
    //======================================================================
    GraphExecutionResult RunEmbedding(int32_t tokenId);
    GraphExecutionResult RunPreNorm();
    GraphExecutionResult RunQKVProjection();
    GraphExecutionResult RunRoPE(uint32_t position);
    GraphExecutionResult RunSelfAttention();
    GraphExecutionResult RunAttentionOutput();
    GraphExecutionResult RunPostAttentionResidual();
    GraphExecutionResult RunFFN();
    GraphExecutionResult RunPostFFNResidual();
    GraphExecutionResult RunFinalNorm();
    GraphExecutionResult RunLMHead();
    
    //======================================================================
    // Cache Management
    //======================================================================
    void ClearKVCache();
    void ResizeKVCache(uint32_t newMaxSeqLen);
    
    //======================================================================
    // Validation & Benchmarking
    //======================================================================
    void SetValidationMode(ValidationMode mode) { validationMode_ = mode; }
    ValidationMode GetValidationMode() const { return validationMode_; }
    
    // Run full validation suite
    bool RunValidationSuite();
    
    // Run benchmark suite
    void RunBenchmarkSuite();
    
    // Get last execution stats
    const ExecutionStats& GetLastStats() const { return lastStats_; }
    
    //======================================================================
    // Backend Selection
    //======================================================================
    void SetDispatchPolicy(SelectionPolicy policy);
    SelectionPolicy GetDispatchPolicy() const;
    
    void ForceBackend(const std::string& backendName);
    void AutoSelectBackend();

private:
    bool initialized_{false};
    TransformerConfig config_;
    ValidationMode validationMode_{ValidationMode::NONE};
    ExecutionStats lastStats_;
    
    // Execution context (reused across calls)
    ExecutionContext ctx_;
    
    // Buffers
    std::vector<uint8_t> activationBuffer_;
    std::vector<uint8_t> kvCacheBuffer_;
    std::vector<float> ropeSin_;
    std::vector<float> ropeCos_;
    
    //======================================================================
    // Internal Helpers
    //======================================================================
    
    // Unified kernel dispatch
    GraphExecutionResult DispatchKernel(
        KernelId id,
        ExecutionContext& ctx
    );
    
    // Validation dispatch (runs multiple backends)
    GraphExecutionResult DispatchWithValidation(
        KernelId id,
        ExecutionContext& ctx
    );
    
    // Benchmark dispatch
    GraphExecutionResult DispatchWithBenchmark(
        KernelId id,
        ExecutionContext& ctx
    );
    
    // Buffer management
    bool AllocateBuffers();
    void FreeBuffers();
    
    // RoPE cache
    bool InitializeRoPECache();
    
    // Context setup helpers
    void SetupMatMulContext(ExecutionContext& ctx,
                           const TensorDesc& A,
                           const TensorDesc& B,
                           TensorDesc& C);
    void SetupAttentionContext(ExecutionContext& ctx,
                              const TensorDesc& Q,
                              const TensorDesc& K,
                              const TensorDesc& V,
                              TensorDesc& output,
                              uint32_t seqLen);
    void SetupNormContext(ExecutionContext& ctx,
                         const TensorDesc& input,
                         const TensorDesc& weight,
                         TensorDesc& output);
};

} // namespace sovereign
