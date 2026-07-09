/**
 * @file execution_gateway_impl.h
 * @brief RawrXD Execution Gateway - Real Kernel Integration
 *
 * Bridges CLI commands to actual kernel execution.
 * No simulation - only real execution paths.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include "execution_contracts.h"
#include "../kernels/kernel_registry.h"
#include "../kernels/fused_quant_gemm.h"
#include "../kernels/compression_codec.h"

#include <memory>
#include <thread>
#include <atomic>

namespace rawrxd {
namespace execution {

// Forward declarations
class KernelRegistryGateway;
class InferencePipeline;
class TelemetryCollector;

// ============================================================================
// Real Execution Gateway
// ============================================================================

class RealExecutionGateway : public ExecutionGateway {
public:
    RealExecutionGateway();
    ~RealExecutionGateway();
    
    // Initialize with kernel registry
    bool Initialize();
    void Shutdown();
    
    // ExecutionGateway interface
    ExecutionResult Execute(const ExecutionRequest& request) override;
    bool IsReady() const override;
    std::vector<std::string> GetAvailableCommands() const override;
    std::vector<std::string> GetAvailableKernels() const override;
    
    // Direct kernel access (for advanced use)
    kernels::KernelRegistry& GetKernelRegistry();
    
private:
    // Command handlers
    ExecutionResult HandleRunInference(const ExecutionRequest& req);
    ExecutionResult HandleKernelValidate(const ExecutionRequest& req);
    ExecutionResult HandleKernelProfile(const ExecutionRequest& req);
    ExecutionResult HandleKernelPolicy(const ExecutionRequest& req);
    ExecutionResult HandleBenchmark(const ExecutionRequest& req);
    ExecutionResult HandleInspectModel(const ExecutionRequest& req);
    ExecutionResult HandleTokenizerValidate(const ExecutionRequest& req);  // Step C2
    ExecutionResult HandleTestSuite(const ExecutionRequest& req);
    
    // Real kernel operations
    ExecutionResult ExecuteRealGEMMValidation(const ExecutionRequest& req);
    ExecutionResult ExecuteRealRMSNormValidation(const ExecutionRequest& req);
    ExecutionResult ExecuteRealRoPEValidation(const ExecutionRequest& req);
    ExecutionResult ExecuteRealSoftmaxValidation(const ExecutionRequest& req);
    
    // Real profiling
    ExecutionResult ExecuteRealGEMMProfile(const ExecutionRequest& req);
    
    // Real inference pipeline
    ExecutionResult ExecuteRealInference(const ExecutionRequest& req);
    
    // Telemetry
    void CollectTelemetry(ExecutionTelemetry& telemetry);
    
    // State
    bool initialized_ = false;
    std::atomic<bool> shutting_down_{false};
    
    // Subsystems
    std::unique_ptr<TelemetryCollector> telemetry_collector_;
    std::unique_ptr<InferencePipeline> inference_pipeline_;
};

// ============================================================================
// Telemetry Collector (Real Measurements)
// ============================================================================

class TelemetryCollector {
public:
    struct Measurement {
        std::string name;
        double value_ms;
        std::chrono::steady_clock::time_point timestamp;
    };
    
    void BeginSession(const std::string& request_id);
    void EndSession();
    
    void RecordKernelTime(double ms);
    void RecordIOTime(double ms);
    void RecordTokenGenerated();
    void RecordMemoryPeak(uint64_t bytes);
    
    ExecutionTelemetry GetTelemetry() const;
    void Reset();
    
private:
    std::string current_request_id_;
    std::chrono::steady_clock::time_point session_start_;
    
    double total_kernel_ms_ = 0.0;
    double total_io_ms_ = 0.0;
    uint32_t tokens_generated_ = 0;
    uint64_t peak_memory_bytes_ = 0;
};

// ============================================================================
// Inference Pipeline (Real Execution)
// ============================================================================

class InferencePipeline {
public:
    struct PipelineConfig {
        uint32_t max_seq_length = 4096;
        uint32_t batch_size = 1;
        bool use_kv_cache = true;
        std::string preferred_kernel = "auto"; // "auto", "reference", "avx2", "avx512"
    };
    
    bool Initialize(const PipelineConfig& config);
    void Shutdown();
    
    // Execute full inference
    ExecutionResult Run(const ExecutionRequest& req);
    
    // Pipeline stages (exposed for profiling)
    bool Stage_LoadModel(const std::string& path);
    bool Stage_Tokenize(const std::string& prompt, std::vector<uint32_t>& tokens);
    bool Stage_BuildKVCache(uint32_t seq_length);
    bool Stage_Attention(const std::vector<uint32_t>& tokens);
    bool Stage_FFN();
    bool Stage_Sample(uint32_t& next_token);
    bool Stage_Detokenize(uint32_t token, std::string& text);
    
private:
    PipelineConfig config_;
    bool initialized_ = false;
    
    // Runtime state
    std::vector<float> kv_cache_k_;
    std::vector<float> kv_cache_v_;
    std::vector<uint32_t> generated_tokens_;
    
    // Kernel handles
    kernels::RmsNormFn rmsnorm_fn_;
    kernels::RopeFn rope_fn_;
    kernels::SoftmaxFn softmax_fn_;
    kernels::GemvFn gemv_fn_;
};

// ============================================================================
// Validation Utilities
// ============================================================================

class KernelValidator {
public:
    // Validate GEMM against reference
    static ValidationResult ValidateGEMM(
        kernels::GemvFn test_kernel,
        size_t rows, size_t cols,
        rawrxd::compression::CompressionType codec
    );
    
    // Validate RMSNorm against reference
    static ValidationResult ValidateRMSNorm(
        kernels::RmsNormFn test_kernel,
        size_t count
    );
    
    // Validate RoPE against reference
    static ValidationResult ValidateRoPE(
        kernels::RopeFn test_kernel,
        size_t head_dim, size_t num_heads
    );
    
    // Validate Softmax against reference
    static ValidationResult ValidateSoftmax(
        kernels::SoftmaxFn test_kernel,
        size_t count
    );
    
private:
    // Reference implementations (for validation)
    static void ReferenceGEMV(
        const float* weights, const float* input,
        float* output, size_t rows, size_t cols
    );
    
    static void ReferenceRMSNorm(
        float* data, size_t count, float epsilon, float scale
    );
    
    static void ReferenceRoPE(
        float* q, float* k, size_t head_dim, size_t num_heads,
        size_t seq_pos, float theta
    );
    
    static void ReferenceSoftmax(float* data, size_t count);
    
    // Comparison metrics
    static double ComputeCosineSimilarity(
        const float* a, const float* b, size_t count
    );
    
    static double ComputeRMSE(
        const float* a, const float* b, size_t count
    );
};

// ============================================================================
// Gateway Factory
// ============================================================================

class ExecutionGatewayFactory {
public:
    // Create the real execution gateway
    static std::unique_ptr<ExecutionGateway> CreateRealGateway();
    
    // Create a mock gateway for testing
    static std::unique_ptr<ExecutionGateway> CreateMockGateway();
};

} // namespace execution
} // namespace rawrxd
