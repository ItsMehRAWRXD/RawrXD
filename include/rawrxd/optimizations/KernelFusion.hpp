#pragma once

#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace rawrxd {
namespace optimizations {

// Fusion pattern types
enum class FusionPattern {
    LINEAR_GELU,           // Linear + GELU activation
    LINEAR_SILU,           // Linear + SiLU activation
    QKV_PROJECTION,        // Q, K, V projections fused
    ATTENTION_QK,          // Q @ K^T fused
    ATTENTION_SOFTMAX_V,   // Softmax + Attention @ V fused
    LAYERNORM_LINEAR,      // LayerNorm + Linear fused
    RESIDUAL_LAYERNORM,    // Residual + LayerNorm fused
    FFN_UP_GATE,           // FFN up-projection + gate fused
    ROPE_QK,               // RoPE + QK projection fused
    RMSNORM,               // RMSNorm fused kernel
    CUSTOM                 // User-defined fusion
};

// Fused kernel configuration
struct FusionConfig {
    FusionPattern pattern;
    bool useTensorCores = true;
    bool useWarpSpecialization = true;
    int blockSize = 256;
    int vectorWidth = 4;
    bool asyncExecution = false;
    std::string customKernelName;
};

// Fused operation base class
class FusedOperation {
public:
    virtual ~FusedOperation() = default;
    
    // Initialize the fused operation
    virtual bool Initialize(const FusionConfig& config) = 0;
    
    // Execute fused operation
    virtual bool Execute(const std::vector<float*>& inputs, 
                        float* output,
                        const std::vector<int>& inputSizes,
                        int outputSize) = 0;
    
    // Get pattern type
    virtual FusionPattern GetPattern() const = 0;
    
    // Estimate performance improvement
    virtual float GetSpeedupEstimate() const = 0;
};

// Linear + Activation fusion
class LinearGeluFusion : public FusedOperation {
public:
    LinearGeluFusion();
    ~LinearGeluFusion() override;
    
    bool Initialize(const FusionConfig& config) override;
    bool Execute(const std::vector<float*>& inputs,
                 float* output,
                 const std::vector<int>& inputSizes,
                 int outputSize) override;
    FusionPattern GetPattern() const override { return FusionPattern::LINEAR_GELU; }
    float GetSpeedupEstimate() const override { return 1.3f; }

private:
    FusionConfig config_;
    bool initialized_ = false;
    
    // GELU approximation coefficients
    static constexpr float GELU_COEF_0 = 0.044715f;
    static constexpr float GELU_COEF_1 = 0.7978845608f;  // sqrt(2/pi)
    
    void ExecuteCPU(const float* input, const float* weight, const float* bias,
                    float* output, int batchSize, int inFeatures, int outFeatures);
    void ExecuteGPU(const float* input, const float* weight, const float* bias,
                    float* output, int batchSize, int inFeatures, int outFeatures);
};

// QKV projection fusion
class QKVProjectionFusion : public FusedOperation {
public:
    QKVProjectionFusion();
    ~QKVProjectionFusion() override;
    
    bool Initialize(const FusionConfig& config) override;
    bool Execute(const std::vector<float*>& inputs,
                 float* output,
                 const std::vector<int>& inputSizes,
                 int outputSize) override;
    FusionPattern GetPattern() const override { return FusionPattern::QKV_PROJECTION; }
    float GetSpeedupEstimate() const override { return 1.5f; }

private:
    FusionConfig config_;
    bool initialized_ = false;
    
    void ExecuteCPU(const float* input, const float* wq, const float* wk, const float* wv,
                    float* q, float* k, float* v,
                    int batchSize, int seqLen, int hiddenSize, int numHeads, int headDim);
};

// Attention QK + Softmax + V fusion (Flash Attention style)
class AttentionSoftmaxVFusion : public FusedOperation {
public:
    AttentionSoftmaxVFusion();
    ~AttentionSoftmaxVFusion() override;
    
    bool Initialize(const FusionConfig& config) override;
    bool Execute(const std::vector<float*>& inputs,
                 float* output,
                 const std::vector<int>& inputSizes,
                 int outputSize) override;
    FusionPattern GetPattern() const override { return FusionPattern::ATTENTION_SOFTMAX_V; }
    float GetSpeedupEstimate() const override { return 2.0f; }

private:
    FusionConfig config_;
    bool initialized_ = false;
    
    struct SoftmaxStats {
        float maxVal;
        float sumExp;
    };
    
    void ExecuteCPU(const float* q, const float* k, const float* v,
                    float* output, float* softmaxLse,
                    int batchSize, int seqLen, int numHeads, int headDim);
};

// Residual + LayerNorm fusion
class ResidualLayerNormFusion : public FusedOperation {
public:
    ResidualLayerNormFusion();
    ~ResidualLayerNormFusion() override;
    
    bool Initialize(const FusionConfig& config) override;
    bool Execute(const std::vector<float*>& inputs,
                 float* output,
                 const std::vector<int>& inputSizes,
                 int outputSize) override;
    FusionPattern GetPattern() const override { return FusionPattern::RESIDUAL_LAYERNORM; }
    float GetSpeedupEstimate() const override { return 1.2f; }

private:
    FusionConfig config_;
    bool initialized_ = false;
    float epsilon_ = 1e-5f;
    
    void ExecuteCPU(const float* residual, const float* x,
                    const float* gamma, const float* beta,
                    float* output, float* mean, float* rstd,
                    int batchSize, int hiddenSize);
};

// FFN Up + Gate fusion (for SwiGLU)
class FFNUpGateFusion : public FusedOperation {
public:
    FFNUpGateFusion();
    ~FFNUpGateFusion() override;
    
    bool Initialize(const FusionConfig& config) override;
    bool Execute(const std::vector<float*>& inputs,
                 float* output,
                 const std::vector<int>& inputSizes,
                 int outputSize) override;
    FusionPattern GetPattern() const override { return FusionPattern::FFN_UP_GATE; }
    float GetSpeedupEstimate() const override { return 1.4f; }

private:
    FusionConfig config_;
    bool initialized_ = false;
    
    void ExecuteCPU(const float* x, const float* w_up, const float* w_gate,
                    float* output,
                    int batchSize, int hiddenSize, int intermediateSize);
};

// RMSNorm fusion
class RMSNormFusion : public FusedOperation {
public:
    RMSNormFusion();
    ~RMSNormFusion() override;
    
    bool Initialize(const FusionConfig& config) override;
    bool Execute(const std::vector<float*>& inputs,
                 float* output,
                 const std::vector<int>& inputSizes,
                 int outputSize) override;
    FusionPattern GetPattern() const override { return FusionPattern::RMSNORM; }
    float GetSpeedupEstimate() const override { return 1.25f; }

private:
    FusionConfig config_;
    bool initialized_ = false;
    float epsilon_ = 1e-6f;
    
    void ExecuteCPU(const float* x, const float* weight,
                    float* output, float* rms,
                    int batchSize, int hiddenSize);
};

// Kernel fusion registry
class FusionRegistry {
public:
    static FusionRegistry& GetInstance();
    
    // Register a fusion pattern
    void RegisterPattern(FusionPattern pattern, 
                         std::function<std::unique_ptr<FusedOperation>()> factory);
    
    // Create fused operation
    std::unique_ptr<FusedOperation> CreateOperation(FusionPattern pattern);
    
    // Check if pattern is available
    bool IsPatternAvailable(FusionPattern pattern) const;
    
    // Get all available patterns
    std::vector<FusionPattern> GetAvailablePatterns() const;
    
    // Auto-detect fusion opportunities in a graph
    std::vector<FusionPattern> DetectFusionOpportunities(
        const std::vector<std::string>& operationSequence) const;

private:
    FusionRegistry() = default;
    ~FusionRegistry() = default;
    FusionRegistry(const FusionRegistry&) = delete;
    FusionRegistry& operator=(const FusionRegistry&) = delete;
    
    std::unordered_map<FusionPattern, 
                       std::function<std::unique_ptr<FusedOperation>()>> factories_;
    mutable std::mutex mutex_;
};

// Fusion pass for model optimization
class FusionPass {
public:
    // Analyze model and apply fusion
    static bool ApplyFusion(class ModelGraph& graph);
    
    // Get fusion statistics
    struct Stats {
        int patternsDetected = 0;
        int patternsApplied = 0;
        float estimatedSpeedup = 1.0f;
        std::vector<FusionPattern> appliedPatterns;
    };
    static Stats GetStats();

private:
    static Stats stats_;
    
    static bool TryFuseLinearActivation(ModelGraph& graph, int nodeIdx);
    static bool TryFuseQKVProjection(ModelGraph& graph, int nodeIdx);
    static bool TryFuseAttention(ModelGraph& graph, int nodeIdx);
    static bool TryFuseResidualLayerNorm(ModelGraph& graph, int nodeIdx);
    static bool TryFuseFFNUpGate(ModelGraph& graph, int nodeIdx);
};

// Performance benchmark for fused kernels
class FusionBenchmark {
public:
    struct Result {
        FusionPattern pattern;
        float baselineTimeMs;
        float fusedTimeMs;
        float speedup;
        float memoryBandwidthGBps;
        float computeUtilization;
    };
    
    // Benchmark a specific fusion pattern
    static Result BenchmarkPattern(FusionPattern pattern, 
                                   const std::vector<int>& inputSizes);
    
    // Benchmark all available patterns
    static std::vector<Result> BenchmarkAll();
    
    // Generate report
    static std::string GenerateReport(const std::vector<Result>& results);
};

} // namespace optimizations
} // namespace rawrxd
