#pragma once

#include <vector>
#include <memory>
#include <cmath>

namespace rawrxd {
namespace optimizations {

// Flash Attention V2 configuration
struct FlashAttentionConfig {
    int blockSizeM = 128;    // Block size for Q (rows)
    int blockSizeN = 128;    // Block size for K (columns)
    int blockSizeK = 64;     // Block size for head dimension
    int numSplits = 1;       // Number of splits for parallelism
    bool causal = false;     // Causal masking
    float softmaxScale = 1.0f;
    float dropoutProbability = 0.0f;
    uint64_t dropoutSeed = 0;
    bool returnSoftmaxLse = false;  // Return log-sum-exp for backward
    bool useTiling = true;
    bool useSharedMemory = true;
    bool asyncCopy = true;
};

// Flash Attention V2 implementation
class FlashAttentionV2 {
public:
    FlashAttentionV2();
    ~FlashAttentionV2();

    // Initialize Flash Attention
    bool Initialize(const FlashAttentionConfig& config);
    
    // Forward pass
    bool Forward(const float* query, const float* key, const float* value,
                 float* output, float* softmaxLse,
                 int batchSize, int numHeads, int seqLenQ, int seqLenKV, int headDim);
    
    // Backward pass (for training)
    bool Backward(const float* query, const float* key, const float* value,
                  const float* output, const float* softmaxLse,
                  const float* gradOutput,
                  float* gradQuery, float* gradKey, float* gradValue,
                  int batchSize, int numHeads, int seqLenQ, int seqLenKV, int headDim);
    
    // Get configuration
    const FlashAttentionConfig& GetConfig() const { return config_; }
    
    // Get memory requirements
    size_t GetWorkspaceSize(int batchSize, int numHeads, int seqLenQ, int seqLenKV, int headDim) const;
    
    // Check if Flash Attention is available on this device
    static bool IsAvailable();
    
    // Get optimal configuration for given problem size
    static FlashAttentionConfig GetOptimalConfig(int seqLen, int headDim, int batchSize = 1);

private:
    FlashAttentionConfig config_;
    bool initialized_ = false;
    
    // Workspace memory
    std::vector<uint8_t> workspace_;
    
    // Internal methods
    void ComputeBlockSize(int seqLen, int headDim);
    
    // CPU implementation
    void ForwardCPU(const float* query, const float* key, const float* value,
                    float* output, float* softmaxLse,
                    int batchSize, int numHeads, int seqLenQ, int seqLenKV, int headDim);
    
    // Tiled forward pass
    void ForwardTiled(const float* query, const float* key, const float* value,
                      float* output, float* softmaxLse,
                      int batchSize, int numHeads, int seqLenQ, int seqLenKV, int headDim);
    
    // Single block computation
    struct BlockStats {
        float m;      // max
        float l;      // sum of exp
    };
    
    void ComputeAttentionBlock(const float* qBlock, const float* kBlock, const float* vBlock,
                               float* outBlock, BlockStats& stats,
                               int blockM, int blockN, int headDim, bool causal);
    
    // Online softmax update
    void OnlineSoftmaxUpdate(float& m, float& l, const float* scores, int len);
    
    // Rescale output block
    void RescaleOutput(float* outBlock, const BlockStats& oldStats, 
                       const BlockStats& newStats, int blockM, int headDim);
};

// Block-sparse Flash Attention for long sequences
class BlockSparseFlashAttention {
public:
    struct SparsePattern {
        std::vector<std::pair<int, int>> blocks;  // (row, col) blocks to compute
        float sparsityRatio = 0.0f;
    };
    
    BlockSparseFlashAttention();
    ~BlockSparseFlashAttention();
    
    bool Initialize(const FlashAttentionConfig& config);
    
    // Forward with sparse pattern
    bool Forward(const float* query, const float* key, const float* value,
                 const SparsePattern& pattern,
                 float* output,
                 int batchSize, int numHeads, int seqLen, int headDim);
    
    // Generate sparse pattern based on attention scores
    SparsePattern GeneratePattern(const float* query, const float* key,
                                  int batchSize, int numHeads, int seqLen, int headDim,
                                  float sparsityTarget = 0.9f);
    
    // Common patterns
    static SparsePattern LocalPattern(int seqLen, int blockSize, int localWindow);
    static SparsePattern StridedPattern(int seqLen, int blockSize, int stride);
    static SparsePattern DilatedPattern(int seqLen, int blockSize, int dilation);

private:
    FlashAttentionConfig config_;
    bool initialized_ = false;
};

// Memory-efficient attention for inference
class MemoryEfficientAttention {
public:
    MemoryEfficientAttention();
    ~MemoryEfficientAttention();
    
    bool Initialize(int maxSeqLen, int headDim);
    
    // Incremental attention for autoregressive generation
    bool IncrementalForward(const float* query, const float* key, const float* value,
                            float* output,
                            int batchSize, int numHeads, int seqLen, int headDim,
                            int step);
    
    // KV cache management
    void ResetCache();
    void UpdateKVCache(const float* key, const float* value,
                       int batchSize, int numHeads, int seqLen, int headDim);

private:
    int maxSeqLen_ = 0;
    int headDim_ = 0;
    bool initialized_ = false;
    
    // KV cache
    std::vector<float> kCache_;
    std::vector<float> vCache_;
    int cacheLen_ = 0;
};

// Flash Attention benchmark
class FlashAttentionBenchmark {
public:
    struct Result {
        int seqLen;
        int headDim;
        int batchSize;
        int numHeads;
        float standardTimeMs;
        float flashTimeMs;
        float speedup;
        float memoryStandardMB;
        float memoryFlashMB;
        float memoryReduction;
        float tflops;
    };
    
    // Benchmark specific configuration
    static Result Benchmark(int seqLen, int headDim, int batchSize = 1, int numHeads = 32);
    
    // Benchmark sweep over sequence lengths
    static std::vector<Result> BenchmarkSweep(
        const std::vector<int>& seqLengths,
        int headDim = 64,
        int batchSize = 1,
        int numHeads = 32);
    
    // Generate comparison report
    static std::string GenerateReport(const std::vector<Result>& results);
    
    // Find optimal configuration
    static FlashAttentionConfig FindOptimalConfig(int seqLen, int headDim);
};

// Attention kernel selector
class AttentionKernelSelector {
public:
    enum class KernelType {
        STANDARD,           // Standard attention
        FLASH_ATTENTION,    // Flash Attention V2
        MEMORY_EFFICIENT,   // Memory-efficient for inference
        BLOCK_SPARSE        // Block-sparse for long sequences
    };
    
    // Select best kernel for given problem
    static KernelType SelectKernel(int seqLen, int headDim, bool isTraining, 
                                    bool hasMask = false);
    
    // Get kernel name
    static std::string GetKernelName(KernelType type);
    
    // Estimate performance
    static float EstimateSpeedup(KernelType kernel, int seqLen, int headDim);
};

} // namespace optimizations
} // namespace rawrxd
