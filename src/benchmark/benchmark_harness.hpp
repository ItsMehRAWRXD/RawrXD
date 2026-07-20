/*===========================================================================
 * benchmark_harness.hpp
 * 
 * Fixed benchmark harness with Int64 arithmetic
 * 
 * Previous issue: Int32 overflow at 404494150400 bytes (> 2.1GB limit)
 * Fix: Use size_t (64-bit) for all memory calculations
 *===========================================================================*/

#pragma once

#include <cstdint>
#include <chrono>
#include <vector>
#include <string>
#include <cmath>

namespace RawrXD {
namespace Benchmark {

// Use 64-bit for all memory calculations to prevent overflow
using MemorySize = size_t;
using TokenCount = uint64_t;
using TimeNanos = uint64_t;

// Benchmark configuration
struct BenchmarkConfig {
    uint32_t warmupIterations = 3;
    uint32_t benchmarkIterations = 10;
    uint32_t minSequenceLength = 128;
    uint32_t maxSequenceLength = 8192;
    uint32_t sequenceStep = 128;
    
    // Model dimensions (for memory calculation)
    uint32_t batchSize = 1;
    uint32_t numLayers = 80;        // DeepSeek-V3.1
    uint32_t hiddenSize = 8192;      // Hidden dimension
    uint32_t numHeads = 128;         // Attention heads
    uint32_t headDim = 64;           // Head dimension
    uint32_t vocabSize = 129280;     // Vocabulary size
    uint32_t intermediateSize = 32768;  // FFN intermediate size
    
    // Memory layout
    bool useNHWC = true;            // Use NHWC layout for SIMD efficiency
    uint32_t alignment = 64;          // 64-byte alignment for AVX-512
};

// Memory requirements calculation (Int64 safe)
struct MemoryRequirements {
    MemorySize weightsSize = 0;      // Model weights
    MemorySize kvCacheSize = 0;      // KV cache
    MemorySize activationSize = 0;   // Activations
    MemorySize workspaceSize = 0;    // Temporary workspace
    MemorySize totalSize = 0;        // Total required
    
    // Calculate from config
    void Calculate(const BenchmarkConfig& config);
    
    // Format for display
    std::string Format() const;
};

// TPS measurement with statistical analysis
struct TPSResult {
    double meanTPS = 0.0;
    double stdDevTPS = 0.0;
    double minTPS = 0.0;
    double maxTPS = 0.0;
    double p99TPS = 0.0;
    
    std::vector<double> samples;
    
    void AddSample(double tps);
    void Finalize();
};

// Sequence length benchmark result
struct SequenceBenchmark {
    uint32_t sequenceLength = 0;
    TPSResult prefillTPS;           // Prefill phase
    TPSResult decodeTPS;            // Decode phase
    MemorySize memoryUsed = 0;
    double latencyMs = 0.0;
};

// Full benchmark report
struct BenchmarkReport {
    std::string modelName;
    std::string timestamp;
    BenchmarkConfig config;
    MemoryRequirements memory;
    std::vector<SequenceBenchmark> results;
    
    // Summary statistics
    double peakTPS = 0.0;
    double sustainedTPS = 0.0;      // Average over all sequences
    double tpsAt4K = 0.0;           // TPS at 4K context
    double tpsAt8K = 0.0;           // TPS at 8K context
    
    void GenerateSummary();
    void ExportJSON(const std::string& path) const;
    void ExportCSV(const std::string& path) const;
};

// Main benchmark harness
class BenchmarkHarness {
public:
    explicit BenchmarkHarness(const BenchmarkConfig& config);
    ~BenchmarkHarness();
    
    // Initialize memory pools
    bool Initialize();
    
    // Run full benchmark suite
    BenchmarkReport RunSuite();
    
    // Run single sequence length
    SequenceBenchmark RunSequence(uint32_t seqLength);
    
    // Validation
    bool ValidateMemory();
    bool ValidateResults(const BenchmarkReport& report);
    
private:
    BenchmarkConfig m_config;
    MemoryRequirements m_memory;
    
    // Memory pools (64-byte aligned)
    void* m_weightsPool = nullptr;
    void* m_kvCachePool = nullptr;
    void* m_activationPool = nullptr;
    void* m_workspacePool = nullptr;
    
    // Timing
    using Clock = std::chrono::high_resolution_clock;
    using TimePoint = Clock::time_point;
    
    TimePoint Now() const { return Clock::now(); }
    double ElapsedMs(TimePoint start, TimePoint end) const {
        return std::chrono::duration<double, std::milli>(end - start).count();
    }
    
    // Internal helpers
    bool AllocatePools();
    void FreePools();
    double MeasurePrefill(uint32_t seqLength);
    double MeasureDecode(uint32_t seqLength);
};

// Memory calculation implementation
inline void MemoryRequirements::Calculate(const BenchmarkConfig& config) {
    // Use 64-bit arithmetic throughout
    MemorySize batch = config.batchSize;
    MemorySize layers = config.numLayers;
    MemorySize hidden = config.hiddenSize;
    MemorySize heads = config.numHeads;
    MemorySize headDim = config.headDim;
    MemorySize vocab = config.vocabSize;
    MemorySize intermediate = config.intermediateSize;
    
    // Model weights (QKV + O + FFN)
    // QKV: 3 * hidden * hidden
    MemorySize qkvSize = 3 * hidden * hidden * sizeof(float);
    // O projection: hidden * hidden
    MemorySize oSize = hidden * hidden * sizeof(float);
    // FFN: 2 * hidden * intermediate (gate + up)
    MemorySize ffnSize = 2 * hidden * intermediate * sizeof(float);
    // Output: intermediate * hidden
    MemorySize ffnOutSize = intermediate * hidden * sizeof(float);
    // Embeddings: vocab * hidden
    MemorySize embedSize = vocab * hidden * sizeof(float);
    // LM head: vocab * hidden (often shared with embeddings)
    MemorySize lmHeadSize = vocab * hidden * sizeof(float);
    
    weightsSize = (qkvSize + oSize + ffnSize + ffnOutSize + embedSize + lmHeadSize) * layers;
    
    // KV cache: 2 * layers * batch * seq * heads * head_dim
    // For max sequence length
    MemorySize maxSeq = config.maxSequenceLength;
    kvCacheSize = 2 * layers * batch * maxSeq * heads * headDim * sizeof(float);
    
    // Activations: batch * seq * hidden (for each layer)
    activationSize = batch * maxSeq * hidden * sizeof(float) * 4;  // 4x for intermediates
    
    // Workspace: temporary buffers
    workspaceSize = batch * maxSeq * hidden * sizeof(float) * 2;
    
    // Total with alignment padding
    totalSize = weightsSize + kvCacheSize + activationSize + workspaceSize;
    totalSize = (totalSize + 4095) & ~4095;  // 4KB align
}

inline std::string MemoryRequirements::Format() const {
    auto formatBytes = [](MemorySize bytes) -> std::string {
        const char* units[] = {"B", "KB", "MB", "GB", "TB"};
        int unit = 0;
        double size = static_cast<double>(bytes);
        while (size >= 1024.0 && unit < 4) {
            size /= 1024.0;
            unit++;
        }
        char buf[64];
        snprintf(buf, sizeof(buf), "%.2f %s", size, units[unit]);
        return std::string(buf);
    };
    
    std::string result = "Memory Requirements:\n";
    result += "  Weights:    " + formatBytes(weightsSize) + "\n";
    result += "  KV Cache:   " + formatBytes(kvCacheSize) + "\n";
    result += "  Activations:" + formatBytes(activationSize) + "\n";
    result += "  Workspace:  " + formatBytes(workspaceSize) + "\n";
    result += "  Total:      " + formatBytes(totalSize) + "\n";
    return result;
}

} // namespace Benchmark
} // namespace RawrXD
