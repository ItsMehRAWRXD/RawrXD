//=============================================================================
// VAL-035: Sovereign Runtime Integration Benchmark
// End-to-End Pipeline Validation for RawrXD Memory+Compute Architecture
//
// Measures the complete inference pipeline:
//   Token Request → KV Lookup → Residency Classification → Prefetch Scheduling
//   → Tree Attention → FFN → Sampler → Token Output
//
// Validates the claimed 657x speedup (33,000µs → 50.5µs) with reproducible
// end-to-end measurements on identical hardware and model configurations.
//=============================================================================

#pragma once

#include "../memory/SovereignMemoryAllocator.hpp"
#include "../memory/KVResidencyScheduler.hpp"
#include "../memory/AVX512PrefetchIntegration.hpp"
#include "../kv_cache/PagedKVCache_Sovereign.hpp"
#include <cstdint>
#include <vector>
#include <chrono>
#include <atomic>
#include <string>

namespace RawrXD {
namespace Benchmark {

//=============================================================================
// Benchmark Configuration
//=============================================================================
struct IntegrationBenchmarkConfig {
    // Model configuration
    uint32_t numLayers = 32;
    uint32_t numHeads = 32;
    uint32_t headDim = 128;
    uint32_t hiddenDim = 4096;
    uint32_t vocabSize = 32000;
    
    // Sequence configuration
    uint32_t promptLength = 128;
    uint32_t generationLength = 256;
    uint32_t batchSize = 1;
    
    // KV cache configuration
    uint32_t maxSeqLen = 8192;
    uint32_t blockSize = 16;
    
    // Benchmark iterations
    uint32_t warmupIterations = 10;
    uint32_t benchmarkIterations = 100;
    
    // Enable/disable components
    bool useSovereignAllocator = true;
    bool useResidencyScheduler = true;
    bool usePrefetchIntegration = true;
    bool useLargePages = true;
    bool useNumaAffinity = true;
};

//=============================================================================
// Latency Metrics
//=============================================================================
struct LatencyMetrics {
    // Time to first token
    double ttftMs;              // Time from request to first output token
    
    // Token generation latency
    double meanTokenLatencyUs;
    double p50TokenLatencyUs;
    double p95TokenLatencyUs;
    double p99TokenLatencyUs;
    double minTokenLatencyUs;
    double maxTokenLatencyUs;
    
    // End-to-end
    double totalTimeMs;
    double tokensPerSecond;
    
    // Component breakdown (microseconds)
    double kvLookupUs;
    double residencyCheckUs;
    double prefetchScheduleUs;
    double attentionComputeUs;
    double ffnComputeUs;
    double samplerUs;
    
    void CalculatePercentiles(std::vector<double>& latencies);
    std::string GetReport() const;
};

//=============================================================================
// Memory Metrics
//=============================================================================
struct MemoryMetrics {
    // KV Residency Distribution
    uint64_t blocksHotVram;
    uint64_t blocksActiveNuma;
    uint64_t blocksWarmNuma;
    uint64_t blocksColdDram;
    uint64_t blocksCompressed;
    uint64_t blocksMappedStorage;
    uint64_t blocksEvicted;
    
    // Migration statistics
    uint64_t migrationsRequested;
    uint64_t migrationsCompleted;
    uint64_t migrationsFailed;
    double avgMigrationTimeUs;
    uint64_t bytesMigrated;
    
    // Prefetch statistics
    uint64_t prefetchesIssued;
    uint64_t prefetchesHit;
    uint64_t prefetchesMissed;
    double prefetchHitRate;
    
    // NUMA statistics
    uint64_t numaLocalReads;
    uint64_t numaRemoteReads;
    double numaLocalityRate;
    
    // TLB statistics
    uint64_t tlbMissesBefore;
    uint64_t tlbMissesAfter;
    double tlbMissReduction;
    
    // Memory allocation
    uint64_t bytesAllocated;
    uint64_t largePageAllocations;
    uint64_t standardPageAllocations;
    
    std::string GetReport() const;
};

//=============================================================================
// Kernel Metrics
//=============================================================================
struct KernelMetrics {
    // Cycle counts (measured via RDTSC)
    uint64_t qktCycles;
    uint64_t softmaxCycles;
    uint64_t avCycles;
    uint64_t ffnCycles;
    
    // Cache performance
    uint64_t l1Misses;
    uint64_t l2Misses;
    uint64_t l3Misses;
    
    // Prefetch effectiveness
    uint64_t prefetchStalls;
    uint64_t usefulPrefetches;
    double prefetchEfficiency;
    
    // AVX-512 utilization
    double fmaUtilization;
    double vectorEfficiency;
    
    std::string GetReport() const;
};

//=============================================================================
// Pipeline Stage Timing
//=============================================================================
enum class PipelineStage {
    TOKEN_REQUEST = 0,
    KV_LOOKUP,
    RESIDENCY_CLASSIFICATION,
    PREFETCH_SCHEDULING,
    TREE_ATTENTION,
    FFN,
    SAMPLER,
    TOKEN_OUTPUT,
    STAGE_COUNT
};

struct StageTiming {
    PipelineStage stage;
    uint64_t startCycles;
    uint64_t endCycles;
    uint64_t durationCycles;
    double durationUs;
};

//=============================================================================
// Benchmark Results
//=============================================================================
struct IntegrationBenchmarkResults {
    LatencyMetrics latency;
    MemoryMetrics memory;
    KernelMetrics kernel;
    std::vector<StageTiming> stageTimings;
    
    // Comparison metrics
    double speedupVsBaseline;
    double speedupVsPhase2;
    double speedupVsPhase3A;
    
    std::string GetFullReport() const;
    std::string GetSummary() const;
    bool ValidateSpeedupClaim() const;
};

//=============================================================================
// Sovereign Runtime Integration Benchmark
//=============================================================================
class SovereignRuntimeIntegrationBenchmark {
public:
    SovereignRuntimeIntegrationBenchmark();
    ~SovereignRuntimeIntegrationBenchmark();
    
    // Initialize with configuration
    bool Initialize(const IntegrationBenchmarkConfig& config);
    void Shutdown();
    
    // Run complete benchmark
    IntegrationBenchmarkResults RunBenchmark();
    
    // Run specific phases
    IntegrationBenchmarkResults RunBaselineComparison();  // Without Phase 3 optimizations
    IntegrationBenchmarkResults RunPhase3AOnly();          // Only memory optimizations
    IntegrationBenchmarkResults RunPhase3BOnly();          // Only residency scheduler
    IntegrationBenchmarkResults RunPhase3COnly();          // Only prefetch integration
    IntegrationBenchmarkResults RunFullIntegration();      // All optimizations
    
    // Component accessors for verification
    Memory::SovereignMemoryAllocator* GetAllocator() { return allocator_.get(); }
    Memory::KVResidencyScheduler* GetScheduler() { return scheduler_.get(); }
    KVCache::SovereignPagedKVCache* GetKVCache() { return kvCache_.get(); }
    
private:
    IntegrationBenchmarkConfig config_;
    
    // Components
    std::unique_ptr<Memory::SovereignMemoryAllocator> allocator_;
    std::unique_ptr<Memory::KVResidencyScheduler> scheduler_;
    std::unique_ptr<KVCache::SovereignPagedKVCache> kvCache_;
    std::unique_ptr<Memory::TreeAttentionWithPrefetch> attentionKernel_;
    
    // Benchmark state
    bool initialized_ = false;
    std::vector<double> tokenLatencies_;
    std::vector<StageTiming> stageTimings_;
    
    // Timing utilities
    uint64_t GetRdtsc() const;
    double CyclesToMicroseconds(uint64_t cycles) const;
    double CyclesToMilliseconds(uint64_t cycles) const;
    
    // Pipeline stages
    void Stage_KVLookup(uint32_t tokenIdx, uint64_t& cycles);
    void Stage_ResidencyCheck(uint32_t tokenIdx, uint64_t& cycles);
    void Stage_PrefetchSchedule(uint32_t tokenIdx, uint64_t& cycles);
    void Stage_TreeAttention(uint32_t tokenIdx, uint64_t& cycles);
    void Stage_FFN(uint32_t tokenIdx, uint64_t& cycles);
    void Stage_Sampler(uint32_t tokenIdx, uint64_t& cycles);
    
    // Metrics collection
    void CollectMemoryMetrics(MemoryMetrics& metrics);
    void CollectKernelMetrics(KernelMetrics& metrics);
    void CollectLatencyMetrics(LatencyMetrics& metrics);
    
    // Validation
    bool ValidateConfiguration() const;
    void Warmup();
};

//=============================================================================
// Convenience Functions
//=============================================================================
// Run standard integration benchmark
IntegrationBenchmarkResults RunStandardIntegrationBenchmark();

// Compare against baseline (simulated scalar implementation)
IntegrationBenchmarkResults RunBaselineComparison();

// Generate comparison report
std::string GenerateComparisonReport(
    const IntegrationBenchmarkResults& baseline,
    const IntegrationBenchmarkResults& optimized
);

} // namespace Benchmark
} // namespace RawrXD
