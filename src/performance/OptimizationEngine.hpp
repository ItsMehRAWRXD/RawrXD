/**
 * OptimizationEngine.hpp
 *
 * Phase H Batch 2/5: Optimization Engine
 *
 * Automated performance optimization with code transformation,
 * memory optimization, and cache-friendly data structures.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <optional>

namespace Performance {

// ============================================================================
// Forward Declarations
// ============================================================================

class OptimizationPass;
class OptimizationResult;
class OptimizationEngine;

// ============================================================================
// Optimization Types
// ============================================================================

enum class OptimizationLevel {
    NONE,           // No optimization
    BASIC,          // Basic optimizations
    MODERATE,       // Moderate optimizations
    AGGRESSIVE,     // Aggressive optimizations
    EXTREME         // Extreme optimizations (may affect correctness)
};

enum class OptimizationType {
    // Memory optimizations
    MEMORY_POOLING,
    CACHE_ALIGNMENT,
    COMPACT_DATA_STRUCTURES,
    LAZY_ALLOCATION,
    
    // CPU optimizations
    LOOP_UNROLLING,
    VECTORIZATION,
    INLINE_EXPANSION,
    BRANCH_PREDICTION,
    
    // I/O optimizations
    PREFETCHING,
    ASYNC_IO,
    BATCH_OPERATIONS,
    MEMORY_MAPPED_FILES,
    
    // Algorithmic optimizations
    ALGORITHM_REPLACEMENT,
    DATA_STRUCTURE_REPLACEMENT,
    PARALLELIZATION,
    
    // GPU optimizations
    KERNEL_FUSION,
    MEMORY_COALESCING,
    SHARED_MEMORY_USAGE,
    STREAM_OVERLAP
};

std::string OptimizationTypeToString(OptimizationType type);

// ============================================================================
// Optimization Target
// ============================================================================

/**
 * Target for optimization.
 */
struct OptimizationTarget {
    std::string name;
    std::string file;
    uint32_t line;
    std::string function;
    
    // Performance metrics
    double currentLatencyMs;
    double targetLatencyMs;
    double currentThroughput;
    double targetThroughput;
    size_t currentMemoryUsage;
    size_t targetMemoryUsage;
    
    // Constraints
    bool allowAlgorithmicChanges;
    bool allowParallelization;
    bool allowApproximation;
    double maxApproximationError;
};

// ============================================================================
// Optimization Suggestion
// ============================================================================

/**
 * Suggested optimization.
 */
struct OptimizationSuggestion {
    OptimizationType type;
    std::string description;
    std::string location;
    double estimatedImprovement;  // Percentage improvement
    double confidence;            // 0-1 confidence score
    std::string codeBefore;
    std::string codeAfter;
    std::vector<std::string> risks;
    std::vector<std::string> prerequisites;
};

// ============================================================================
// Optimization Result
// ============================================================================

/**
 * Result of applying an optimization.
 */
struct OptimizationResult {
    bool success;
    std::string errorMessage;
    
    // Before/after metrics
    double latencyBeforeMs;
    double latencyAfterMs;
    double throughputBefore;
    double throughputAfter;
    size_t memoryBefore;
    size_t memoryAfter;
    
    // Calculated improvements
    double latencyImprovement;      // Percentage
    double throughputImprovement;   // Percentage
    double memoryImprovement;       // Percentage
    
    // Validation
    bool correctnessVerified;
    std::string validationMethod;
    
    std::string ToJson() const;
};

// ============================================================================
// Optimization Pass
// ============================================================================

/**
 * Base class for optimization passes.
 */
class OptimizationPass {
public:
    virtual ~OptimizationPass() = default;
    
    virtual std::string GetName() const = 0;
    virtual std::string GetDescription() const = 0;
    virtual OptimizationType GetType() const = 0;
    virtual OptimizationLevel GetLevel() const = 0;
    
    // Check if this pass can be applied
    virtual bool CanApply(const OptimizationTarget& target) const = 0;
    
    // Generate suggestions
    virtual std::vector<OptimizationSuggestion> GenerateSuggestions(
        const OptimizationTarget& target) const = 0;
    
    // Apply optimization
    virtual OptimizationResult Apply(const OptimizationTarget& target,
                                     const OptimizationSuggestion& suggestion) = 0;
    
    // Validate result
    virtual bool Validate(const OptimizationTarget& target,
                          const OptimizationResult& result) const = 0;
};

// ============================================================================
// Memory Optimization Passes
// ============================================================================

/**
 * Memory pooling optimization.
 */
class MemoryPoolOptimizationPass : public OptimizationPass {
public:
    std::string GetName() const override { return "MemoryPoolOptimization"; }
    std::string GetDescription() const override;
    OptimizationType GetType() const override { return OptimizationType::MEMORY_POOLING; }
    OptimizationLevel GetLevel() const override { return OptimizationLevel::MODERATE; }
    
    bool CanApply(const OptimizationTarget& target) const override;
    std::vector<OptimizationSuggestion> GenerateSuggestions(
        const OptimizationTarget& target) const override;
    OptimizationResult Apply(const OptimizationTarget& target,
                             const OptimizationSuggestion& suggestion) override;
    bool Validate(const OptimizationTarget& target,
                  const OptimizationResult& result) const override;
};

/**
 * Cache alignment optimization.
 */
class CacheAlignmentOptimizationPass : public OptimizationPass {
public:
    std::string GetName() const override { return "CacheAlignmentOptimization"; }
    std::string GetDescription() const override;
    OptimizationType GetType() const override { return OptimizationType::CACHE_ALIGNMENT; }
    OptimizationLevel GetLevel() const override { return OptimizationLevel::BASIC; }
    
    bool CanApply(const OptimizationTarget& target) const override;
    std::vector<OptimizationSuggestion> GenerateSuggestions(
        const OptimizationTarget& target) const override;
    OptimizationResult Apply(const OptimizationTarget& target,
                             const OptimizationSuggestion& suggestion) override;
    bool Validate(const OptimizationTarget& target,
                  const OptimizationResult& result) const override;
};

// ============================================================================
// CPU Optimization Passes
// ============================================================================

/**
 * Loop optimization pass.
 */
class LoopOptimizationPass : public OptimizationPass {
public:
    std::string GetName() const override { return "LoopOptimization"; }
    std::string GetDescription() const override;
    OptimizationType GetType() const override { return OptimizationType::LOOP_UNROLLING; }
    OptimizationLevel GetLevel() const override { return OptimizationLevel::MODERATE; }
    
    bool CanApply(const OptimizationTarget& target) const override;
    std::vector<OptimizationSuggestion> GenerateSuggestions(
        const OptimizationTarget& target) const override;
    OptimizationResult Apply(const OptimizationTarget& target,
                             const OptimizationSuggestion& suggestion) override;
    bool Validate(const OptimizationTarget& target,
                  const OptimizationResult& result) const override;
};

/**
 * Vectorization optimization pass.
 */
class VectorizationOptimizationPass : public OptimizationPass {
public:
    std::string GetName() const override { return "VectorizationOptimization"; }
    std::string GetDescription() const override;
    OptimizationType GetType() const override { return OptimizationType::VECTORIZATION; }
    OptimizationLevel GetLevel() const override { return OptimizationLevel::AGGRESSIVE; }
    
    bool CanApply(const OptimizationTarget& target) const override;
    std::vector<OptimizationSuggestion> GenerateSuggestions(
        const OptimizationTarget& target) const override;
    OptimizationResult Apply(const OptimizationTarget& target,
                             const OptimizationSuggestion& suggestion) override;
    bool Validate(const OptimizationTarget& target,
                  const OptimizationResult& result) const override;
};

// ============================================================================
// I/O Optimization Passes
// ============================================================================

/**
 * I/O batching optimization.
 */
class IoBatchingOptimizationPass : public OptimizationPass {
public:
    std::string GetName() const override { return "IoBatchingOptimization"; }
    std::string GetDescription() const override;
    OptimizationType GetType() const override { return OptimizationType::BATCH_OPERATIONS; }
    OptimizationLevel GetLevel() const override { return OptimizationLevel::MODERATE; }
    
    bool CanApply(const OptimizationTarget& target) const override;
    std::vector<OptimizationSuggestion> GenerateSuggestions(
        const OptimizationTarget& target) const override;
    OptimizationResult Apply(const OptimizationTarget& target,
                             const OptimizationSuggestion& suggestion) override;
    bool Validate(const OptimizationTarget& target,
                  const OptimizationResult& result) const override;
};

/**
 * Prefetching optimization.
 */
class PrefetchOptimizationPass : public OptimizationPass {
public:
    std::string GetName() const override { return "PrefetchOptimization"; }
    std::string GetDescription() const override;
    OptimizationType GetType() const override { return OptimizationType::PREFETCHING; }
    OptimizationLevel GetLevel() const override { return OptimizationLevel::BASIC; }
    
    bool CanApply(const OptimizationTarget& target) const override;
    std::vector<OptimizationSuggestion> GenerateSuggestions(
        const OptimizationTarget& target) const override;
    OptimizationResult Apply(const OptimizationTarget& target,
                             const OptimizationSuggestion& suggestion) override;
    bool Validate(const OptimizationTarget& target,
                  const OptimizationResult& result) const override;
};

// ============================================================================
// Algorithmic Optimization Passes
// ============================================================================

/**
 * Algorithm replacement optimization.
 */
class AlgorithmReplacementPass : public OptimizationPass {
public:
    struct AlgorithmAlternative {
        std::string name;
        std::string description;
        double timeComplexity;
        double spaceComplexity;
        std::string codeTemplate;
    };
    
    std::string GetName() const override { return "AlgorithmReplacement"; }
    std::string GetDescription() const override;
    OptimizationType GetType() const override { return OptimizationType::ALGORITHM_REPLACEMENT; }
    OptimizationLevel GetLevel() const override { return OptimizationLevel::AGGRESSIVE; }
    
    bool CanApply(const OptimizationTarget& target) const override;
    std::vector<OptimizationSuggestion> GenerateSuggestions(
        const OptimizationTarget& target) const override;
    OptimizationResult Apply(const OptimizationTarget& target,
                             const OptimizationSuggestion& suggestion) override;
    bool Validate(const OptimizationTarget& target,
                  const OptimizationResult& result) const override;
    
    void RegisterAlgorithm(const std::string& pattern, const AlgorithmAlternative& alternative);
    
private:
    std::map<std::string, AlgorithmAlternative> algorithms_;
};

// ============================================================================
// Optimization Engine
// ============================================================================

/**
 * Main optimization engine.
 */
class OptimizationEngine {
public:
    struct Config {
        OptimizationLevel defaultLevel = OptimizationLevel::MODERATE;
        bool autoApply = false;
        bool requireValidation = true;
        double minImprovementThreshold = 0.05;  // 5% minimum improvement
        uint32_t maxPasses = 10;
    };
    
    explicit OptimizationEngine(const Config& config = Config{});
    ~OptimizationEngine();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Register optimization passes
    void RegisterPass(std::unique_ptr<OptimizationPass> pass);
    void RegisterDefaultPasses();
    
    // Get available passes
    std::vector<OptimizationPass*> GetPasses() const;
    std::vector<OptimizationPass*> GetPassesForType(OptimizationType type) const;
    std::vector<OptimizationPass*> GetPassesForLevel(OptimizationLevel level) const;
    
    // Analyze target
    std::vector<OptimizationSuggestion> Analyze(const OptimizationTarget& target);
    std::vector<OptimizationSuggestion> Analyze(const OptimizationTarget& target,
                                                     OptimizationType type);
    
    // Apply optimization
    OptimizationResult Optimize(const OptimizationTarget& target,
                               const OptimizationSuggestion& suggestion);
    
    // Auto-optimize
    std::vector<OptimizationResult> AutoOptimize(const OptimizationTarget& target);
    std::vector<OptimizationResult> AutoOptimize(const OptimizationTarget& target,
                                                    OptimizationLevel level);
    
    // Batch optimization
    std::vector<OptimizationResult> OptimizeBatch(
        const std::vector<OptimizationTarget>& targets);
    
    // Rollback
    bool Rollback(const std::string& optimizationId);
    bool RollbackAll();
    
    // History
    std::vector<OptimizationResult> GetOptimizationHistory() const;
    std::vector<OptimizationResult> GetSuccessfulOptimizations() const;
    
    // Statistics
    struct Statistics {
        uint64_t totalOptimizations;
        uint64_t successfulOptimizations;
        uint64_t failedOptimizations;
        double averageImprovement;
        double totalImprovement;
    };
    Statistics GetStatistics() const;
    
    // Export
    std::string GenerateReport() const;
    void ExportResults(const std::string& filepath) const;
    
private:
    Config config_;
    std::vector<std::unique_ptr<OptimizationPass>> passes_;
    std::vector<OptimizationResult> history_;
    mutable std::mutex historyMutex_;
    
    std::map<std::string, std::string> backups_;  // optimizationId -> backup
    mutable std::mutex backupsMutex_;
    
    OptimizationResult RunPass(OptimizationPass* pass,
                               const OptimizationTarget& target,
                               const OptimizationSuggestion& suggestion);
};

// ============================================================================
// Optimization Utilities
// ============================================================================

/**
 * Cache-friendly data structures.
 */
template<typename T, size_t CacheLineSize = 64>
class CacheAlignedAllocator {
public:
    using value_type = T;
    using size_type = size_t;
    using difference_type = ptrdiff_t;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    
    pointer allocate(size_type n) {
        size_t bytes = n * sizeof(T);
        size_t padded = ((bytes + CacheLineSize - 1) / CacheLineSize) * CacheLineSize;
        void* ptr = nullptr;
        #ifdef _WIN32
        ptr = _aligned_malloc(padded, CacheLineSize);
        #else
        posix_memalign(&ptr, CacheLineSize, padded);
        #endif
        return static_cast<pointer>(ptr);
    }
    
    void deallocate(pointer p, size_type) {
        #ifdef _WIN32
        _aligned_free(p);
        #else
        free(p);
        #endif
    }
    
    template<typename U>
    struct rebind {
        using other = CacheAlignedAllocator<U, CacheLineSize>;
    };
};

/**
 * Prefetch utilities.
 */
class Prefetcher {
public:
    enum class TemporalLevel {
        NONE,       // Non-temporal (streaming)
        LOW,        // Low temporal locality
        MODERATE,   // Moderate temporal locality
        HIGH        // High temporal locality
    };
    
    static void Prefetch(const void* addr, TemporalLevel level = TemporalLevel::HIGH);
    static void PrefetchWrite(const void* addr, TemporalLevel level = TemporalLevel::HIGH);
};

// Platform-specific prefetch implementations
#ifdef _MSC_VER
#include <intrin.h>
inline void Prefetcher::Prefetch(const void* addr, TemporalLevel level) {
    switch (level) {
        case TemporalLevel::NONE: _mm_prefetch((const char*)addr, _MM_HINT_NTA); break;
        case TemporalLevel::LOW: _mm_prefetch((const char*)addr, _MM_HINT_T2); break;
        case TemporalLevel::MODERATE: _mm_prefetch((const char*)addr, _MM_HINT_T1); break;
        case TemporalLevel::HIGH: _mm_prefetch((const char*)addr, _MM_HINT_T0); break;
    }
}
#else
inline void Prefetcher::Prefetch(const void* addr, TemporalLevel level) {
    __builtin_prefetch(addr, 0, static_cast<int>(level));
}
#endif

} // namespace Performance
