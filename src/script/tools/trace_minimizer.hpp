// RawrXD-Script Trace Minimization Engine
// Reduces failing traces to minimal reproducible cases
// Turns 1000-instruction failures into 5-instruction cases

#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <functional>

namespace RawrXD {
namespace Script {

// Forward declaration
struct TraceEntry;
class TraceValidator;

// ============================================================================
// MINIMIZATION STRATEGY
// ============================================================================

enum class MinimizationStrategy {
    kBinarySearch,      // Halve trace, check if failure persists
    kDeltaDebugging,    // Systematic subset testing
    kDependencyAware,   // Keep instructions that affect failure point
    kGreedyRemoval,     // Try removing each instruction individually
    kHybrid             // Combine strategies for best results
};

// ============================================================================
// MINIMIZATION RESULT
// ============================================================================

struct MinimizationResult {
    bool success;
    size_t originalSize;
    size_t minimizedSize;
    float reductionRatio;
    std::vector<TraceEntry> minimizedTrace;
    std::vector<std::string> removalLog;
    
    void Print() const;
};

// ============================================================================
// TRACE MINIMIZER
// ============================================================================

class TraceMinimizer {
public:
    TraceMinimizer();
    ~TraceMinimizer();
    
    // Set the oracle function - returns true if trace still fails
    void SetOracle(std::function<bool(const std::vector<TraceEntry&)> oracle);
    
    // Minimize a trace using specified strategy
    MinimizationResult Minimize(
        const std::vector<TraceEntry>& original,
        MinimizationStrategy strategy = MinimizationStrategy::kHybrid
    );
    
    // Binary search minimization
    MinimizationResult MinimizeBinarySearch(const std::vector<TraceEntry>& original);
    
    // Delta debugging (systematic subset testing)
    MinimizationResult MinimizeDeltaDebugging(const std::vector<TraceEntry>& original);
    
    // Dependency-aware minimization
    MinimizationResult MinimizeDependencyAware(const std::vector<TraceEntry>& original);
    
    // Greedy removal
    MinimizationResult MinimizeGreedy(const std::vector<TraceEntry>& original);
    
    // Configuration
    void SetMaxIterations(size_t max) { maxIterations_ = max; }
    void SetTimeoutMs(size_t ms) { timeoutMs_ = ms; }
    void SetVerbose(bool verbose) { verbose_ = verbose; }
    
private:
    std::function<bool(const std::vector<TraceEntry&)> oracle_;
    size_t maxIterations_;
    size_t timeoutMs_;
    bool verbose_;
    
    // Helper methods
    bool TestSubset(const std::vector<TraceEntry>& subset);
    std::vector<TraceEntry> RemoveRange(
        const std::vector<TraceEntry>& trace,
        size_t start,
        size_t end
    );
    std::vector<TraceEntry> KeepRange(
        const std::vector<TraceEntry>& trace,
        size_t start,
        size_t end
    );
    
    // Dependency analysis
    std::vector<size_t> FindDependencies(const std::vector<TraceEntry>& trace, size_t targetIdx);
    bool IsDataDependent(const TraceEntry& reader, const TraceEntry& writer);
    bool IsControlDependent(const TraceEntry& branch, const TraceEntry& target);
};

// ============================================================================
// DELTA DEBUGGING IMPLEMENTATION
// ============================================================================

class DeltaDebugger {
public:
    DeltaDebugger(std::function<bool(const std::vector<TraceEntry&)> oracle);
    
    std::vector<TraceEntry> Minimize(const std::vector<TraceEntry>& input);
    
private:
    std::function<bool(const std::vector<TraceEntry&)> oracle_;
    
    // Granularity levels: 2, 4, 8, 16, ... up to input size
    std::vector<TraceEntry> MinimizeAtGranularity(
        const std::vector<TraceEntry>& current,
        size_t granularity
    );
};

// ============================================================================
// FAILURE PATTERN DETECTOR
// ============================================================================

struct FailurePattern {
    enum class Type {
        kArithmeticError,      // Wrong result from arithmetic
        kMemoryError,          // Arena overflow, use-after-free
        kICError,              // IC miss when hit expected
        kControlFlowError,     // Wrong branch taken
        kTypeError,            // Type coercion failure
        kRegisterCorruption,   // Register state unexpected
        kUnknown
    };
    
    Type type;
    size_t failurePoint;       // Instruction index where failure detected
    std::string description;
    std::vector<size_t> relevantInstructions;
};

class FailurePatternDetector {
public:
    FailurePattern DetectPattern(const std::vector<TraceEntry>& trace);
    
    // Pattern-specific minimization hints
    std::vector<size_t> GetRequiredInstructions(const FailurePattern& pattern);
};

} // namespace Script
} // namespace RawrXD
