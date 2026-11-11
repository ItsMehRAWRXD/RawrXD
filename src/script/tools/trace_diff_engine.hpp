// RawrXD-Script Trace Diff Engine
// Compares execution traces to detect semantic drift, IC instability, and optimization bugs

#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <functional>
#include <optional>
#include <json/json.h>

namespace RawrXD {
namespace Script {

// ============================================================================
// TRACE DIFF ENTRY
// ============================================================================
// Represents a single difference between two execution traces

enum class DiffType {
    kOpcodeMismatch,      // Different opcode at same PC
    kRegisterMismatch,    // Register value differs
    kICStateMismatch,     // IC hit/miss differs
    kPCMismatch,          // PC divergence (branch taken differently)
    kMissingInstruction,  // Instruction present in A but not B
    kExtraInstruction,    // Instruction present in B but not A
    kMemoryEffectMismatch,// Arena/memory state differs
    kTimingAnomaly        // Cycle count anomaly (performance regression)
};

struct TraceDiff {
    DiffType type;
    size_t pc;                    // Program counter where diff occurred
    size_t instructionIndex;      // Index in trace sequence
    
    // Before/after values
    uint64_t expectedValue;
    uint64_t actualValue;
    
    // Context
    uint8_t expectedOpcode;
    uint8_t actualOpcode;
    
    // Register context
    uint64_t expectedRegisters[16];
    uint64_t actualRegisters[16];
    
    // Human-readable description
    std::string description;
    
    // Severity
    enum class Severity {
        kInfo,      // Cosmetic difference
        kWarning,   // Potential issue
        kError,     // Semantic divergence
        kCritical   // Execution failure
    } severity;
};

// ============================================================================
// TRACE SNAPSHOT
// ============================================================================
// Immutable record of execution for comparison

struct TraceSnapshot {
    std::string name;                    // e.g., "baseline", "optimized"
    std::string timestamp;
    std::string gitCommit;
    
    struct InstructionRecord {
        size_t pc;
        uint8_t opcode;
        uint64_t rawInstruction;
        uint64_t registers[16];
        uint64_t arenaBump;
        bool icHit;
        bool icMiss;
        uint64_t cycleCount;
    };
    
    std::vector<InstructionRecord> instructions;
    
    // Metadata
    size_t totalOpcodes;
    size_t uniqueOpcodes;
    size_t icHits;
    size_t icMisses;
    uint64_t totalCycles;
    
    // Export/Import
    void ExportToJson(const std::string& filename) const;
    static std::optional<TraceSnapshot> ImportFromJson(const std::string& filename);
};

// ============================================================================
// DIFF CONFIGURATION
// ============================================================================
// Controls what differences are considered significant

struct DiffConfig {
    // Register comparison
    bool compareAllRegisters = true;      // Compare all 16 registers
    bool compareAccumulatorOnly = false;  // Only compare v0 (accumulator)
    uint64_t registerTolerance = 0;       // Bitwise tolerance for floats
    
    // IC comparison
    bool compareICState = true;           // Check hit/miss patterns
    bool allowICWarmup = true;            // Allow first-run misses
    
    // PC comparison
    bool strictPCAlignment = true;        // PC must match exactly
    bool allowLoopUnrolling = false;      // Allow unrolled loops
    
    // Timing
    bool compareCycleCounts = false;      // Include timing in diff
    double cycleTolerancePercent = 5.0;   // Acceptable performance variance
    
    // Memory
    bool compareArenaState = true;      // Check allocation patterns
    
    // Filters
    std::vector<uint8_t> ignoreOpcodes;  // Opcodes to skip in comparison
    bool ignoreDebugOpcodes = true;       // Skip OP_BREAKPOINT, OP_TRACE
};

// ============================================================================
// TRACE DIFF ENGINE
// ============================================================================

class TraceDiffEngine {
public:
    TraceDiffEngine(const DiffConfig& config = DiffConfig{});
    
    // Compare two traces
    std::vector<TraceDiff> Compare(
        const TraceSnapshot& baseline,
        const TraceSnapshot& current
    );
    
    // Smart comparison (handles optimizations)
    std::vector<TraceDiff> CompareWithOptimizations(
        const TraceSnapshot& baseline,
        const TraceSnapshot& current
    );
    
    // Analysis
    bool IsSemanticallyEquivalent(
        const TraceSnapshot& baseline,
        const TraceSnapshot& current
    );
    
    bool IsPerformanceRegression(
        const TraceSnapshot& baseline,
        const TraceSnapshot& current,
        double thresholdPercent = 10.0
    );
    
    // IC stability check
    bool IsICStable(
        const TraceSnapshot& baseline,
        const TraceSnapshot& current
    );
    
    // Report generation
    void GenerateReport(
        const std::vector<TraceDiff>& diffs,
        const std::string& filename
    ) const;
    
    void PrintDiffSummary(const std::vector<TraceDiff>& diffs) const;
    
    // Minimization
    std::vector<TraceSnapshot::InstructionRecord> MinimizeReproducibleCase(
        const std::vector<TraceDiff>& diffs
    ) const;
    
private:
    DiffConfig config_;
    
    // Comparison helpers
    bool RegistersEqual(const uint64_t* a, const uint64_t* b) const;
    bool IsEquivalentOpcode(uint8_t opA, uint8_t opB) const;
    DiffType ClassifyDifference(
        const TraceSnapshot::InstructionRecord& expected,
        const TraceSnapshot::InstructionRecord& actual
    ) const;
    
    // Longest Common Subsequence (LCS) for trace alignment
    std::vector<std::pair<size_t, size_t>> AlignTraces(
        const TraceSnapshot& baseline,
        const TraceSnapshot& current
    ) const;
};

// ============================================================================
// OPTIMIZATION SAFETY GATE
// ============================================================================
// Ensures optimizations don't change semantics

class OptimizationSafetyGate {
public:
    // Before/after optimization comparison
    struct ValidationResult {
        bool passed;
        std::vector<TraceDiff> diffs;
        std::string failureReason;
        
        // Performance metrics
        double speedupPercent;
        bool isPerformanceImprovement;
        bool isPerformanceRegression;
    };
    
    static ValidationResult ValidateOptimization(
        const TraceSnapshot& before,
        const TraceSnapshot& after,
        const DiffConfig& config = DiffConfig{}
    );
    
    // CI/CD integration
    static bool ShouldAcceptOptimization(const ValidationResult& result);
    
    // Generate report for PR
    static void GeneratePRReport(
        const ValidationResult& result,
        const std::string& outputPath
    );
};

// ============================================================================
// CI/CD INTEGRATION
// ============================================================================

// Exit codes for CI integration
namespace TraceDiffExitCode {
    constexpr int kSuccess = 0;           // Traces match
    constexpr int kSemanticDiff = 1;      // Semantic divergence detected
    constexpr int kPerformanceReg = 2;  // Performance regression
    constexpr int kICInstability = 3;   // IC behavior changed
    constexpr int kFileError = 4;     // Could not read trace files
    constexpr int kConfigError = 5;     // Invalid configuration
}

// Command-line interface
int RunTraceDiff(int argc, char* argv[]);

} // namespace Script
} // namespace RawrXD
