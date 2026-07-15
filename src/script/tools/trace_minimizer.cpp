// RawrXD-Script Trace Minimization Engine Implementation
// Reduces failing traces to minimal reproducible cases

#include "trace_minimizer.hpp"
#include "../runtime/trace_validator.hpp"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <algorithm>

namespace RawrXD {
namespace Script {

// ============================================================================
// TRACE MINIMIZER IMPLEMENTATION
// ============================================================================

TraceMinimizer::TraceMinimizer()
    : maxIterations_(1000)
    , timeoutMs_(60000)  // 1 minute default
    , verbose_(false)
{
}

TraceMinimizer::~TraceMinimizer() = default;

void TraceMinimizer::SetOracle(std::function<bool(const std::vector<TraceEntry&)> oracle) {
    oracle_ = oracle;
}

MinimizationResult TraceMinimizer::Minimize(
    const std::vector<TraceEntry>& original,
    MinimizationStrategy strategy
) {
    MinimizationResult result;
    result.originalSize = original.size();
    
    if (!oracle_) {
        result.success = false;
        result.removalLog.push_back("ERROR: No oracle function set");
        return result;
    }
    
    if (original.empty()) {
        result.success = true;
        result.minimizedSize = 0;
        result.reductionRatio = 0.0f;
        return result;
    }
    
    // Verify original actually fails
    if (!oracle_(original)) {
        result.success = false;
        result.removalLog.push_back("ERROR: Original trace does not fail oracle");
        return result;
    }
    
    auto startTime = std::chrono::steady_clock::now();
    
    switch (strategy) {
        case MinimizationStrategy::kBinarySearch:
            result = MinimizeBinarySearch(original);
            break;
        case MinimizationStrategy::kDeltaDebugging:
            result = MinimizeDeltaDebugging(original);
            break;
        case MinimizationStrategy::kDependencyAware:
            result = MinimizeDependencyAware(original);
            break;
        case MinimizationStrategy::kGreedyRemoval:
            result = MinimizeGreedy(original);
            break;
        case MinimizationStrategy::kHybrid:
            // Try multiple strategies and pick best result
            result = MinimizeHybrid(original);
            break;
    }
    
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    if (verbose_) {
        printf("Minimization completed in %lld ms\n", duration.count());
        printf("Original: %zu instructions\n", result.originalSize);
        printf("Minimized: %zu instructions\n", result.minimizedSize);
        printf("Reduction: %.1f%%\n", result.reductionRatio * 100);
    }
    
    return result;
}

MinimizationResult TraceMinimizer::MinimizeBinarySearch(
    const std::vector<TraceEntry>& original
) {
    MinimizationResult result;
    result.originalSize = original.size();
    result.minimizedTrace = original;  // Start with full trace
    
    size_t low = 0;
    size_t high = original.size();
    
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        
        // Try removing second half
        auto candidate = KeepRange(original, 0, mid);
        if (TestSubset(candidate)) {
            // Can remove second half
            result.minimizedTrace = candidate;
            high = mid;
            result.removalLog.push_back("Removed range [" + 
                std::to_string(mid) + ", " + std::to_string(original.size()) + ")");
        } else {
            // Try removing first half
            candidate = KeepRange(original, mid, original.size());
            if (TestSubset(candidate)) {
                result.minimizedTrace = candidate;
                low = mid;
                result.removalLog.push_back("Removed range [0, " + 
                    std::to_string(mid) + ")");
            } else {
                // Can't remove either half, try smaller chunks
                break;
            }
        }
    }
    
    result.minimizedSize = result.minimizedTrace.size();
    result.reductionRatio = 1.0f - (float)result.minimizedSize / result.originalSize;
    result.success = true;
    
    return result;
}

MinimizationResult TraceMinimizer::MinimizeDeltaDebugging(
    const std::vector<TraceEntry>& original
) {
    DeltaDebugger debugger(oracle_);
    
    MinimizationResult result;
    result.originalSize = original.size();
    result.minimizedTrace = debugger.Minimize(original);
    result.minimizedSize = result.minimizedTrace.size();
    result.reductionRatio = 1.0f - (float)result.minimizedSize / result.originalSize;
    result.success = true;
    
    return result;
}

MinimizationResult TraceMinimizer::MinimizeDependencyAware(
    const std::vector<TraceEntry>& original
) {
    MinimizationResult result;
    result.originalSize = original.size();
    
    // First, detect failure pattern
    FailurePatternDetector detector;
    FailurePattern pattern = detector.DetectPattern(original);
    
    // Get required instructions based on pattern
    std::vector<size_t> required = detector.GetRequiredInstructions(pattern);
    
    // Build minimized trace from required instructions
    for (size_t idx : required) {
        if (idx < original.size()) {
            result.minimizedTrace.push_back(original[idx]);
        }
    }
    
    // Verify minimized trace still fails
    if (!TestSubset(result.minimizedTrace)) {
        // Fall back to greedy if dependency analysis fails
        return MinimizeGreedy(original);
    }
    
    result.minimizedSize = result.minimizedTrace.size();
    result.reductionRatio = 1.0f - (float)result.minimizedSize / result.originalSize;
    result.success = true;
    
    return result;
}

MinimizationResult TraceMinimizer::MinimizeGreedy(
    const std::vector<TraceEntry>& original
) {
    MinimizationResult result;
    result.originalSize = original.size();
    result.minimizedTrace = original;
    
    // Try removing each instruction one at a time
    for (size_t i = 0; i < result.minimizedTrace.size() && i < maxIterations_; i++) {
        auto candidate = result.minimizedTrace;
        candidate.erase(candidate.begin() + i);
        
        if (TestSubset(candidate)) {
            // Can remove this instruction
            result.minimizedTrace = candidate;
            result.removalLog.push_back("Removed instruction at index " + std::to_string(i));
            i--;  // Adjust index since we removed current element
        }
    }
    
    result.minimizedSize = result.minimizedTrace.size();
    result.reductionRatio = 1.0f - (float)result.minimizedSize / result.originalSize;
    result.success = true;
    
    return result;
}

MinimizationResult TraceMinimizer::MinimizeHybrid(
    const std::vector<TraceEntry>& original
) {
    // Try multiple strategies and return best result
    std::vector<MinimizationResult> results;
    
    results.push_back(MinimizeBinarySearch(original));
    results.push_back(MinimizeDeltaDebugging(original));
    results.push_back(MinimizeGreedy(original));
    
    // Pick the smallest result
    auto best = std::min_element(results.begin(), results.end(),
        [](const MinimizationResult& a, const MinimizationResult& b) {
            return a.minimizedSize < b.minimizedSize;
        });
    
    return *best;
}

bool TraceMinimizer::TestSubset(const std::vector<TraceEntry>& subset) {
    if (!oracle_) return false;
    
    try {
        return oracle_(subset);
    } catch (...) {
        // Oracle threw exception - treat as failure
        return false;
    }
}

std::vector<TraceEntry> TraceMinimizer::RemoveRange(
    const std::vector<TraceEntry>& trace,
    size_t start,
    size_t end
) {
    std::vector<TraceEntry> result;
    result.reserve(trace.size() - (end - start));
    
    for (size_t i = 0; i < trace.size(); i++) {
        if (i < start || i >= end) {
            result.push_back(trace[i]);
        }
    }
    
    return result;
}

std::vector<TraceEntry> TraceMinimizer::KeepRange(
    const std::vector<TraceEntry>& trace,
    size_t start,
    size_t end
) {
    std::vector<TraceEntry> result;
    
    for (size_t i = start; i < end && i < trace.size(); i++) {
        result.push_back(trace[i]);
    }
    
    return result;
}

// ============================================================================
// DELTA DEBUGGER IMPLEMENTATION
// ============================================================================

DeltaDebugger::DeltaDebugger(std::function<bool(const std::vector<TraceEntry&)> oracle)
    : oracle_(oracle)
{
}

std::vector<TraceEntry> DeltaDebugger::Minimize(const std::vector<TraceEntry>& input) {
    std::vector<TraceEntry> current = input;
    
    // Try increasing granularities
    for (size_t n = 2; n <= current.size(); n *= 2) {
        current = MinimizeAtGranularity(current, n);
    }
    
    return current;
}

std::vector<TraceEntry> DeltaDebugger::MinimizeAtGranularity(
    const std::vector<TraceEntry>& current,
    size_t granularity
) {
    size_t chunkSize = (current.size() + granularity - 1) / granularity;
    
    for (size_t i = 0; i < granularity; i++) {
        size_t start = i * chunkSize;
        size_t end = std::min(start + chunkSize, current.size());
        
        // Try removing this chunk
        std::vector<TraceEntry> candidate;
        for (size_t j = 0; j < current.size(); j++) {
            if (j < start || j >= end) {
                candidate.push_back(current[j]);
            }
        }
        
        if (oracle_(candidate)) {
            // Can remove this chunk
            return MinimizeAtGranularity(candidate, granularity);
        }
    }
    
    return current;
}

// ============================================================================
// FAILURE PATTERN DETECTOR
// ============================================================================

FailurePattern FailurePatternDetector::DetectPattern(const std::vector<TraceEntry>& trace) {
    FailurePattern pattern;
    pattern.type = FailurePattern::Type::kUnknown;
    pattern.failurePoint = trace.size();  // Default to end
    
    // Analyze trace for common failure patterns
    for (size_t i = 0; i < trace.size(); i++) {
        const auto& entry = trace[i];
        
        // Check for arithmetic errors (unexpected result)
        // This would require knowing expected vs actual values
        
        // Check for IC errors
        if (entry.icMiss && i > 0) {
            // IC miss when we might expect hit
            // This is heuristic - would need more context
        }
        
        // Check for memory errors (would need arena state)
    }
    
    return pattern;
}

std::vector<size_t> FailurePatternDetector::GetRequiredInstructions(
    const FailurePattern& pattern
) {
    std::vector<size_t> required;
    
    // Always include failure point
    required.push_back(pattern.failurePoint);
    
    // Include instructions that set up the failure
    // This is pattern-specific
    switch (pattern.type) {
        case FailurePattern::Type::kArithmeticError:
            // Need the arithmetic instruction and its inputs
            if (pattern.failurePoint > 0) {
                required.push_back(pattern.failurePoint - 1);  // Input 1
            }
            break;
            
        case FailurePattern::Type::kICError:
            // Need property access and shape setup
            break;
            
        default:
            // Conservative: keep everything near failure point
            for (size_t i = 0; i <= pattern.failurePoint && i < 10; i++) {
                required.push_back(i);
            }
            break;
    }
    
    // Sort and deduplicate
    std::sort(required.begin(), required.end());
    required.erase(std::unique(required.begin(), required.end()), required.end());
    
    return required;
}

// ============================================================================
// MINIMIZATION RESULT
// ============================================================================

void MinimizationResult::Print() const {
    printf("\n=== Trace Minimization Result ===\n");
    printf("Success: %s\n", success ? "YES" : "NO");
    printf("Original size: %zu instructions\n", originalSize);
    printf("Minimized size: %zu instructions\n", minimizedSize);
    printf("Reduction: %.1f%%\n", reductionRatio * 100);
    
    if (!removalLog.empty()) {
        printf("\nRemoval log:\n");
        for (const auto& log : removalLog) {
            printf("  - %s\n", log.c_str());
        }
    }
    
    printf("===================================\n\n");
}

} // namespace Script
} // namespace RawrXD
