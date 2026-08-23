// ============================================================================
// VAL-051.7 — Deterministic Baseline Fixture
// Captures structural counters and token sequences for A/B comparison.
// ============================================================================

#ifndef VAL0517_BASELINE_FIXTURE_HPP
#define VAL0517_BASELINE_FIXTURE_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace Deep2 {

// ============================================================================
// Baseline Snapshot — Immutable capture of a single run
// ============================================================================
struct BaselineSnapshot {
    // Program identity
    std::string gitHead;
    std::string buildConfig;
    std::string executableSha256;
    std::string modelSha256;
    std::string modelPath;
    std::string prompt;
    uint64_t    seed = 0;

    // Run identity
    std::string timestamp;
    int         runNumber = 0;
    int         exitCode = 0;

    // Token sequence
    std::vector<int>    tokenIds;
    std::vector<std::string> tokenTexts;
    size_t              tokensGenerated = 0;

    // Structural counters (must be deterministic)
    uint64_t forwardCount = 0;
    uint64_t layerCount = 0;
    uint64_t remapCount = 0;
    uint64_t acquireCount = 0;
    uint64_t releaseCount = 0;
    uint64_t mapCount = 0;
    uint64_t unmapCount = 0;
    uint64_t evictionCount = 0;
    uint64_t activeLeaseCount = 0;
    uint64_t staleLeaseCount = 0;
    uint64_t residencyErrors = 0;
    uint64_t tensorAcquireFailures = 0;
    uint64_t tensorReleaseFailures = 0;
    uint64_t layerTransitions = 0;
    uint64_t forwardTransitions = 0;

    // Timing (may vary; stored for reference)
    double totalForwardMs = 0.0;
    double totalLayerMs = 0.0;
    double totalGenerationMs = 0.0;

    // Position integrity
    std::vector<size_t> positions;
    bool positionMonotonic = false;

    // Numerical health
    bool hiddenStateFinite = false;
    bool logitsFinite = false;
    size_t nonFiniteCount = 0;

    // Classification
    std::string failureCategory;  // empty = PASS
    std::string failureDetail;
};

// ============================================================================
// Baseline Manager — Load / save / compare
// ============================================================================
class BaselineManager {
public:
    // Load a baseline from JSON file
    static bool Load(const std::string& path, BaselineSnapshot& out);

    // Save a baseline to JSON file
    static bool Save(const std::string& path, const BaselineSnapshot& snap);

    // Compare two baselines for structural equivalence
    // Returns true if equivalent within tolerance
    static bool Compare(const BaselineSnapshot& a,
                        const BaselineSnapshot& b,
                        std::string& diffOut);

    // Compare token sequences
    static bool TokensEqual(const BaselineSnapshot& a,
                            const BaselineSnapshot& b);

    // Compare counters (exact)
    static bool CountersEqual(const BaselineSnapshot& a,
                              const BaselineSnapshot& b,
                              std::string& diffOut);

    // Compare position integrity
    static bool PositionsEqual(const BaselineSnapshot& a,
                               const BaselineSnapshot& b);

    // Generate human-readable report
    static std::string Report(const BaselineSnapshot& snap);

    // Generate diff report
    static std::string DiffReport(const BaselineSnapshot& expected,
                                   const BaselineSnapshot& actual);
};

} // namespace Deep2

#endif // VAL0517_BASELINE_FIXTURE_HPP
