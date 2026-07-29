/**
 * @file PatternDebuggerBridge.hpp
 * @brief Bridge between ComprehensivePatternGenerator and DebuggerIntegration
 * @defensive SAW/THF-compliant
 * 
 * Provides seamless integration between pattern generation and live debugging:
 * - Real-time pattern discovery from running processes
 * - Automatic breakpoint generation from discovered patterns
 * - Pattern validation against live memory
 * - Export discovered patterns to BigDaddyG model
 */

#pragma once

#include "ComprehensivePatternGenerator.hpp"
#include "DebuggerIntegration.hpp"
#include <memory>
#include <vector>
#include <string>
#include <functional>

namespace RawrXD {
namespace Reverse {

/**
 * @brief Configuration for pattern discovery in debugger context
 */
struct PatternDiscoveryConfig {
    size_t minPatternLength = 4;           ///< Minimum bytes for a pattern
    size_t maxPatternLength = 32;          ///< Maximum bytes for a pattern
    size_t minOccurrences = 3;             ///< Minimum occurrences to be significant
    double minEntropy = 0.5;               ///< Minimum entropy threshold
    double minConfidence = 0.75;           ///< Minimum confidence for auto-breakpoints
    bool enableAutoBreakpoints = false;    ///< Auto-set breakpoints on high-confidence patterns
    bool scanExecutableOnly = true;        ///< Only scan executable regions
    uint32_t scanIntervalMs = 5000;        ///< Memory rescan interval
};

/**
 * @brief Result of pattern discovery session
 */
struct DiscoverySession {
    uint64_t timestamp;
    std::vector<Pattern> discoveredPatterns;
    std::vector<LiveAnalysisResult> liveMatches;
    size_t bytesScanned;
    size_t regionsScanned;
    double averageEntropy;
};

/**
 * @brief Callback for new pattern discoveries
 */
using PatternDiscoveryCallback = std::function<void(const Pattern&, const LiveAnalysisResult&)>;

/**
 * @brief Bridge class connecting pattern generator to debugger
 */
class PatternDebuggerBridge {
public:
    PatternDebuggerBridge();
    ~PatternDebuggerBridge();

    // Initialization
    bool initialize(std::shared_ptr<DebuggerIntegration> debugger);
    bool isInitialized() const { return debugger_ != nullptr; }

    // Configuration
    void setConfig(const PatternDiscoveryConfig& config) { config_ = config; }
    const PatternDiscoveryConfig& getConfig() const { return config_; }

    // Pattern discovery from live process
    DiscoverySession discoverPatterns(uint64_t startAddress, size_t size);
    DiscoverySession discoverPatternsInModule(const std::string& moduleName);
    DiscoverySession discoverPatternsInAllMemory();

    // Continuous monitoring
    void startContinuousDiscovery(PatternDiscoveryCallback callback);
    void stopContinuousDiscovery();
    bool isDiscovering() const { return isDiscovering_; }

    // Pattern validation
    std::vector<LiveAnalysisResult> validatePattern(const Pattern& pattern);
    double calculatePatternConfidence(const Pattern& pattern);

    // Automatic breakpoint management
    std::vector<uint32_t> setBreakpointsForPattern(const Pattern& pattern);
    void removePatternBreakpoints(const Pattern& pattern);
    void clearAllPatternBreakpoints();

    // Export discovered patterns
    std::string exportDiscoveredToBigDaddyG() const;
    bool saveDiscoveredToFile(const std::string& filepath) const;

    // Statistics
    size_t getTotalPatternsDiscovered() const { return totalPatternsDiscovered_; }
    size_t getTotalBreakpointsSet() const { return patternBreakpoints_.size(); }
    size_t getTotalMatchesFound() const { return totalMatchesFound_; }

private:
    std::shared_ptr<DebuggerIntegration> debugger_;
    std::unique_ptr<ComprehensivePatternGenerator> generator_;
    PatternDiscoveryConfig config_;
    
    std::vector<Pattern> discoveredPatterns_;
    std::vector<uint32_t> patternBreakpoints_;
    std::vector<DiscoverySession> sessions_;
    
    size_t totalPatternsDiscovered_ = 0;
    size_t totalMatchesFound_ = 0;
    bool isDiscovering_ = false;

    void onPatternDetected(const LiveAnalysisResult& result);
    bool shouldAutoBreakpoint(const Pattern& pattern) const;
};

/**
 * @brief Utility functions for pattern-debugger operations
 */
namespace PatternDebuggerUtils {

    /**
     * @brief Quick scan for common function signatures
     */
    std::vector<LiveAnalysisResult> findFunctionSignatures(
        std::shared_ptr<DebuggerIntegration> debugger,
        uint64_t startAddress,
        size_t size
    );

    /**
     * @brief Find all call instructions pointing to a specific address
     */
    std::vector<LiveAnalysisResult> findCallers(
        std::shared_ptr<DebuggerIntegration> debugger,
        uint64_t targetAddress,
        uint64_t searchStart,
        size_t searchSize
    );

    /**
     * @brief Generate pattern from function prologue at address
     */
    Pattern generatePatternFromFunction(
        std::shared_ptr<DebuggerIntegration> debugger,
        uint64_t functionAddress,
        size_t prologueLength = 16
    );

    /**
     * @brief Compare patterns between two memory regions
     */
    struct PatternComparison {
        std::vector<Pattern> commonPatterns;
        std::vector<Pattern> uniqueToA;
        std::vector<Pattern> uniqueToB;
        double similarityScore;
    };

    PatternComparison compareMemoryRegions(
        std::shared_ptr<DebuggerIntegration> debugger,
        uint64_t regionA, size_t sizeA,
        uint64_t regionB, size_t sizeB
    );

    /**
     * @brief Create watchpoint for pattern modification
     */
    bool watchPatternModification(
        std::shared_ptr<DebuggerIntegration> debugger,
        const Pattern& pattern,
        uint64_t address,
        PatternBreakpointCallback callback
    );

} // namespace PatternDebuggerUtils

} // namespace Reverse
} // namespace RawrXD
