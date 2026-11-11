#pragma once

/**
 * EmergentPatternDetector.hpp
 *
 * Phase C.2 Batch 1/5: Emergent Pattern Detection
 *
 * Detects harmonic attractors, behavioral clusters, and stability basins
 * from runtime telemetry history.
 */

#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <string>

namespace Emergent {

/**
 * Pattern types detected by the system
 */
enum class PatternType {
    HARMONIC_ATTRACTOR,      // Convergence points in harmonic space
    BEHAVIORAL_CLUSTER,      // Groups of similar agent behaviors
    STABILITY_BASIN,         // Regions of stable execution
    OSCILLATION_MODE,        // Periodic behavior patterns
    PHASE_TRANSITION,          // State change boundaries
    ANOMALY                  // Deviation from expected patterns
};

/**
 * Detected emergent pattern
 */
struct EmergentPattern {
    std::string patternId;
    PatternType type;
    std::string name;
    std::string description;
    
    // Temporal bounds
    int64_t firstSeenMs;
    int64_t lastSeenMs;
    int occurrenceCount;
    
    // Spatial/behavioral bounds
    std::map<std::string, double> centroid;
    std::map<std::string, double> variance;
    double confidence;
    
    // Associated data
    std::vector<std::string> relatedMetrics;
    std::map<std::string, std::string> metadata;
    
    std::string ToJson() const;
};

/**
 * Pattern detection configuration
 */
struct PatternDetectionConfig {
    // Detection thresholds
    double minConfidence = 0.75;
    int minOccurrences = 3;
    int64_t timeWindowMs = 60000;  // 1 minute
    
    // Clustering parameters
    double similarityThreshold = 0.85;
    int maxClusters = 10;
    
    // Stability detection
    double stabilityThreshold = 0.90;
    int64_t stabilityWindowMs = 30000;  // 30 seconds
    
    // Anomaly detection
    double anomalyThreshold = 2.0;  // Standard deviations
    bool enableAnomalyDetection = true;
};

/**
 * Pattern detection result
 */
struct PatternDetectionResult {
    std::vector<EmergentPattern> patterns;
    int totalSamplesAnalyzed;
    int64_t analysisDurationMs;
    std::map<PatternType, int> patternCounts;
    
    std::string ToJson() const;
    void PrintSummary() const;
};

/**
 * Telemetry sample for pattern analysis
 */
struct TelemetrySample {
    int64_t timestampMs;
    std::map<std::string, double> metrics;
    std::map<std::string, std::string> tags;
};

/**
 * Emergent Pattern Detector
 *
 * Analyzes telemetry history to identify emergent patterns
 */
class EmergentPatternDetector {
public:
    EmergentPatternDetector();
    ~EmergentPatternDetector();
    
    // Initialize with configuration
    bool Initialize(const PatternDetectionConfig& config = PatternDetectionConfig{});
    
    // Feed telemetry sample
    void FeedSample(const TelemetrySample& sample);
    void FeedSamples(const std::vector<TelemetrySample>& samples);
    
    // Run pattern detection
    PatternDetectionResult DetectPatterns();
    
    // Specific pattern detection
    std::vector<EmergentPattern> DetectHarmonicAttractors();
    std::vector<EmergentPattern> DetectBehavioralClusters();
    std::vector<EmergentPattern> DetectStabilityBasins();
    std::vector<EmergentPattern> DetectOscillationModes();
    std::vector<EmergentPattern> DetectAnomalies();
    
    // Get current patterns
    const std::vector<EmergentPattern>& GetPatterns() const { return patterns_; }
    
    // Clear patterns
    void ClearPatterns();
    
    // Export/Import
    bool SavePatterns(const std::string& path) const;
    bool LoadPatterns(const std::string& path);
    
private:
    PatternDetectionConfig config_;
    std::vector<TelemetrySample> samples_;
    std::vector<EmergentPattern> patterns_;
    
    // Detection algorithms
    std::vector<EmergentPattern> ClusterSamples(const std::vector<TelemetrySample>& samples);
    double CalculateSimilarity(const TelemetrySample& a, const TelemetrySample& b);
    std::map<std::string, double> CalculateCentroid(const std::vector<TelemetrySample>& samples);
    double CalculateStability(const std::vector<TelemetrySample>& samples);
    
    std::string GeneratePatternId() const;
};

/**
 * Pattern detection CLI
 */
class EmergentPatternDetectorCLI {
public:
    static int Run(int argc, char* argv[]);
    
private:
    static void PrintBanner();
    static void PrintUsage();
    static PatternDetectionConfig ParseArgs(int argc, char* argv[]);
};

} // namespace Emergent
