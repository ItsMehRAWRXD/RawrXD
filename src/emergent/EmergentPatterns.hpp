// EmergentPatterns.hpp
// Phase C.1 — Emergent Pattern Detection
// Detects harmonic attractors, swarm clusters, graph motifs, and stability basins

#ifndef EMERGENT_PATTERNS_HPP
#define EMERGENT_PATTERNS_HPP

#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include "../seg/SovereignExecutionGraph.hpp"
#include "../swarm/SwarmScheduler.hpp"

namespace Emergent {

// Forward declarations
class PatternDetector;
class HarmonicAttractorAnalyzer;
class SwarmClusterDetector;
class GraphMotifDetector;
class StabilityBasinComputer;

// ============================================================================
// Pattern Types
// ============================================================================

enum class PatternType {
    HARMONIC_ATTRACTOR,      // Convergence points in harmonic space
    SWARM_CLUSTER,           // Behavioral groupings in swarm
    GRAPH_MOTIF,             // Recurring subgraph patterns
    STABILITY_BASIN,         // Regions of convergence stability
    CONVERGENCE_WAVE,        // Propagation patterns
    ROLE_EMERGENCE,          // Dynamic role formation
    INTENT_CLUSTER,          // Goal-oriented groupings
    UNKNOWN
};

// Pattern confidence level
enum class ConfidenceLevel {
    LOW = 1,      // 0-33%
    MEDIUM = 2,   // 33-66%
    HIGH = 3,     // 66-90%
    CERTAIN = 4   // 90-100%
};

// ============================================================================
// Core Data Structures
// ============================================================================

struct PatternSignature {
    std::string id;
    PatternType type;
    double confidence;
    std::vector<uint64_t> node_ids;
    std::map<std::string, double> metrics;
    std::chrono::steady_clock::time_point detection_time;
    uint32_t occurrence_count;
    
    PatternSignature() : type(PatternType::UNKNOWN), confidence(0.0), occurrence_count(0) {}
};

struct HarmonicAttractor {
    std::string id;
    double frequency;
    double amplitude;
    double phase;
    std::vector<uint32_t> cycle_ids;
    double convergence_rate;
    double stability_score;
    
    bool IsStable() const { return stability_score > 0.8; }
};

struct SwarmCluster {
    std::string id;
    std::vector<uint32_t> agent_ids;
    std::vector<uint32_t> task_preferences;
    double cohesion_score;
    double performance_score;
    std::chrono::steady_clock::time_point formation_time;
    
    bool IsCohesive() const { return cohesion_score > 0.7; }
};

struct GraphMotif {
    std::string id;
    std::string pattern_hash;
    std::vector<std::string> node_types;
    std::vector<std::pair<std::string, std::string>> edge_types;
    uint32_t frequency;
    double significance_score;
};

struct StabilityBasin {
    std::string id;
    std::vector<uint64_t> boundary_nodes;
    double basin_volume;
    double attractor_strength;
    double escape_probability;
    std::map<std::string, double> local_metrics;
};

// ============================================================================
// Detection Results
// ============================================================================

struct EmergentPatternReport {
    std::chrono::steady_clock::time_point timestamp;
    
    // Detected patterns
    std::vector<HarmonicAttractor> harmonic_attractors;
    std::vector<SwarmCluster> swarm_clusters;
    std::vector<GraphMotif> graph_motifs;
    std::vector<StabilityBasin> stability_basins;
    
    // Summary metrics
    uint32_t total_patterns_detected;
    double average_confidence;
    double system_entropy;
    double emergence_score;
    
    // Temporal analysis
    std::map<std::string, uint32_t> pattern_evolution;
    double stability_trend;
    
    EmergentPatternReport() : total_patterns_detected(0), average_confidence(0.0),
        system_entropy(0.0), emergence_score(0.0), stability_trend(0.0) {}
};

// ============================================================================
// Configuration
// ============================================================================

struct PatternDetectionConfig {
    // Detection thresholds
    double harmonic_attractor_threshold = 0.75;
    double swarm_cluster_threshold = 0.6;
    double graph_motif_threshold = 0.5;
    double stability_basin_threshold = 0.8;
    
    // Temporal settings
    std::chrono::milliseconds detection_window{5000};
    std::chrono::milliseconds min_pattern_lifetime{1000};
    
    // Sampling
    uint32_t sample_size = 1000;
    double sampling_rate = 1.0;
    
    // Analysis depth
    uint32_t max_motif_size = 5;
    uint32_t max_clusters = 10;
    uint32_t history_depth = 10;
};

// ============================================================================
// Main Pattern Detector Interface
// ============================================================================

class EmergentPatternDetector {
public:
    EmergentPatternDetector(const PatternDetectionConfig& config = PatternDetectionConfig{});
    ~EmergentPatternDetector();
    
    // Core detection API
    EmergentPatternReport DetectPatterns(const SEG::SovereignExecutionGraph& graph);
    EmergentPatternReport DetectPatterns(const Swarm::SwarmScheduler& scheduler);
    
    // Incremental detection (streaming)
    void FeedGraphState(const SEG::SovereignExecutionGraph& graph);
    void FeedSwarmState(const Swarm::SwarmScheduler& scheduler);
    EmergentPatternReport GetCurrentReport() const;
    
    // Specific pattern detection
    std::vector<HarmonicAttractor> DetectHarmonicAttractors(const SEG::SovereignExecutionGraph& graph);
    std::vector<SwarmCluster> DetectSwarmClusters(const Swarm::SwarmScheduler& scheduler);
    std::vector<GraphMotif> DetectGraphMotifs(const SEG::SovereignExecutionGraph& graph);
    std::vector<StabilityBasin> DetectStabilityBasins(const SEG::SovereignExecutionGraph& graph);
    
    // Pattern evolution tracking
    std::vector<PatternSignature> GetPatternEvolution(const std::string& pattern_id) const;
    double CalculatePatternStability(const std::string& pattern_id) const;
    
    // System-level metrics
    double CalculateSystemEntropy() const;
    double CalculateEmergenceScore() const;
    double CalculateConvergenceRate() const;
    
    // Configuration
    void SetConfig(const PatternDetectionConfig& config);
    PatternDetectionConfig GetConfig() const;
    
    // Reset
    void Reset();
    void ClearHistory();
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// Specialized Detectors
// ============================================================================

class HarmonicAttractorAnalyzer {
public:
    HarmonicAttractorAnalyzer(double threshold = 0.75);
    
    std::vector<HarmonicAttractor> Analyze(const SEG::SovereignExecutionGraph& graph);
    std::vector<HarmonicAttractor> AnalyzeCycles(const std::vector<uint32_t>& cycle_ids,
                                                   const std::vector<double>& convergence_rates);
    
    double CalculateResonance(const HarmonicAttractor& a1, const HarmonicAttractor& a2) const;
    double PredictConvergence(const HarmonicAttractor& attractor, uint32_t iterations) const;
    
private:
    double threshold_;
};

class SwarmClusterDetector {
public:
    SwarmClusterDetector(double cohesion_threshold = 0.6, uint32_t max_clusters = 10);
    
    std::vector<SwarmCluster> DetectClusters(const Swarm::SwarmScheduler& scheduler);
    std::vector<SwarmCluster> DetectBehavioralClusters(const std::vector<Swarm::AgentState>& agents);
    
    double CalculateCohesion(const SwarmCluster& cluster) const;
    double CalculatePerformance(const SwarmCluster& cluster) const;
    
    SwarmCluster MergeClusters(const SwarmCluster& c1, const SwarmCluster& c2) const;
    bool ShouldSplitCluster(const SwarmCluster& cluster) const;
    
private:
    double cohesion_threshold_;
    uint32_t max_clusters_;
};

class GraphMotifDetector {
public:
    GraphMotifDetector(uint32_t max_motif_size = 5, double significance_threshold = 0.5);
    
    std::vector<GraphMotif> DetectMotifs(const SEG::SovereignExecutionGraph& graph);
    std::vector<GraphMotif> FindFrequentSubgraphs(const SEG::SovereignExecutionGraph& graph,
                                                     uint32_t min_frequency);
    
    std::string ComputePatternHash(const std::vector<std::string>& node_types,
                                   const std::vector<std::pair<std::string, std::string>>& edges) const;
    double CalculateSignificance(const GraphMotif& motif, const SEG::SovereignExecutionGraph& graph) const;
    
private:
    uint32_t max_motif_size_;
    double significance_threshold_;
};

class StabilityBasinComputer {
public:
    StabilityBasinComputer(double stability_threshold = 0.8);
    
    std::vector<StabilityBasin> ComputeBasins(const SEG::SovereignExecutionGraph& graph);
    std::vector<StabilityBasin> ComputeFromAttractors(const std::vector<HarmonicAttractor>& attractors,
                                                       const SEG::SovereignExecutionGraph& graph);
    
    double CalculateBasinVolume(const StabilityBasin& basin) const;
    double CalculateEscapeProbability(const StabilityBasin& basin, uint64_t node_id) const;
    double CalculateLocalStability(const StabilityBasin& basin) const;
    
private:
    double stability_threshold_;
};

// ============================================================================
// Pattern Evolution Tracker
// ============================================================================

class PatternEvolutionTracker {
public:
    PatternEvolutionTracker(uint32_t history_depth = 10);
    
    void RecordPattern(const PatternSignature& pattern);
    void RecordPatternState(const std::string& pattern_id, double confidence, 
                            const std::map<std::string, double>& metrics);
    
    std::vector<PatternSignature> GetEvolution(const std::string& pattern_id) const;
    double CalculateStability(const std::string& pattern_id) const;
    double CalculateTrend(const std::string& pattern_id) const;
    
    std::vector<std::string> GetEmergingPatterns() const;
    std::vector<std::string> GetDissolvingPatterns() const;
    std::vector<std::string> GetStablePatterns() const;
    
    void ClearHistory();
    
private:
    uint32_t history_depth_;
    mutable std::mutex mutex_;
    std::map<std::string, std::vector<PatternSignature>> pattern_history_;
};

// ============================================================================
// Utility Functions
// ============================================================================

namespace Utils {
    // Statistical utilities
    double CalculateEntropy(const std::vector<double>& probabilities);
    double CalculateMutualInformation(const std::vector<double>& x, const std::vector<double>& y);
    double CalculateCorrelation(const std::vector<double>& x, const std::vector<double>& y);
    
    // Clustering utilities
    std::vector<std::vector<size_t>> KMeans(const std::vector<std::vector<double>>& points, 
                                             uint32_t k, uint32_t max_iterations = 100);
    std::vector<std::vector<size_t>> DBSCAN(const std::vector<std::vector<double>>& points,
                                               double eps, uint32_t min_points);
    
    // Graph utilities
    std::vector<std::vector<uint64_t>> FindConnectedComponents(const SEG::SovereignExecutionGraph& graph);
    std::vector<std::vector<uint64_t>> FindCliques(const SEG::SovereignExecutionGraph& graph, uint32_t min_size);
    double CalculateGraphDensity(const SEG::SovereignExecutionGraph& graph);
    double CalculateClusteringCoefficient(const SEG::SovereignExecutionGraph& graph);
}

// ============================================================================
// Integration with SEG
// ============================================================================

class SEGPatternIntegration {
public:
    static void AttachPatternDetector(SEG::SovereignExecutionGraph& graph,
                                      EmergentPatternDetector& detector);
    static void DetachPatternDetector(SEG::SovereignExecutionGraph& graph);
    
    static EmergentPatternReport GeneratePatternReport(const SEG::SovereignExecutionGraph& graph);
    static void ExportPatternTelemetry(const EmergentPatternReport& report, 
                                       const std::string& output_path);
};

} // namespace Emergent

#endif // EMERGENT_PATTERNS_HPP
