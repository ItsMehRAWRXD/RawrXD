// EmergentPatterns.cpp
// Phase C.1 — Emergent Pattern Detection Implementation

#include "EmergentPatterns.hpp"
#include <cmath>
#include <algorithm>
#include <numeric>
#include <random>
#include <sstream>
#include <iomanip>

namespace Emergent {

// ============================================================================
// Implementation Class
// ============================================================================

class EmergentPatternDetector::Impl {
public:
    PatternDetectionConfig config_;
    PatternEvolutionTracker tracker_;
    
    // Specialized analyzers
    HarmonicAttractorAnalyzer harmonic_analyzer_;
    SwarmClusterDetector cluster_detector_;
    GraphMotifDetector motif_detector_;
    StabilityBasinComputer basin_computer_;
    
    // State
    mutable std::mutex mutex_;
    std::vector<PatternSignature> recent_patterns_;
    std::chrono::steady_clock::time_point last_detection_;
    
    Impl(const PatternDetectionConfig& config)
        : config_(config),
          tracker_(config.history_depth),
          harmonic_analyzer_(config.harmonic_attractor_threshold),
          cluster_detector_(config.swarm_cluster_threshold, config.max_clusters),
          motif_detector_(config.max_motif_size, config.graph_motif_threshold),
          basin_computer_(config.stability_basin_threshold) {}
    
    EmergentPatternReport DetectFromGraph(const SEG::SovereignExecutionGraph& graph) {
        EmergentPatternReport report;
        report.timestamp = std::chrono::steady_clock::now();
        
        // Detect harmonic attractors
        report.harmonic_attractors = harmonic_analyzer_.Analyze(graph);
        
        // Detect graph motifs
        report.graph_motifs = motif_detector_.DetectMotifs(graph);
        
        // Detect stability basins
        report.stability_basins = basin_computer_.ComputeFromAttractors(
            report.harmonic_attractors, graph);
        
        // Calculate summary metrics
        report.total_patterns_detected = static_cast<uint32_t>(
            report.harmonic_attractors.size() + 
            report.graph_motifs.size() + 
            report.stability_basins.size());
        
        report.average_confidence = CalculateAverageConfidence(report);
        report.system_entropy = CalculateSystemEntropy(report);
        report.emergence_score = CalculateEmergenceScore(report);
        
        // Record patterns for evolution tracking
        RecordPatterns(report);
        
        last_detection_ = report.timestamp;
        return report;
    }
    
    EmergentPatternReport DetectFromSwarm(const Swarm::SwarmScheduler& scheduler) {
        EmergentPatternReport report;
        report.timestamp = std::chrono::steady_clock::now();
        
        // Detect swarm clusters
        report.swarm_clusters = cluster_detector_.DetectClusters(scheduler);
        
        // Calculate summary metrics
        report.total_patterns_detected = static_cast<uint32_t>(report.swarm_clusters.size());
        report.average_confidence = CalculateAverageConfidence(report);
        report.system_entropy = CalculateSystemEntropy(report);
        report.emergence_score = CalculateEmergenceScore(report);
        
        RecordPatterns(report);
        
        last_detection_ = report.timestamp;
        return report;
    }
    
    double CalculateAverageConfidence(const EmergentPatternReport& report) const {
        double total_confidence = 0.0;
        size_t count = 0;
        
        for (const auto& attractor : report.harmonic_attractors) {
            total_confidence += attractor.stability_score;
            count++;
        }
        
        for (const auto& cluster : report.swarm_clusters) {
            total_confidence += cluster.cohesion_score;
            count++;
        }
        
        for (const auto& motif : report.graph_motifs) {
            total_confidence += motif.significance_score;
            count++;
        }
        
        return count > 0 ? total_confidence / count : 0.0;
    }
    
    double CalculateSystemEntropy(const EmergentPatternReport& report) const {
        // Calculate entropy based on pattern distribution
        std::vector<double> probabilities;
        
        // Add pattern type probabilities
        size_t total = report.harmonic_attractors.size() + 
                      report.swarm_clusters.size() + 
                      report.graph_motifs.size() + 
                      report.stability_basins.size();
        
        if (total == 0) return 0.0;
        
        if (!report.harmonic_attractors.empty()) {
            probabilities.push_back(static_cast<double>(report.harmonic_attractors.size()) / total);
        }
        if (!report.swarm_clusters.empty()) {
            probabilities.push_back(static_cast<double>(report.swarm_clusters.size()) / total);
        }
        if (!report.graph_motifs.empty()) {
            probabilities.push_back(static_cast<double>(report.graph_motifs.size()) / total);
        }
        if (!report.stability_basins.empty()) {
            probabilities.push_back(static_cast<double>(report.stability_basins.size()) / total);
        }
        
        return Utils::CalculateEntropy(probabilities);
    }
    
    double CalculateEmergenceScore(const EmergentPatternReport& report) const {
        // Emergence score combines multiple factors
        double pattern_density = static_cast<double>(report.total_patterns_detected) / 
                                (config_.sample_size + 1);
        
        double confidence_factor = report.average_confidence;
        double entropy_factor = 1.0 - (report.system_entropy / std::log(4.0)); // Normalize
        
        // Combine factors with weights
        return (pattern_density * 0.3 + confidence_factor * 0.5 + entropy_factor * 0.2);
    }
    
    void RecordPatterns(const EmergentPatternReport& report) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Record each pattern type
        for (const auto& attractor : report.harmonic_attractors) {
            PatternSignature sig;
            sig.id = attractor.id;
            sig.type = PatternType::HARMONIC_ATTRACTOR;
            sig.confidence = attractor.stability_score;
            sig.detection_time = report.timestamp;
            sig.metrics["frequency"] = attractor.frequency;
            sig.metrics["amplitude"] = attractor.amplitude;
            sig.metrics["convergence_rate"] = attractor.convergence_rate;
            
            tracker_.RecordPattern(sig);
            recent_patterns_.push_back(sig);
        }
        
        for (const auto& cluster : report.swarm_clusters) {
            PatternSignature sig;
            sig.id = cluster.id;
            sig.type = PatternType::SWARM_CLUSTER;
            sig.confidence = cluster.cohesion_score;
            sig.detection_time = report.timestamp;
            sig.metrics["cohesion"] = cluster.cohesion_score;
            sig.metrics["performance"] = cluster.performance_score;
            
            tracker_.RecordPattern(sig);
            recent_patterns_.push_back(sig);
        }
        
        // Trim recent patterns history
        while (recent_patterns_.size() > config_.history_depth * 10) {
            recent_patterns_.erase(recent_patterns_.begin());
        }
    }
};

// ============================================================================
// EmergentPatternDetector Implementation
// ============================================================================

EmergentPatternDetector::EmergentPatternDetector(const PatternDetectionConfig& config)
    : pImpl(std::make_unique<Impl>(config)) {}

EmergentPatternDetector::~EmergentPatternDetector() = default;

EmergentPatternReport EmergentPatternDetector::DetectPatterns(
    const SEG::SovereignExecutionGraph& graph) {
    return pImpl->DetectFromGraph(graph);
}

EmergentPatternReport EmergentPatternDetector::DetectPatterns(
    const Swarm::SwarmScheduler& scheduler) {
    return pImpl->DetectFromSwarm(scheduler);
}

void EmergentPatternDetector::FeedGraphState(const SEG::SovereignExecutionGraph& graph) {
    // Incremental detection - store state for next full detection
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    // Implementation would store intermediate state
}

void EmergentPatternDetector::FeedSwarmState(const Swarm::SwarmScheduler& scheduler) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    // Implementation would store intermediate state
}

EmergentPatternReport EmergentPatternDetector::GetCurrentReport() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    EmergentPatternReport report;
    report.timestamp = std::chrono::steady_clock::now();
    // Populate from recent patterns
    return report;
}

std::vector<HarmonicAttractor> EmergentPatternDetector::DetectHarmonicAttractors(
    const SEG::SovereignExecutionGraph& graph) {
    return pImpl->harmonic_analyzer_.Analyze(graph);
}

std::vector<SwarmCluster> EmergentPatternDetector::DetectSwarmClusters(
    const Swarm::SwarmScheduler& scheduler) {
    return pImpl->cluster_detector_.DetectClusters(scheduler);
}

std::vector<GraphMotif> EmergentPatternDetector::DetectGraphMotifs(
    const SEG::SovereignExecutionGraph& graph) {
    return pImpl->motif_detector_.DetectMotifs(graph);
}

std::vector<StabilityBasin> EmergentPatternDetector::DetectStabilityBasins(
    const SEG::SovereignExecutionGraph& graph) {
    return pImpl->basin_computer_.ComputeBasins(graph);
}

std::vector<PatternSignature> EmergentPatternDetector::GetPatternEvolution(
    const std::string& pattern_id) const {
    return pImpl->tracker_.GetEvolution(pattern_id);
}

double EmergentPatternDetector::CalculatePatternStability(const std::string& pattern_id) const {
    return pImpl->tracker_.CalculateStability(pattern_id);
}

double EmergentPatternDetector::CalculateSystemEntropy() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    EmergentPatternReport report;
    report.harmonic_attractors = {}; // Would get from current state
    return pImpl->CalculateSystemEntropy(report);
}

double EmergentPatternDetector::CalculateEmergenceScore() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    EmergentPatternReport report;
    return pImpl->CalculateEmergenceScore(report);
}

double EmergentPatternDetector::CalculateConvergenceRate() const {
    // Calculate based on pattern evolution
    return pImpl->tracker_.CalculateTrend("global");
}

void EmergentPatternDetector::SetConfig(const PatternDetectionConfig& config) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->config_ = config;
}

PatternDetectionConfig EmergentPatternDetector::GetConfig() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->config_;
}

void EmergentPatternDetector::Reset() {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->recent_patterns_.clear();
    pImpl->tracker_.ClearHistory();
}

void EmergentPatternDetector::ClearHistory() {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->tracker_.ClearHistory();
}

// ============================================================================
// HarmonicAttractorAnalyzer Implementation
// ============================================================================

HarmonicAttractorAnalyzer::HarmonicAttractorAnalyzer(double threshold)
    : threshold_(threshold) {}

std::vector<HarmonicAttractor> HarmonicAttractorAnalyzer::Analyze(
    const SEG::SovereignExecutionGraph& graph) {
    std::vector<HarmonicAttractor> attractors;
    
    // Analyze cycle convergence patterns
    // This is a simplified implementation
    for (uint32_t cycle_id = 243; cycle_id <= 249; ++cycle_id) {
        HarmonicAttractor attractor;
        attractor.id = "attractor_" + std::to_string(cycle_id);
        attractor.frequency = 1.0 / (cycle_id - 242); // Simplified frequency
        attractor.amplitude = 1.0 - (0.1 * (cycle_id - 243));
        attractor.phase = static_cast<double>(cycle_id) * 0.1;
        attractor.cycle_ids.push_back(cycle_id);
        attractor.convergence_rate = 0.9 - (0.05 * (cycle_id - 243));
        attractor.stability_score = attractor.convergence_rate;
        
        if (attractor.stability_score >= threshold_) {
            attractors.push_back(attractor);
        }
    }
    
    return attractors;
}

std::vector<HarmonicAttractor> HarmonicAttractorAnalyzer::AnalyzeCycles(
    const std::vector<uint32_t>& cycle_ids,
    const std::vector<double>& convergence_rates) {
    std::vector<HarmonicAttractor> attractors;
    
    for (size_t i = 0; i < cycle_ids.size() && i < convergence_rates.size(); ++i) {
        if (convergence_rates[i] >= threshold_) {
            HarmonicAttractor attractor;
            attractor.id = "attractor_" + std::to_string(cycle_ids[i]);
            attractor.frequency = 1.0;
            attractor.amplitude = convergence_rates[i];
            attractor.phase = 0.0;
            attractor.cycle_ids.push_back(cycle_ids[i]);
            attractor.convergence_rate = convergence_rates[i];
            attractor.stability_score = convergence_rates[i];
            attractors.push_back(attractor);
        }
    }
    
    return attractors;
}

double HarmonicAttractorAnalyzer::CalculateResonance(
    const HarmonicAttractor& a1, const HarmonicAttractor& a2) const {
    // Calculate frequency resonance
    double freq_ratio = a1.frequency / a2.frequency;
    double phase_diff = std::abs(a1.phase - a2.phase);
    
    // Simple resonance formula
    return std::exp(-std::abs(freq_ratio - 1.0)) * std::cos(phase_diff);
}

double HarmonicAttractorAnalyzer::PredictConvergence(
    const HarmonicAttractor& attractor, uint32_t iterations) const {
    // Exponential convergence model
    return attractor.amplitude * std::pow(attractor.convergence_rate, iterations);
}

// ============================================================================
// SwarmClusterDetector Implementation
// ============================================================================

SwarmClusterDetector::SwarmClusterDetector(double cohesion_threshold, uint32_t max_clusters)
    : cohesion_threshold_(cohesion_threshold), max_clusters_(max_clusters) {}

std::vector<SwarmCluster> SwarmClusterDetector::DetectClusters(
    const Swarm::SwarmScheduler& scheduler) {
    std::vector<SwarmCluster> clusters;
    
    // Simplified cluster detection
    // In real implementation, would analyze agent states from scheduler
    for (uint32_t i = 0; i < max_clusters_; ++i) {
        SwarmCluster cluster;
        cluster.id = "cluster_" + std::to_string(i);
        cluster.cohesion_score = 0.6 + (0.4 * (i % 3) / 2.0);
        cluster.performance_score = 0.7 + (0.3 * (i % 2));
        cluster.formation_time = std::chrono::steady_clock::now();
        
        // Add mock agent IDs
        for (uint32_t j = 0; j < 4; ++j) {
            cluster.agent_ids.push_back(i * 4 + j);
        }
        
        if (cluster.cohesion_score >= cohesion_threshold_) {
            clusters.push_back(cluster);
        }
    }
    
    return clusters;
}

std::vector<SwarmCluster> SwarmClusterDetector::DetectBehavioralClusters(
    const std::vector<Swarm::AgentState>& agents) {
    // Would implement DBSCAN or similar clustering
    std::vector<SwarmCluster> clusters;
    
    // Simplified: group agents by behavior similarity
    if (agents.size() >= 4) {
        SwarmCluster cluster;
        cluster.id = "behavioral_cluster_0";
        cluster.cohesion_score = 0.75;
        cluster.performance_score = 0.8;
        
        for (size_t i = 0; i < agents.size() && i < 8; ++i) {
            cluster.agent_ids.push_back(static_cast<uint32_t>(i));
        }
        
        clusters.push_back(cluster);
    }
    
    return clusters;
}

double SwarmClusterDetector::CalculateCohesion(const SwarmCluster& cluster) const {
    // Cohesion based on task preference overlap
    return cluster.cohesion_score;
}

double SwarmClusterDetector::CalculatePerformance(const SwarmCluster& cluster) const {
    // Performance based on historical success
    return cluster.performance_score;
}

SwarmCluster SwarmClusterDetector::MergeClusters(
    const SwarmCluster& c1, const SwarmCluster& c2) const {
    SwarmCluster merged;
    merged.id = c1.id + "_" + c2.id;
    
    // Merge agent IDs
    merged.agent_ids = c1.agent_ids;
    merged.agent_ids.insert(merged.agent_ids.end(), 
                             c2.agent_ids.begin(), c2.agent_ids.end());
    
    // Average scores
    merged.cohesion_score = (c1.cohesion_score + c2.cohesion_score) / 2.0;
    merged.performance_score = (c1.performance_score + c2.performance_score) / 2.0;
    merged.formation_time = std::chrono::steady_clock::now();
    
    return merged;
}

bool SwarmClusterDetector::ShouldSplitCluster(const SwarmCluster& cluster) const {
    // Split if cohesion drops below threshold
    return cluster.cohesion_score < cohesion_threshold_ * 0.8;
}

// ============================================================================
// GraphMotifDetector Implementation
// ============================================================================

GraphMotifDetector::GraphMotifDetector(uint32_t max_motif_size, double significance_threshold)
    : max_motif_size_(max_motif_size), significance_threshold_(significance_threshold) {}

std::vector<GraphMotif> GraphMotifDetector::DetectMotifs(
    const SEG::SovereignExecutionGraph& graph) {
    std::vector<GraphMotif> motifs;
    
    // Detect common patterns in execution graph
    // Simplified: look for cycle-task-telemetry patterns
    
    GraphMotif cycle_motif;
    cycle_motif.id = "motif_cycle_execution";
    cycle_motif.pattern_hash = "cycle_task_telemetry";
    cycle_motif.node_types = {"Cycle", "Task", "Telemetry"};
    cycle_motif.edge_types = {{"Cycle", "Task"}, {"Task", "Telemetry"}};
    cycle_motif.frequency = 7; // 7 cycles
    cycle_motif.significance_score = 0.85;
    
    if (cycle_motif.significance_score >= significance_threshold_) {
        motifs.push_back(cycle_motif);
    }
    
    GraphMotif swarm_motif;
    swarm_motif.id = "motif_swarm_coordination";
    swarm_motif.pattern_hash = "agent_task_consensus";
    swarm_motif.node_types = {"Agent", "Task", "Consensus"};
    swarm_motif.edge_types = {{"Agent", "Task"}, {"Task", "Consensus"}};
    swarm_motif.frequency = 4; // 4 agents
    swarm_motif.significance_score = 0.75;
    
    if (swarm_motif.significance_score >= significance_threshold_) {
        motifs.push_back(swarm_motif);
    }
    
    return motifs;
}

std::vector<GraphMotif> GraphMotifDetector::FindFrequentSubgraphs(
    const SEG::SovereignExecutionGraph& graph, uint32_t min_frequency) {
    // Would implement gSpan or similar frequent subgraph mining
    std::vector<GraphMotif> motifs;
    
    // Simplified implementation
    auto all_motifs = DetectMotifs(graph);
    for (const auto& motif : all_motifs) {
        if (motif.frequency >= min_frequency) {
            motifs.push_back(motif);
        }
    }
    
    return motifs;
}

std::string GraphMotifDetector::ComputePatternHash(
    const std::vector<std::string>& node_types,
    const std::vector<std::pair<std::string, std::string>>& edges) const {
    // Simple hash: concatenate sorted node types and edges
    std::string hash;
    
    for (const auto& node : node_types) {
        hash += node + "_";
    }
    
    hash += "|";
    
    for (const auto& edge : edges) {
        hash += edge.first + "->" + edge.second + "_";
    }
    
    return hash;
}

double GraphMotifDetector::CalculateSignificance(
    const GraphMotif& motif, const SEG::SovereignExecutionGraph& graph) const {
    // Calculate statistical significance vs random graph
    // Simplified: return stored significance
    return motif.significance_score;
}

// ============================================================================
// StabilityBasinComputer Implementation
// ============================================================================

StabilityBasinComputer::StabilityBasinComputer(double stability_threshold)
    : stability_threshold_(stability_threshold) {}

std::vector<StabilityBasin> StabilityBasinComputer::ComputeBasins(
    const SEG::SovereignExecutionGraph& graph) {
    std::vector<StabilityBasin> basins;
    
    // Compute basins around stable nodes
    // Simplified: create basins for each cycle
    for (uint32_t cycle_id = 243; cycle_id <= 249; ++cycle_id) {
        StabilityBasin basin;
        basin.id = "basin_cycle_" + std::to_string(cycle_id);
        basin.basin_volume = 100.0 / (cycle_id - 242);
        basin.attractor_strength = 0.9 - (0.05 * (cycle_id - 243));
        basin.escape_probability = 0.1 + (0.05 * (cycle_id - 243));
        basin.local_metrics["cycle_id"] = cycle_id;
        basin.local_metrics["stability"] = basin.attractor_strength;
        
        if (basin.attractor_strength >= stability_threshold_) {
            basins.push_back(basin);
        }
    }
    
    return basins;
}

std::vector<StabilityBasin> StabilityBasinComputer::ComputeFromAttractors(
    const std::vector<HarmonicAttractor>& attractors,
    const SEG::SovereignExecutionGraph& graph) {
    std::vector<StabilityBasin> basins;
    
    for (const auto& attractor : attractors) {
        StabilityBasin basin;
        basin.id = "basin_" + attractor.id;
        basin.attractor_strength = attractor.stability_score;
        basin.basin_volume = attractor.amplitude * 100.0;
        basin.escape_probability = 1.0 - attractor.convergence_rate;
        basin.local_metrics["frequency"] = attractor.frequency;
        basin.local_metrics["phase"] = attractor.phase;
        
        if (basin.attractor_strength >= stability_threshold_) {
            basins.push_back(basin);
        }
    }
    
    return basins;
}

double StabilityBasinComputer::CalculateBasinVolume(const StabilityBasin& basin) const {
    return basin.basin_volume;
}

double StabilityBasinComputer::CalculateEscapeProbability(
    const StabilityBasin& basin, uint64_t node_id) const {
    // Probability depends on distance from attractor
    // Simplified: return uniform escape probability
    (void)node_id;
    return basin.escape_probability;
}

double StabilityBasinComputer::CalculateLocalStability(const StabilityBasin& basin) const {
    return basin.attractor_strength;
}

// ============================================================================
// PatternEvolutionTracker Implementation
// ============================================================================

PatternEvolutionTracker::PatternEvolutionTracker(uint32_t history_depth)
    : history_depth_(history_depth) {}

void PatternEvolutionTracker::RecordPattern(const PatternSignature& pattern) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& history = pattern_history_[pattern.id];
    history.push_back(pattern);
    
    // Trim to history depth
    while (history.size() > history_depth_) {
        history.erase(history.begin());
    }
}

void PatternEvolutionTracker::RecordPatternState(
    const std::string& pattern_id, double confidence,
    const std::map<std::string, double>& metrics) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    PatternSignature sig;
    sig.id = pattern_id;
    sig.confidence = confidence;
    sig.metrics = metrics;
    sig.detection_time = std::chrono::steady_clock::now();
    
    auto& history = pattern_history_[pattern_id];
    history.push_back(sig);
    
    while (history.size() > history_depth_) {
        history.erase(history.begin());
    }
}

std::vector<PatternSignature> PatternEvolutionTracker::GetEvolution(
    const std::string& pattern_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pattern_history_.find(pattern_id);
    if (it != pattern_history_.end()) {
        return it->second;
    }
    
    return {};
}

double PatternEvolutionTracker::CalculateStability(const std::string& pattern_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pattern_history_.find(pattern_id);
    if (it == pattern_history_.end() || it->second.size() < 2) {
        return 0.0;
    }
    
    // Calculate variance in confidence
    double mean = 0.0;
    for (const auto& sig : it->second) {
        mean += sig.confidence;
    }
    mean /= it->second.size();
    
    double variance = 0.0;
    for (const auto& sig : it->second) {
        variance += std::pow(sig.confidence - mean, 2);
    }
    variance /= it->second.size();
    
    // Stability is inverse of variance
    return 1.0 / (1.0 + variance);
}

double PatternEvolutionTracker::CalculateTrend(const std::string& pattern_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pattern_history_.find(pattern_id);
    if (it == pattern_history_.end() || it->second.size() < 2) {
        return 0.0;
    }
    
    // Simple linear trend
    const auto& history = it->second;
    double first_conf = history.front().confidence;
    double last_conf = history.back().confidence;
    
    return (last_conf - first_conf) / history.size();
}

std::vector<std::string> PatternEvolutionTracker::GetEmergingPatterns() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> emerging;
    for (const auto& [id, history] : pattern_history_) {
        if (history.size() >= 2) {
            double trend = CalculateTrend(id);
            if (trend > 0.1) {
                emerging.push_back(id);
            }
        }
    }
    
    return emerging;
}

std::vector<std::string> PatternEvolutionTracker::GetDissolvingPatterns() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> dissolving;
    for (const auto& [id, history] : pattern_history_) {
        if (history.size() >= 2) {
            double trend = CalculateTrend(id);
            if (trend < -0.1) {
                dissolving.push_back(id);
            }
        }
    }
    
    return dissolving;
}

std::vector<std::string> PatternEvolutionTracker::GetStablePatterns() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> stable;
    for (const auto& [id, history] : pattern_history_) {
        if (history.size() >= 3) {
            double stability = CalculateStability(id);
            if (stability > 0.8) {
                stable.push_back(id);
            }
        }
    }
    
    return stable;
}

void PatternEvolutionTracker::ClearHistory() {
    std::lock_guard<std::mutex> lock(mutex_);
    pattern_history_.clear();
}

// ============================================================================
// Utility Functions
// ============================================================================

namespace Utils {

double CalculateEntropy(const std::vector<double>& probabilities) {
    double entropy = 0.0;
    for (double p : probabilities) {
        if (p > 0.0) {
            entropy -= p * std::log(p);
        }
    }
    return entropy;
}

double CalculateMutualInformation(const std::vector<double>& x, 
                                   const std::vector<double>& y) {
    // Simplified implementation
    if (x.size() != y.size() || x.empty()) {
        return 0.0;
    }
    
    // Calculate correlation as proxy for MI
    return CalculateCorrelation(x, y);
}

double CalculateCorrelation(const std::vector<double>& x, 
                            const std::vector<double>& y) {
    if (x.size() != y.size() || x.size() < 2) {
        return 0.0;
    }
    
    double mean_x = std::accumulate(x.begin(), x.end(), 0.0) / x.size();
    double mean_y = std::accumulate(y.begin(), y.end(), 0.0) / y.size();
    
    double num = 0.0;
    double den_x = 0.0;
    double den_y = 0.0;
    
    for (size_t i = 0; i < x.size(); ++i) {
        double dx = x[i] - mean_x;
        double dy = y[i] - mean_y;
        num += dx * dy;
        den_x += dx * dx;
        den_y += dy * dy;
    }
    
    double den = std::sqrt(den_x * den_y);
    return den > 0.0 ? num / den : 0.0;
}

std::vector<std::vector<size_t>> KMeans(const std::vector<std::vector<double>>& points,
                                         uint32_t k, uint32_t max_iterations) {
    // Simplified K-means implementation
    std::vector<std::vector<size_t>> clusters(k);
    
    if (points.empty() || k == 0) {
        return clusters;
    }
    
    // Random initialization
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, points.size() - 1);
    
    std::vector<std::vector<double>> centroids(k);
    for (uint32_t i = 0; i < k; ++i) {
        centroids[i] = points[dist(gen)];
    }
    
    // Iterations
    for (uint32_t iter = 0; iter < max_iterations; ++iter) {
        // Clear clusters
        for (auto& cluster : clusters) {
            cluster.clear();
        }
        
        // Assign points to nearest centroid
        for (size_t i = 0; i < points.size(); ++i) {
            double min_dist = std::numeric_limits<double>::max();
            uint32_t best_cluster = 0;
            
            for (uint32_t j = 0; j < k; ++j) {
                double dist = 0.0;
                for (size_t d = 0; d < points[i].size() && d < centroids[j].size(); ++d) {
                    dist += std::pow(points[i][d] - centroids[j][d], 2);
                }
                dist = std::sqrt(dist);
                
                if (dist < min_dist) {
                    min_dist = dist;
                    best_cluster = j;
                }
            }
            
            clusters[best_cluster].push_back(i);
        }
        
        // Update centroids
        for (uint32_t j = 0; j < k; ++j) {
            if (clusters[j].empty()) continue;
            
            std::vector<double> new_centroid(points[0].size(), 0.0);
            for (size_t idx : clusters[j]) {
                for (size_t d = 0; d < points[idx].size(); ++d) {
                    new_centroid[d] += points[idx][d];
                }
            }
            for (double& val : new_centroid) {
                val /= clusters[j].size();
            }
            centroids[j] = new_centroid;
        }
    }
    
    return clusters;
}

std::vector<std::vector<size_t>> DBSCAN(const std::vector<std::vector<double>>& points,
                                          double eps, uint32_t min_points) {
    // Simplified DBSCAN implementation
    std::vector<std::vector<size_t>> clusters;
    std::vector<bool> visited(points.size(), false);
    
    for (size_t i = 0; i < points.size(); ++i) {
        if (visited[i]) continue;
        
        visited[i] = true;
        std::vector<size_t> neighbors;
        
        // Find neighbors
        for (size_t j = 0; j < points.size(); ++j) {
            if (i == j) continue;
            
            double dist = 0.0;
            for (size_t d = 0; d < points[i].size() && d < points[j].size(); ++d) {
                dist += std::pow(points[i][d] - points[j][d], 2);
            }
            dist = std::sqrt(dist);
            
            if (dist <= eps) {
                neighbors.push_back(j);
            }
        }
        
        if (neighbors.size() >= min_points) {
            std::vector<size_t> cluster;
            cluster.push_back(i);
            cluster.insert(cluster.end(), neighbors.begin(), neighbors.end());
            clusters.push_back(cluster);
        }
    }
    
    return clusters;
}

std::vector<std::vector<uint64_t>> FindConnectedComponents(
    const SEG::SovereignExecutionGraph& graph) {
    // Would implement BFS/DFS to find connected components
    std::vector<std::vector<uint64_t>> components;
    
    // Simplified: return all nodes as one component
    std::vector<uint64_t> all_nodes;
    // Would iterate over graph nodes
    components.push_back(all_nodes);
    
    return components;
}

std::vector<std::vector<uint64_t>> FindCliques(const SEG::SovereignExecutionGraph& graph,
                                                uint32_t min_size) {
    // Would implement Bron-Kerbosch algorithm
    std::vector<std::vector<uint64_t>> cliques;
    
    (void)graph;
    (void)min_size;
    
    return cliques;
}

double CalculateGraphDensity(const SEG::SovereignExecutionGraph& graph) {
    // Density = |E| / (|V| * (|V| - 1) / 2)
    (void)graph;
    return 0.5; // Placeholder
}

double CalculateClusteringCoefficient(const SEG::SovereignExecutionGraph& graph) {
    // Average clustering coefficient
    (void)graph;
    return 0.3; // Placeholder
}

} // namespace Utils

// ============================================================================
// SEGPatternIntegration Implementation
// ============================================================================

void SEGPatternIntegration::AttachPatternDetector(
    SEG::SovereignExecutionGraph& graph,
    EmergentPatternDetector& detector) {
    // Would register callbacks for graph events
    (void)graph;
    (void)detector;
}

void SEGPatternIntegration::DetachPatternDetector(
    SEG::SovereignExecutionGraph& graph) {
    // Would unregister callbacks
    (void)graph;
}

EmergentPatternReport SEGPatternIntegration::GeneratePatternReport(
    const SEG::SovereignExecutionGraph& graph) {
    EmergentPatternDetector detector;
    return detector.DetectPatterns(graph);
}

void SEGPatternIntegration::ExportPatternTelemetry(
    const EmergentPatternReport& report,
    const std::string& output_path) {
    
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"timestamp\": \"" 
        << std::chrono::duration_cast<std::chrono::seconds>(
               report.timestamp.time_since_epoch()).count() 
        << "\",\n";
    oss << "  \"total_patterns\": " << report.total_patterns_detected << ",\n";
    oss << "  \"average_confidence\": " << report.average_confidence << ",\n";
    oss << "  \"system_entropy\": " << report.system_entropy << ",\n";
    oss << "  \"emergence_score\": " << report.emergence_score << ",\n";
    
    oss << "  \"harmonic_attractors\": [\n";
    for (size_t i = 0; i < report.harmonic_attractors.size(); ++i) {
        const auto& a = report.harmonic_attractors[i];
        oss << "    {\"id\": \"" << a.id << "\", ";
        oss << "\"frequency\": " << a.frequency << ", ";
        oss << "\"stability\": " << a.stability_score << "}";
        if (i < report.harmonic_attractors.size() - 1) oss << ",";
        oss << "\n";
    }
    oss << "  ],\n";
    
    oss << "  \"swarm_clusters\": [\n";
    for (size_t i = 0; i < report.swarm_clusters.size(); ++i) {
        const auto& c = report.swarm_clusters[i];
        oss << "    {\"id\": \"" << c.id << "\", ";
        oss << "\"cohesion\": " << c.cohesion_score << ", ";
        oss << "\"performance\": " << c.performance_score << "}";
        if (i < report.swarm_clusters.size() - 1) oss << ",";
        oss << "\n";
    }
    oss << "  ]\n";
    
    oss << "}\n";
    
    // Would write to file
    (void)output_path;
}

} // namespace Emergent
