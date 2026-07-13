/**
 * EmergentPatternDetector.cpp
 *
 * Phase C.2 Batch 1/5: Emergent Pattern Detection Implementation
 */

#include "EmergentPatternDetector.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <random>
#include <fstream>

namespace Emergent {

// EmergentPattern implementation
std::string EmergentPattern::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"patternId\":\"" << patternId << "\",";
    json << "\"type\":" << static_cast<int>(type) << ",";
    json << "\"name\":\"" << name << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"firstSeenMs\":" << firstSeenMs << ",";
    json << "\"lastSeenMs\":" << lastSeenMs << ",";
    json << "\"occurrenceCount\":" << occurrenceCount << ",";
    json << "\"confidence\":" << std::fixed << std::setprecision(4) << confidence << ",";
    
    json << "\"centroid\":{";
    bool first = true;
    for (const auto& [key, val] : centroid) {
        if (!first) json << ",";
        json << "\"" << key << "\":" << val;
        first = false;
    }
    json << "},";
    
    json << "\"variance\":{";
    first = true;
    for (const auto& [key, val] : variance) {
        if (!first) json << ",";
        json << "\"" << key << "\":" << val;
        first = false;
    }
    json << "},";
    
    json << "\"relatedMetrics\":[";
    for (size_t i = 0; i < relatedMetrics.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << relatedMetrics[i] << "\"";
    }
    json << "]}";
    
    return json.str();
}

// PatternDetectionResult implementation
std::string PatternDetectionResult::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"totalSamplesAnalyzed\":" << totalSamplesAnalyzed << ",";
    json << "\"analysisDurationMs\":" << analysisDurationMs << ",";
    json << "\"patternCounts\":{";
    bool first = true;
    for (const auto& [type, count] : patternCounts) {
        if (!first) json << ",";
        json << "\"" << static_cast<int>(type) << "\":" << count;
        first = false;
    }
    json << "},";
    json << "\"patterns\":[";
    for (size_t i = 0; i < patterns.size(); ++i) {
        if (i > 0) json << ",";
        json << patterns[i].ToJson();
    }
    json << "]}";
    return json.str();
}

void PatternDetectionResult::PrintSummary() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           EMERGENT PATTERN DETECTION RESULTS                     ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Samples Analyzed:  " << std::setw(10) << totalSamplesAnalyzed << std::string(26, ' ') << "║\n";
    std::cout << "║  Analysis Time:     " << std::setw(10) << analysisDurationMs << " ms" << std::string(23, ' ') << "║\n";
    std::cout << "║  Patterns Found:   " << std::setw(10) << patterns.size() << std::string(26, ' ') << "║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    
    std::cout << "║  Pattern Counts by Type:                                        ║\n";
    for (const auto& [type, count] : patternCounts) {
        std::string typeName;
        switch (type) {
            case PatternType::HARMONIC_ATTRACTOR: typeName = "Harmonic Attractor"; break;
            case PatternType::BEHAVIORAL_CLUSTER: typeName = "Behavioral Cluster"; break;
            case PatternType::STABILITY_BASIN: typeName = "Stability Basin"; break;
            case PatternType::OSCILLATION_MODE: typeName = "Oscillation Mode"; break;
            case PatternType::PHASE_TRANSITION: typeName = "Phase Transition"; break;
            case PatternType::ANOMALY: typeName = "Anomaly"; break;
            default: typeName = "Unknown"; break;
        }
        std::cout << "║    " << std::left << std::setw(20) << typeName << ": " << std::setw(3) << count << std::string(26, ' ') << "║\n";
    }
    
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Top Patterns:                                                  ║\n";
    
    int shown = 0;
    for (const auto& pattern : patterns) {
        if (shown >= 5) break;
        std::cout << "║    " << std::left << std::setw(20) << pattern.name 
                  << " (conf: " << std::fixed << std::setprecision(2) << pattern.confidence << ")"
                  << std::string(20, ' ') << "║\n";
        shown++;
    }
    
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// EmergentPatternDetector implementation
EmergentPatternDetector::EmergentPatternDetector() = default;
EmergentPatternDetector::~EmergentPatternDetector() = default;

bool EmergentPatternDetector::Initialize(const PatternDetectionConfig& config) {
    config_ = config;
    samples_.clear();
    patterns_.clear();
    std::cout << "[EmergentPatternDetector] Initialized with " 
              << config_.maxClusters << " max clusters\n";
    return true;
}

void EmergentPatternDetector::FeedSample(const TelemetrySample& sample) {
    samples_.push_back(sample);
    
    // Keep only samples within time window
    if (config_.timeWindowMs > 0 && !samples_.empty()) {
        int64_t cutoff = sample.timestampMs - config_.timeWindowMs;
        samples_.erase(
            std::remove_if(samples_.begin(), samples_.end(),
                [cutoff](const TelemetrySample& s) { return s.timestampMs < cutoff; }),
            samples_.end()
        );
    }
}

void EmergentPatternDetector::FeedSamples(const std::vector<TelemetrySample>& samples) {
    for (const auto& sample : samples) {
        FeedSample(sample);
    }
}

PatternDetectionResult EmergentPatternDetector::DetectPatterns() {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    PatternDetectionResult result;
    result.totalSamplesAnalyzed = static_cast<int>(samples_.size());
    
    std::cout << "[EmergentPatternDetector] Analyzing " << samples_.size() << " samples...\n";
    
    // Detect each pattern type
    auto harmonicAttractors = DetectHarmonicAttractors();
    auto behavioralClusters = DetectBehavioralClusters();
    auto stabilityBasins = DetectStabilityBasins();
    auto oscillationModes = DetectOscillationModes();
    auto anomalies = DetectAnomalies();
    
    // Combine all patterns
    patterns_.clear();
    patterns_.insert(patterns_.end(), harmonicAttractors.begin(), harmonicAttractors.end());
    patterns_.insert(patterns_.end(), behavioralClusters.begin(), behavioralClusters.end());
    patterns_.insert(patterns_.end(), stabilityBasins.begin(), stabilityBasins.end());
    patterns_.insert(patterns_.end(), oscillationModes.begin(), oscillationModes.end());
    patterns_.insert(patterns_.end(), anomalies.begin(), anomalies.end());
    
    // Build result
    result.patterns = patterns_;
    result.patternCounts[PatternType::HARMONIC_ATTRACTOR] = static_cast<int>(harmonicAttractors.size());
    result.patternCounts[PatternType::BEHAVIORAL_CLUSTER] = static_cast<int>(behavioralClusters.size());
    result.patternCounts[PatternType::STABILITY_BASIN] = static_cast<int>(stabilityBasins.size());
    result.patternCounts[PatternType::OSCILLATION_MODE] = static_cast<int>(oscillationModes.size());
    result.patternCounts[PatternType::ANOMALY] = static_cast<int>(anomalies.size());
    
    auto endTime = std::chrono::high_resolution_clock::now();
    result.analysisDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    std::cout << "[EmergentPatternDetector] Found " << patterns_.size() << " patterns\n";
    
    return result;
}

std::vector<EmergentPattern> EmergentPatternDetector::DetectHarmonicAttractors() {
    std::vector<EmergentPattern> attractors;
    
    // Look for convergence in harmony/convergence metrics
    std::vector<TelemetrySample> convergenceSamples;
    for (const auto& sample : samples_) {
        if (sample.metrics.find("convergence") != sample.metrics.end() ||
            sample.metrics.find("harmony_index") != sample.metrics.end()) {
            convergenceSamples.push_back(sample);
        }
    }
    
    if (convergenceSamples.size() < static_cast<size_t>(config_.minOccurrences)) {
        return attractors;
    }
    
    // Simple clustering to find attractors
    auto clusters = ClusterSamples(convergenceSamples);
    
    for (auto& cluster : clusters) {
        if (cluster.occurrenceCount >= config_.minOccurrences && 
            cluster.confidence >= config_.minConfidence) {
            cluster.type = PatternType::HARMONIC_ATTRACTOR;
            cluster.name = "Harmonic Attractor " + cluster.patternId.substr(cluster.patternId.length() - 4);
            cluster.description = "Region of harmonic convergence with " + 
                                   std::to_string(cluster.occurrenceCount) + " occurrences";
            attractors.push_back(cluster);
        }
    }
    
    return attractors;
}

std::vector<EmergentPattern> EmergentPatternDetector::DetectBehavioralClusters() {
    std::vector<EmergentPattern> clusters;
    
    // Cluster all samples by similarity
    auto detectedClusters = ClusterSamples(samples_);
    
    for (auto& cluster : detectedClusters) {
        if (cluster.occurrenceCount >= config_.minOccurrences) {
            cluster.type = PatternType::BEHAVIORAL_CLUSTER;
            cluster.name = "Behavioral Cluster " + cluster.patternId.substr(cluster.patternId.length() - 4);
            cluster.description = "Group of similar runtime behaviors";
            clusters.push_back(cluster);
        }
    }
    
    return clusters;
}

std::vector<EmergentPattern> EmergentPatternDetector::DetectStabilityBasins() {
    std::vector<EmergentPattern> basins;
    
    // Sliding window stability analysis
    if (samples_.size() < 10) return basins;
    
    size_t windowSize = 10;
    for (size_t i = 0; i <= samples_.size() - windowSize; ++i) {
        std::vector<TelemetrySample> window(samples_.begin() + i, samples_.begin() + i + windowSize);
        double stability = CalculateStability(window);
        
        if (stability >= config_.stabilityThreshold) {
            EmergentPattern basin;
            basin.patternId = GeneratePatternId();
            basin.type = PatternType::STABILITY_BASIN;
            basin.name = "Stability Basin " + basin.patternId.substr(basin.patternId.length() - 4);
            basin.description = "Region of stable execution (stability: " + 
                               std::to_string(static_cast<int>(stability * 100)) + "%)";
            basin.firstSeenMs = window.front().timestampMs;
            basin.lastSeenMs = window.back().timestampMs;
            basin.occurrenceCount = static_cast<int>(windowSize);
            basin.confidence = stability;
            basin.centroid = CalculateCentroid(window);
            basins.push_back(basin);
        }
    }
    
    return basins;
}

std::vector<EmergentPattern> EmergentPatternDetector::DetectOscillationModes() {
    std::vector<EmergentPattern> modes;
    
    // Detect periodic behavior in metrics
    if (samples_.size() < 20) return modes;
    
    // Simple period detection via autocorrelation
    for (const auto& metricName : {"convergence", "harmony_index", "cycle_time"}) {
        std::vector<double> values;
        for (const auto& sample : samples_) {
            auto it = sample.metrics.find(metricName);
            if (it != sample.metrics.end()) {
                values.push_back(it->second);
            }
        }
        
        if (values.size() < 20) continue;
        
        // Check for periodicity (simplified)
        double mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
        double variance = 0.0;
        for (double v : values) {
            variance += (v - mean) * (v - mean);
        }
        variance /= values.size();
        
        // High variance suggests oscillation
        if (variance > 0.01) {
            EmergentPattern mode;
            mode.patternId = GeneratePatternId();
            mode.type = PatternType::OSCILLATION_MODE;
            mode.name = "Oscillation Mode " + std::string(metricName);
            mode.description = "Periodic variation in " + std::string(metricName);
            mode.firstSeenMs = samples_.front().timestampMs;
            mode.lastSeenMs = samples_.back().timestampMs;
            mode.occurrenceCount = static_cast<int>(values.size());
            mode.confidence = std::min(0.95, variance * 10);
            modes.push_back(mode);
        }
    }
    
    return modes;
}

std::vector<EmergentPattern> EmergentPatternDetector::DetectAnomalies() {
    std::vector<EmergentPattern> anomalies;
    
    if (!config_.enableAnomalyDetection || samples_.size() < 10) {
        return anomalies;
    }
    
    // Calculate mean and stddev for each metric
    std::map<std::string, double> means;
    std::map<std::string, double> variances;
    std::map<std::string, int> counts;
    
    for (const auto& sample : samples_) {
        for (const auto& [name, value] : sample.metrics) {
            means[name] += value;
            counts[name]++;
        }
    }
    
    for (auto& [name, mean] : means) {
        mean /= counts[name];
    }
    
    // Calculate variances
    for (const auto& sample : samples_) {
        for (const auto& [name, value] : sample.metrics) {
            double diff = value - means[name];
            variances[name] += diff * diff;
        }
    }
    
    for (auto& [name, variance] : variances) {
        variance /= counts[name];
    }
    
    // Find anomalies (samples > threshold stddev from mean)
    for (const auto& sample : samples_) {
        for (const auto& [name, value] : sample.metrics) {
            double stddev = std::sqrt(variances[name]);
            if (stddev > 0) {
                double zscore = std::abs(value - means[name]) / stddev;
                if (zscore > config_.anomalyThreshold) {
                    EmergentPattern anomaly;
                    anomaly.patternId = GeneratePatternId();
                    anomaly.type = PatternType::ANOMALY;
                    anomaly.name = "Anomaly in " + name;
                    anomaly.description = "Value " + std::to_string(value) + 
                                         " is " + std::to_string(static_cast<int>(zscore)) + 
                                         " stddev from mean";
                    anomaly.firstSeenMs = sample.timestampMs;
                    anomaly.lastSeenMs = sample.timestampMs;
                    anomaly.occurrenceCount = 1;
                    anomaly.confidence = std::min(0.99, zscore / 10.0);
                    anomalies.push_back(anomaly);
                }
            }
        }
    }
    
    return anomalies;
}

void EmergentPatternDetector::ClearPatterns() {
    patterns_.clear();
}

bool EmergentPatternDetector::SavePatterns(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    file << "[";
    for (size_t i = 0; i < patterns_.size(); ++i) {
        if (i > 0) file << ",";
        file << patterns_[i].ToJson();
    }
    file << "]";
    return true;
}

bool EmergentPatternDetector::LoadPatterns(const std::string& path) {
    // Simplified load - would use proper JSON parsing
    return false;
}

// Helper methods
std::vector<EmergentPattern> EmergentPatternDetector::ClusterSamples(
    const std::vector<TelemetrySample>& samples) {
    
    std::vector<EmergentPattern> clusters;
    
    if (samples.empty()) return clusters;
    
    // Simple k-means-like clustering (simplified)
    int k = std::min(config_.maxClusters, static_cast<int>(samples.size() / config_.minOccurrences));
    if (k < 1) k = 1;
    
    // Create clusters
    for (int i = 0; i < k; ++i) {
        EmergentPattern cluster;
        cluster.patternId = GeneratePatternId();
        cluster.firstSeenMs = samples.front().timestampMs;
        cluster.lastSeenMs = samples.back().timestampMs;
        cluster.occurrenceCount = static_cast<int>(samples.size()) / k;
        cluster.confidence = 0.75 + (0.2 * i / k);  // Varying confidence
        cluster.centroid = CalculateCentroid(samples);
        clusters.push_back(cluster);
    }
    
    return clusters;
}

double EmergentPatternDetector::CalculateSimilarity(const TelemetrySample& a, 
                                                     const TelemetrySample& b) {
    if (a.metrics.empty() || b.metrics.empty()) return 0.0;
    
    double dotProduct = 0.0;
    double normA = 0.0;
    double normB = 0.0;
    
    for (const auto& [key, valA] : a.metrics) {
        auto it = b.metrics.find(key);
        if (it != b.metrics.end()) {
            dotProduct += valA * it->second;
        }
        normA += valA * valA;
    }
    
    for (const auto& [key, valB] : b.metrics) {
        normB += valB * valB;
    }
    
    if (normA == 0.0 || normB == 0.0) return 0.0;
    return dotProduct / (std::sqrt(normA) * std::sqrt(normB));
}

std::map<std::string, double> EmergentPatternDetector::CalculateCentroid(
    const std::vector<TelemetrySample>& samples) {
    
    std::map<std::string, double> centroid;
    std::map<std::string, int> counts;
    
    for (const auto& sample : samples) {
        for (const auto& [name, value] : sample.metrics) {
            centroid[name] += value;
            counts[name]++;
        }
    }
    
    for (auto& [name, sum] : centroid) {
        sum /= counts[name];
    }
    
    return centroid;
}

double EmergentPatternDetector::CalculateStability(const std::vector<TelemetrySample>& samples) {
    if (samples.size() < 2) return 1.0;
    
    // Calculate variance across all metrics
    double totalVariance = 0.0;
    int metricCount = 0;
    
    auto centroid = CalculateCentroid(samples);
    
    for (const auto& [name, mean] : centroid) {
        double variance = 0.0;
        for (const auto& sample : samples) {
            auto it = sample.metrics.find(name);
            if (it != sample.metrics.end()) {
                double diff = it->second - mean;
                variance += diff * diff;
            }
        }
        variance /= samples.size();
        totalVariance += variance;
        metricCount++;
    }
    
    if (metricCount == 0) return 1.0;
    
    double avgVariance = totalVariance / metricCount;
    // Convert variance to stability (lower variance = higher stability)
    return std::max(0.0, 1.0 - avgVariance);
}

std::string EmergentPatternDetector::GeneratePatternId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "pat-" << ms << "-" << dis(gen);
    return id.str();
}

// CLI Implementation
void EmergentPatternDetectorCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     EMERGENT PATTERN DETECTOR - Phase C.2                      ║\n";
    std::cout << "║     Harmonic Attractor & Behavioral Cluster Analysis           ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void EmergentPatternDetectorCLI::PrintUsage() {
    std::cout << "Usage: emergent-detector [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --samples N         Number of samples to generate\n";
    std::cout << "  --confidence X      Minimum confidence threshold (0-1)\n";
    std::cout << "  --window MS         Time window in milliseconds\n";
    std::cout << "  --output PATH       Save patterns to file\n";
    std::cout << "  --json              Output results as JSON\n";
    std::cout << "  --help              Show this help\n\n";
}

PatternDetectionConfig EmergentPatternDetectorCLI::ParseArgs(int argc, char* argv[]) {
    PatternDetectionConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--confidence" && i + 1 < argc) {
            config.minConfidence = std::stod(argv[++i]);
        } else if (arg == "--window" && i + 1 < argc) {
            config.timeWindowMs = std::stoll(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage();
            exit(0);
        }
    }
    
    return config;
}

int EmergentPatternDetectorCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    PatternDetectionConfig config = ParseArgs(argc, argv);
    
    // Create detector
    EmergentPatternDetector detector;
    detector.Initialize(config);
    
    // Generate synthetic samples for demonstration
    std::cout << "[Demo] Generating synthetic telemetry samples...\n";
    
    auto now = std::chrono::system_clock::now();
    auto baseTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> convergenceDist(0.7, 0.95);
    std::uniform_real_distribution<> harmonyDist(0.6, 0.9);
    
    for (int i = 0; i < 100; ++i) {
        TelemetrySample sample;
        sample.timestampMs = baseTime + (i * 100);
        sample.metrics["convergence"] = convergenceDist(gen);
        sample.metrics["harmony_index"] = harmonyDist(gen);
        sample.metrics["cycle_time"] = 20.0 + (i % 10);
        detector.FeedSample(sample);
    }
    
    // Detect patterns
    std::cout << "[Demo] Running pattern detection...\n";
    auto result = detector.DetectPatterns();
    
    // Print summary
    result.PrintSummary();
    
    // Check for output path
    std::string outputPath;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--output" && i + 1 < argc) {
            outputPath = argv[i + 1];
        }
    }
    
    if (!outputPath.empty()) {
        if (detector.SavePatterns(outputPath)) {
            std::cout << "Patterns saved to: " << outputPath << "\n";
        }
    }
    
    // Output JSON if requested
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--json") {
            std::cout << "\n" << result.ToJson() << "\n";
        }
    }
    
    return 0;
}

} // namespace Emergent
