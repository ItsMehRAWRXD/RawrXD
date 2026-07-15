#pragma once

/**
 * PerformanceBaseline.hpp
 * 
 * Phase B.5 Batch 2/5: Performance Baseline Capture
 * 
 * Captures and tracks performance metrics for the Sovereign Runtime
 */

#include <string>
#include <vector>
#include <chrono>
#include <map>
#include <sstream>
#include <iomanip>

namespace Sovereign {

/**
 * Performance metric for a single measurement
 */
struct MetricSample {
    std::string name;
    double value;
    std::string unit;
    int64_t timestampMs;
    std::map<std::string, std::string> tags;
    
    std::string ToJson() const {
        std::ostringstream json;
        json << "{\"name\":\"" << name << "\",";
        json << "\"value\":" << std::fixed << std::setprecision(4) << value << ",";
        json << "\"unit\":\"" << unit << "\",";
        json << "\"timestamp\":" << timestampMs;
        if (!tags.empty()) {
            json << ",\"tags\":{";
            bool first = true;
            for (const auto& [key, val] : tags) {
                if (!first) json << ",";
                json << "\"" << key << "\":\"" << val << "\"";
                first = false;
            }
            json << "}";
        }
        json << "}";
        return json.str();
    }
};

/**
 * Aggregated statistics for a metric
 */
struct MetricStats {
    std::string name;
    double min = 0.0;
    double max = 0.0;
    double mean = 0.0;
    double median = 0.0;
    double p95 = 0.0;
    double p99 = 0.0;
    double stddev = 0.0;
    int64_t sampleCount = 0;
    
    std::string ToJson() const {
        std::ostringstream json;
        json << "{\"name\":\"" << name << "\",";
        json << "\"min\":" << std::fixed << std::setprecision(4) << min << ",";
        json << "\"max\":" << max << ",";
        json << "\"mean\":" << mean << ",";
        json << "\"median\":" << median << ",";
        json << "\"p95\":" << p95 << ",";
        json << "\"p99\":" << p99 << ",";
        json << "\"stddev\":" << stddev << ",";
        json << "\"count\":" << sampleCount << "}";
        return json.str();
    }
};

/**
 * Performance baseline for a specific phase/component
 */
struct PhaseBaseline {
    std::string phaseName;
    int64_t startTimeMs;
    int64_t endTimeMs;
    std::vector<MetricSample> samples;
    std::map<std::string, MetricStats> statistics;
    
    double GetDurationMs() const {
        return static_cast<double>(endTimeMs - startTimeMs);
    }
    
    void AddSample(const std::string& name, double value, const std::string& unit,
                  const std::map<std::string, std::string>& tags = {}) {
        MetricSample sample;
        sample.name = name;
        sample.value = value;
        sample.unit = unit;
        sample.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        sample.tags = tags;
        samples.push_back(sample);
    }
    
    void CalculateStatistics();
    
    std::string ToJson() const {
        std::ostringstream json;
        json << "{\"phase\":\"" << phaseName << "\",";
        json << "\"durationMs\":" << GetDurationMs() << ",";
        json << "\"samples\":[";
        for (size_t i = 0; i < samples.size(); ++i) {
            if (i > 0) json << ",";
            json << samples[i].ToJson();
        }
        json << "],\"statistics\":{";
        bool first = true;
        for (const auto& [name, stats] : statistics) {
            if (!first) json << ",";
            json << "\"" << name << "\":" << stats.ToJson();
            first = false;
        }
        json << "}}";
        return json.str();
    }
};

/**
 * Complete performance baseline capture
 */
class PerformanceBaseline {
public:
    PerformanceBaseline();
    
    // Start a new phase
    void StartPhase(const std::string& phaseName);
    
    // End current phase
    void EndPhase();
    
    // Add sample to current phase
    void AddSample(const std::string& name, double value, const std::string& unit,
                   const std::map<std::string, std::string>& tags = {});
    
    // Get all baselines
    const std::vector<PhaseBaseline>& GetBaselines() const { return baselines_; }
    
    // Get baseline by phase name
    const PhaseBaseline* GetBaseline(const std::string& phaseName) const;
    
    // Calculate all statistics
    void CalculateAllStatistics();
    
    // Export to JSON
    std::string ExportToJson() const;
    
    // Save to file
    bool SaveToFile(const std::string& path) const;
    
    // Load from file
    bool LoadFromFile(const std::string& path);
    
    // Compare with another baseline
    std::string Compare(const PerformanceBaseline& other) const;
    
    // Print summary
    void PrintSummary() const;
    
private:
    std::vector<PhaseBaseline> baselines_;
    PhaseBaseline* currentPhase_ = nullptr;
    int64_t startTime_;
};

/**
 * Performance baseline capture for specific runtime phases
 */
class RuntimePerformanceCapture {
public:
    RuntimePerformanceCapture();
    
    // Capture startup phase
    void CaptureStartup(int64_t startupTimeMs, int componentCount);
    
    // Capture validation phase
    void CaptureValidation(int testsRun, int testsPassed, int64_t durationMs);
    
    // Capture workflow execution
    void CaptureWorkflowExecution(int cycleNumber, double harmonyIndex, 
                                   int64_t durationMs, double convergenceScore);
    
    // Capture convergence achievement
    void CaptureConvergence(int iterations, double finalScore, int64_t totalDurationMs);
    
    // Get the baseline
    PerformanceBaseline& GetBaseline() { return baseline_; }
    const PerformanceBaseline& GetBaseline() const { return baseline_; }
    
    // Export results
    std::string ExportResults() const;
    
private:
    PerformanceBaseline baseline_;
};

} // namespace Sovereign
