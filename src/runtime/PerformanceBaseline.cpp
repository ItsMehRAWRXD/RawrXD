/**
 * PerformanceBaseline.cpp
 * 
 * Phase B.5 Batch 2/5: Performance Baseline Capture Implementation
 */

#include "PerformanceBaseline.hpp"
#include <algorithm>
#include <numeric>
#include <fstream>
#include <iostream>
#include <cmath>

namespace Sovereign {

// Calculate statistics for a phase
void PhaseBaseline::CalculateStatistics() {
    // Group samples by name
    std::map<std::string, std::vector<double>> grouped;
    for (const auto& sample : samples) {
        grouped[sample.name].push_back(sample.value);
    }
    
    // Calculate stats for each metric
    for (const auto& [name, values] : grouped) {
        if (values.empty()) continue;
        
        MetricStats stats;
        stats.name = name;
        stats.sampleCount = static_cast<int64_t>(values.size());
        
        // Min and max
        auto [minIt, maxIt] = std::minmax_element(values.begin(), values.end());
        stats.min = *minIt;
        stats.max = *maxIt;
        
        // Mean
        stats.mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
        
        // Sort for median and percentiles
        std::vector<double> sorted = values;
        std::sort(sorted.begin(), sorted.end());
        
        // Median
        size_t mid = sorted.size() / 2;
        if (sorted.size() % 2 == 0) {
            stats.median = (sorted[mid - 1] + sorted[mid]) / 2.0;
        } else {
            stats.median = sorted[mid];
        }
        
        // P95 and P99
        size_t p95Idx = static_cast<size_t>(std::ceil(0.95 * sorted.size())) - 1;
        size_t p99Idx = static_cast<size_t>(std::ceil(0.99 * sorted.size())) - 1;
        stats.p95 = sorted[std::min(p95Idx, sorted.size() - 1)];
        stats.p99 = sorted[std::min(p99Idx, sorted.size() - 1)];
        
        // Standard deviation
        double variance = 0.0;
        for (double v : values) {
            variance += (v - stats.mean) * (v - stats.mean);
        }
        variance /= values.size();
        stats.stddev = std::sqrt(variance);
        
        statistics[name] = stats;
    }
}

// PerformanceBaseline implementation
PerformanceBaseline::PerformanceBaseline() {
    startTime_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void PerformanceBaseline::StartPhase(const std::string& phaseName) {
    if (currentPhase_ != nullptr) {
        EndPhase();
    }
    
    PhaseBaseline phase;
    phase.phaseName = phaseName;
    phase.startTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    baselines_.push_back(phase);
    currentPhase_ = &baselines_.back();
}

void PerformanceBaseline::EndPhase() {
    if (currentPhase_ != nullptr) {
        currentPhase_->endTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        currentPhase_->CalculateStatistics();
        currentPhase_ = nullptr;
    }
}

void PerformanceBaseline::AddSample(const std::string& name, double value, 
                                     const std::string& unit,
                                     const std::map<std::string, std::string>& tags) {
    if (currentPhase_ != nullptr) {
        currentPhase_->AddSample(name, value, unit, tags);
    }
}

const PhaseBaseline* PerformanceBaseline::GetBaseline(const std::string& phaseName) const {
    for (const auto& baseline : baselines_) {
        if (baseline.phaseName == phaseName) {
            return &baseline;
        }
    }
    return nullptr;
}

void PerformanceBaseline::CalculateAllStatistics() {
    for (auto& baseline : baselines_) {
        baseline.CalculateStatistics();
    }
}

std::string PerformanceBaseline::ExportToJson() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"captureTime\": " << startTime_ << ",\n";
    json << "  \"totalPhases\": " << baselines_.size() << ",\n";
    json << "  \"phases\": [\n";
    
    for (size_t i = 0; i < baselines_.size(); ++i) {
        if (i > 0) json << ",\n";
        json << "    " << baselines_[i].ToJson();
    }
    
    json << "\n  ]\n}";
    return json.str();
}

bool PerformanceBaseline::SaveToFile(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return false;
    file << ExportToJson();
    return true;
}

bool PerformanceBaseline::LoadFromFile(const std::string& path) {
    // Simplified load - would need proper JSON parsing
    return false;
}

std::string PerformanceBaseline::Compare(const PerformanceBaseline& other) const {
    std::ostringstream report;
    report << "Performance Comparison Report\n";
    report << "==============================\n\n";
    
    for (const auto& baseline : baselines_) {
        const PhaseBaseline* otherBaseline = other.GetBaseline(baseline.phaseName);
        if (otherBaseline == nullptr) continue;
        
        report << "Phase: " << baseline.phaseName << "\n";
        report << "  Duration: " << baseline.GetDurationMs() << "ms vs " 
               << otherBaseline->GetDurationMs() << "ms\n";
        
        for (const auto& [name, stats] : baseline.statistics) {
            auto it = otherBaseline->statistics.find(name);
            if (it != otherBaseline->statistics.end()) {
                double diff = stats.mean - it->second.mean;
                double pct = (diff / it->second.mean) * 100.0;
                report << "  " << name << ": " << stats.mean << " vs " 
                       << it->second.mean << " (" << (pct > 0 ? "+" : "") 
                       << pct << "%)\n";
            }
        }
        report << "\n";
    }
    
    return report.str();
}

void PerformanceBaseline::PrintSummary() const {
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           Performance Baseline Summary                       ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
    
    for (const auto& baseline : baselines_) {
        std::cout << "Phase: " << baseline.phaseName << "\n";
        std::cout << "  Duration: " << std::fixed << std::setprecision(2) 
                  << baseline.GetDurationMs() << " ms\n";
        
        for (const auto& [name, stats] : baseline.statistics) {
            std::cout << "  " << name << ":\n";
            std::cout << "    Mean: " << std::fixed << std::setprecision(4) << stats.mean << "\n";
            std::cout << "    Min/Max: " << stats.min << " / " << stats.max << "\n";
            std::cout << "    P95/P99: " << stats.p95 << " / " << stats.p99 << "\n";
        }
        std::cout << "\n";
    }
}

// RuntimePerformanceCapture implementation
RuntimePerformanceCapture::RuntimePerformanceCapture() {
    baseline_.StartPhase("initialization");
}

void RuntimePerformanceCapture::CaptureStartup(int64_t startupTimeMs, int componentCount) {
    baseline_.EndPhase(); // End initialization
    
    baseline_.StartPhase("startup");
    baseline_.AddSample("startup_time_ms", static_cast<double>(startupTimeMs), "ms");
    baseline_.AddSample("components_initialized", static_cast<double>(componentCount), "count");
    baseline_.EndPhase();
}

void RuntimePerformanceCapture::CaptureValidation(int testsRun, int testsPassed, int64_t durationMs) {
    baseline_.StartPhase("validation");
    baseline_.AddSample("tests_run", static_cast<double>(testsRun), "count");
    baseline_.AddSample("tests_passed", static_cast<double>(testsPassed), "count");
    baseline_.AddSample("validation_duration_ms", static_cast<double>(durationMs), "ms");
    baseline_.AddSample("pass_rate", static_cast<double>(testsPassed) / testsRun * 100.0, "percent");
    baseline_.EndPhase();
}

void RuntimePerformanceCapture::CaptureWorkflowExecution(int cycleNumber, double harmonyIndex,
                                                          int64_t durationMs, double convergenceScore) {
    std::map<std::string, std::string> tags;
    tags["cycle"] = std::to_string(cycleNumber);
    
    baseline_.StartPhase("workflow_cycle_" + std::to_string(cycleNumber));
    baseline_.AddSample("harmony_index", harmonyIndex, "score", tags);
    baseline_.AddSample("execution_time_ms", static_cast<double>(durationMs), "ms", tags);
    baseline_.AddSample("convergence_score", convergenceScore, "score", tags);
    baseline_.EndPhase();
}

void RuntimePerformanceCapture::CaptureConvergence(int iterations, double finalScore, int64_t totalDurationMs) {
    baseline_.StartPhase("convergence");
    baseline_.AddSample("iterations_to_converge", static_cast<double>(iterations), "count");
    baseline_.AddSample("final_convergence_score", finalScore, "score");
    baseline_.AddSample("total_duration_ms", static_cast<double>(totalDurationMs), "ms");
    baseline_.AddSample("avg_time_per_iteration_ms", 
                        static_cast<double>(totalDurationMs) / iterations, "ms");
    baseline_.EndPhase();
}

std::string RuntimePerformanceCapture::ExportResults() const {
    return baseline_.ExportToJson();
}

} // namespace Sovereign
