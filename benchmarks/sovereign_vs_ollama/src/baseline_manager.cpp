// Performance Baseline Management Implementation
// Copyright (c) 2026 RawrXD Team

#include "baseline_manager.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <math>
#include <chrono>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#endif

namespace rawrxd::benchmark {

// ============================================================================
// Baseline Entry Implementation
// ============================================================================

bool BaselineEntry::IsSimilarTo(const BaselineEntry& other, double tolerance) const {
    double latency_diff = std::abs(latency.mean - other.latency.mean) / latency.mean;
    double throughput_diff = std::abs(throughput.mean - other.throughput.mean) / throughput.mean;
    
    return latency_diff <= tolerance && throughput_diff <= tolerance;
}

double BaselineEntry::CalculateDistance(const BaselineEntry& other) const {
    // Normalized Euclidean distance
    double latency_norm = (latency.mean - other.latency.mean) / latency.mean;
    double throughput_norm = (throughput.mean - other.throughput.mean) / throughput.mean;
    
    return std::sqrt(latency_norm * latency_norm + throughput_norm * throughput_norm);
}

// ============================================================================
// Baseline History Implementation
// ============================================================================

std::optional<BaselineEntry> BaselineHistory::GetLatest() const {
    for (auto it = entries.rbegin(); it != entries.rend(); ++it) {
        if (it->is_valid) {
            return *it;
        }
    }
    return std::nullopt;
}

std::optional<BaselineEntry> BaselineHistory::GetAtTime(const std::string& timestamp) const {
    for (const auto& entry : entries) {
        if (entry.timestamp == timestamp) {
            return entry;
        }
    }
    return std::nullopt;
}

std::vector<BaselineEntry> BaselineHistory::GetInRange(const std::string& start,
                                                          const std::string& end) const {
    std::vector<BaselineEntry> result;
    for (const auto& entry : entries) {
        if (entry.timestamp >= start && entry.timestamp <= end) {
            result.push_back(entry);
        }
    }
    return result;
}

std::pair<double, double> BaselineHistory::CalculateTrend() const {
    if (entries.size() < 2) {
        return {0.0, 0.0};
    }
    
    // Simple linear regression on latency
    double n = static_cast<double>(entries.size());
    double sum_x = 0.0, sum_y = 0.0, sum_xy = 0.0, sum_x2 = 0.0;
    
    for (size_t i = 0; i < entries.size(); ++i) {
        sum_x += static_cast<double>(i);
        sum_y += entries[i].latency.mean;
        sum_xy += static_cast<double>(i) * entries[i].latency.mean;
        sum_x2 += static_cast<double>(i) * static_cast<double>(i);
    }
    
    double slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
    
    // Calculate R-squared
    double mean_y = sum_y / n;
    double ss_tot = 0.0, ss_res = 0.0;
    for (size_t i = 0; i < entries.size(); ++i) {
        double predicted = slope * static_cast<double>(i);
        ss_tot += (entries[i].latency.mean - mean_y) * (entries[i].latency.mean - mean_y);
        ss_res += (entries[i].latency.mean - predicted) * (entries[i].latency.mean - predicted);
    }
    double r_squared = 1.0 - (ss_res / ss_tot);
    
    return {slope, r_squared};
}

bool BaselineHistory::IsStable(const BaselineConfig& config) const {
    if (entries.size() < static_cast<size_t>(config.min_runs)) {
        return false;
    }
    
    // Check coefficient of variation
    std::vector<double> latencies;
    for (const auto& entry : entries) {
        latencies.push_back(entry.latency.mean);
    }
    
    double mean = BaselineEstablishment::CalculateMean(latencies);
    double stddev = BaselineEstablishment::CalculateStdDev(latencies);
    double cv = (mean > 0.0) ? stddev / mean : 0.0;
    
    return cv <= config.max_cv;
}

double BaselineHistory::GetStabilityScore() const {
    if (entries.empty()) {
        return 0.0;
    }
    
    // Calculate coefficient of variation
    std::vector<double> latencies;
    for (const auto& entry : entries) {
        latencies.push_back(entry.latency.mean);
    }
    
    double mean = BaselineEstablishment::CalculateMean(latencies);
    double stddev = BaselineEstablishment::CalculateStdDev(latencies);
    double cv = (mean > 0.0) ? stddev / mean : 1.0;
    
    // Convert CV to stability score (0-100)
    // Lower CV = higher stability
    double score = std::max(0.0, 100.0 * (1.0 - cv * 10.0));
    return score;
}

// ============================================================================
// Baseline Manager Implementation
// ============================================================================

BaselineManager::BaselineManager() = default;
BaselineManager::~BaselineManager() {
    SaveToDisk();
}

bool BaselineManager::Initialize(const std::string& storage_path,
                                    const BaselineConfig& config) {
    storage_path_ = storage_path;
    config_ = config;
    return LoadFromDisk();
}

bool BaselineManager::AddEntry(const BaselineEntry& entry) {
    if (!ValidateEntry(entry)) {
        return false;
    }
    
    baselines_[entry.benchmark_id].benchmark_id = entry.benchmark_id;
    baselines_[entry.benchmark_id].entries.push_back(entry);
    
    // Trim history if needed
    auto& history = baselines_[entry.benchmark_id];
    if (history.entries.size() > static_cast<size_t>(config_.max_runs)) {
        history.entries.erase(history.entries.begin());
    }
    
    return SaveToDisk();
}

std::optional<BaselineEntry> BaselineManager::GetBaseline(const std::string& benchmark_id) const {
    auto it = baselines_.find(benchmark_id);
    if (it == baselines_.end()) {
        return std::nullopt;
    }
    return it->second.GetLatest();
}

BaselineHistory BaselineManager::GetHistory(const std::string& benchmark_id) const {
    auto it = baselines_.find(benchmark_id);
    if (it == baselines_.end()) {
        return BaselineHistory{};
    }
    return it->second;
}

bool BaselineManager::HasBaseline(const std::string& benchmark_id) const {
    return baselines_.find(benchmark_id) != baselines_.end();
}

std::optional<BaselineEntry> BaselineManager::EstablishBaseline(
    const std::string& benchmark_id,
    const std::vector<BenchmarkResult>& results) {
    
    if (results.empty()) {
        return std::nullopt;
    }
    
    // Aggregate results into baseline entry
    BaselineEntry entry;
    entry.benchmark_id = benchmark_id;
    entry.benchmark_name = results[0].benchmark_name;
    entry.category = results[0].category;
    entry.backend = results[0].backend;
    entry.model_name = results[0].model_name;
    entry.timestamp = baseline_utils::GetTimestamp();
    entry.git_commit = baseline_utils::GetGitCommit();
    entry.git_branch = baseline_utils::GetGitBranch();
    
    // Collect all latencies
    std::vector<double> all_latencies;
    std::vector<double> all_throughputs;
    double total_success_rate = 0.0;
    
    for (const auto& result : results) {
        if (!result.raw_latencies.empty()) {
            all_latencies.insert(all_latencies.end(), 
                                  result.raw_latencies.begin(), 
                                  result.raw_latencies.end());
        }
        all_throughputs.push_back(result.throughput.mean);
        total_success_rate += result.success_rate;
    }
    
    // Remove outliers
    all_latencies = BaselineEstablishment::RemoveOutliers(all_latencies, config_.outlier_threshold);
    
    // Calculate statistics
    if (!all_latencies.empty()) {
        entry.latency = StatisticalMetrics::Calculate(all_latencies);
        entry.raw_latencies = all_latencies;
    }
    
    if (!all_throughputs.empty()) {
        entry.throughput = StatisticalMetrics::Calculate(all_throughputs);
    }
    
    entry.success_rate = total_success_rate / results.size();
    entry.is_valid = true;
    
    // Store baseline
    AddEntry(entry);
    
    return entry;
}

bool BaselineManager::UpdateBaseline(const std::string& benchmark_id,
                                      const BenchmarkResult& result) {
    BaselineEntry entry;
    entry.benchmark_id = benchmark_id;
    entry.benchmark_name = result.benchmark_name;
    entry.category = result.category;
    entry.backend = result.backend;
    entry.model_name = result.model_name;
    entry.timestamp = baseline_utils::GetTimestamp();
    entry.git_commit = baseline_utils::GetGitCommit();
    entry.git_branch = baseline_utils::GetGitBranch();
    entry.latency = result.latency;
    entry.throughput = result.throughput;
    entry.success_rate = result.success_rate;
    entry.raw_latencies = result.raw_latencies;
    entry.is_valid = true;
    
    return AddEntry(entry);
}

bool BaselineManager::InvalidateBaseline(const std::string& benchmark_id,
                                          const std::string& reason) {
    auto it = baselines_.find(benchmark_id);
    if (it == baselines_.end()) {
        return false;
    }
    
    // Mark latest entry as invalid
    for (auto& entry : it->second.entries) {
        if (entry.is_valid) {
            entry.is_valid = false;
            entry.validation_message = reason;
        }
    }
    
    return SaveToDisk();
}

BaselineManager::ComparisonResult BaselineManager::CompareToBaseline(
    const std::string& benchmark_id, const BenchmarkResult& result) const {
    
    ComparisonResult comp;
    
    auto baseline_opt = GetBaseline(benchmark_id);
    if (!baseline_opt.has_value()) {
        comp.summary = "No baseline found for comparison";
        return comp;
    }
    
    const auto& baseline = baseline_opt.value();
    
    // Calculate changes
    comp.latency_change_percent = ((result.latency.mean - baseline.latency.mean) / baseline.latency.mean) * 100.0;
    comp.throughput_change_percent = ((result.throughput.mean - baseline.throughput.mean) / baseline.throughput.mean) * 100.0;
    
    // Determine if regression or improvement
    comp.is_regression = comp.latency_change_percent > 10.0 || comp.throughput_change_percent < -10.0;
    comp.is_improvement = comp.latency_change_percent < -10.0 || comp.throughput_change_percent > 10.0;
    
    // Calculate confidence (simplified)
    comp.confidence = 0.95;
    comp.is_valid = true;
    
    // Generate summary
    std::ostringstream oss;
    if (comp.is_regression) {
        oss << "REGRESSION: ";
    } else if (comp.is_improvement) {
        oss << "IMPROVEMENT: ";
    } else {
        oss << "STABLE: ";
    }
    oss << "Latency " << (comp.latency_change_percent > 0 ? "+" : "") 
       << std::fixed << std::setprecision(2) << comp.latency_change_percent << "%, ";
    oss << "Throughput " << (comp.throughput_change_percent > 0 ? "+" : "") 
       << comp.throughput_change_percent << "%";
    comp.summary = oss.str();
    
    return comp;
}

std::vector<std::string> BaselineManager::GetBaselineIds() const {
    std::vector<std::string> ids;
    for (const auto& [id, _] : baselines_) {
        ids.push_back(id);
    }
    return ids;
}

bool BaselineManager::ExportToFile(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    // Simple JSON export
    file << "{\n";
    file << "  \"baselines\": [\n";
    
    bool first = true;
    for (const auto& [id, history] : baselines_) {
        for (const auto& entry : history.entries) {
            if (!first) file << ",\n";
            first = false;
            
            file << "    {\n";
            file << "      \"benchmark_id\": \"" << entry.benchmark_id << "\",\n";
            file << "      \"benchmark_name\": \"" << entry.benchmark_name << "\",\n";
            file << "      \"timestamp\": \"" << entry.timestamp << "\",\n";
            file << "      \"latency_mean\": " << entry.latency.mean << ",\n";
            file << "      \"throughput_mean\": " << entry.throughput.mean << ",\n";
            file << "      \"success_rate\": " << entry.success_rate << ",\n";
            file << "      \"is_valid\": " << (entry.is_valid ? "true" : "false") << "\n";
            file << "    }";
        }
    }
    
    file << "\n  ]\n";
    file << "}\n";
    
    return true;
}

bool BaselineManager::ImportFromFile(const std::string& path) {
    // Simplified import - in production, use proper JSON parsing
    return LoadFromDisk();
}

std::string BaselineManager::GenerateReport() const {
    std::ostringstream oss;
    
    oss << "Baseline Report\n";
    oss << "===============\n\n";
    oss << "Total benchmarks: " << baselines_.size() << "\n\n";
    
    for (const auto& [id, history] : baselines_) {
        oss << "Benchmark: " << id << "\n";
        oss << "  Entries: " << history.entries.size() << "\n";
        
        auto latest = history.GetLatest();
        if (latest.has_value()) {
            oss << "  Latest Latency: " << latest->latency.mean << " ms\n";
            oss << "  Latest Throughput: " << latest->throughput.mean << " TPS\n";
            oss << "  Stability Score: " << history.GetStabilityScore() << "/100\n";
        }
        
        auto [trend, r_squared] = history.CalculateTrend();
        oss << "  Trend: " << (trend > 0 ? "increasing" : "decreasing") << " (R²=" << r_squared << ")\n";
        oss << "\n";
    }
    
    return oss.str();
}

bool BaselineManager::SaveToDisk() {
    if (storage_path_.empty()) {
        return false;
    }
    return ExportToFile(storage_path_);
}

bool BaselineManager::LoadFromDisk() {
    // Simplified load - in production, implement proper JSON parsing
    return true;
}

bool BaselineManager::ValidateEntry(const BaselineEntry& entry) const {
    return entry.is_valid && 
           !entry.benchmark_id.empty() && 
           entry.latency.sample_count > 0;
}

// ============================================================================
// Baseline Establishment Implementation
// ============================================================================

BaselineEntry BaselineEstablishment::Establish(const std::string& benchmark_name,
                                                BenchmarkCategory category,
                                                BackendType backend,
                                                const BenchmarkConfig& config,
                                                const BaselineConfig& baseline_config) {
    // This would run the actual benchmark multiple times
    // For now, return a placeholder
    BaselineEntry entry;
    entry.benchmark_id = benchmark_name + "_" + BackendTypeToString(backend);
    entry.benchmark_name = benchmark_name;
    entry.category = category;
    entry.backend = backend;
    entry.timestamp = baseline_utils::GetTimestamp();
    entry.git_commit = baseline_utils::GetGitCommit();
    entry.git_branch = baseline_utils::GetGitBranch();
    entry.is_valid = false;  // Not yet established
    entry.validation_message = "Baseline establishment in progress";
    
    return entry;
}

bool BaselineEstablishment::HasEnoughSamples(const std::vector<BenchmarkResult>& results,
                                              const BaselineConfig& config) {
    return static_cast<int>(results.size()) >= config.min_runs;
}

bool BaselineEstablishment::IsStable(const std::vector<BenchmarkResult>& results,
                                      const BaselineConfig& config) {
    if (results.size() < static_cast<size_t>(config.stable_consecutive_count)) {
        return false;
    }
    
    // Check last N runs for stability
    for (size_t i = results.size() - config.stable_consecutive_count; i < results.size() - 1; ++i) {
        double change = std::abs(results[i+1].latency.mean - results[i].latency.mean) / results[i].latency.mean;
        if (change > config.stability_threshold) {
            return false;
        }
    }
    
    return true;
}

int BaselineEstablishment::CalculateRequiredSamples(const std::vector<BenchmarkResult>& results,
                                                     const BaselineConfig& config) {
    int current = static_cast<int>(results.size());
    return std::max(0, config.min_runs - current);
}

std::vector<double> BaselineEstablishment::RemoveOutliers(const std::vector<double>& samples,
                                                            double threshold) {
    if (samples.size() < 3) return samples;
    
    double mean = CalculateMean(samples);
    double stddev = CalculateStdDev(samples);
    
    if (stddev == 0.0) return samples;
    
    std::vector<double> filtered;
    for (double s : samples) {
        double z_score = std::abs(s - mean) / stddev;
        if (z_score <= threshold) {
            filtered.push_back(s);
        }
    }
    
    return filtered;
}

double BaselineEstablishment::CalculateCV(const std::vector<double>& samples) {
    if (samples.empty()) return 0.0;
    
    double mean = CalculateMean(samples);
    double stddev = CalculateStdDev(samples);
    
    return (mean > 0.0) ? stddev / mean : 0.0;
}

bool BaselineEstablishment::HasConverged(const std::vector<double>& samples,
                                          double threshold) {
    if (samples.size() < 10) return false;
    
    // Check if CV has stabilized
    size_t half = samples.size() / 2;
    std::vector<double> first_half(samples.begin(), samples.begin() + half);
    std::vector<double> second_half(samples.begin() + half, samples.end());
    
    double cv1 = CalculateCV(first_half);
    double cv2 = CalculateCV(second_half);
    
    return std::abs(cv1 - cv2) < threshold;
}

// ============================================================================
// Baseline Utilities Implementation
// ============================================================================

namespace baseline_utils {

std::string GetGitCommit() {
    // Try to get git commit hash
    char buffer[128];
    std::string result = "unknown";
    
#ifdef _WIN32
    FILE* pipe = _popen("git rev-parse --short HEAD 2>nul", "r");
#else
    FILE* pipe = popen("git rev-parse --short HEAD 2>/dev/null", "r");
#endif
    
    if (pipe) {
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result = buffer;
            // Remove newline
            result.erase(result.find_last_not_of("\r\n") + 1);
        }
#ifdef _WIN32
        _pclose(pipe);
#else
        pclose(pipe);
#endif
    }
    
    return result;
}

std::string GetGitBranch() {
    char buffer[128];
    std::string result = "unknown";
    
#ifdef _WIN32
    FILE* pipe = _popen("git rev-parse --abbrev-ref HEAD 2>nul", "r");
#else
    FILE* pipe = popen("git rev-parse --abbrev-ref HEAD 2>/dev/null", "r");
#endif
    
    if (pipe) {
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result = buffer;
            result.erase(result.find_last_not_of("\r\n") + 1);
        }
#ifdef _WIN32
        _pclose(pipe);
#else
        pclose(pipe);
#endif
    }
    
    return result;
}

std::string GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

double CalculateMean(const std::vector<double>& samples) {
    if (samples.empty()) return 0.0;
    
    double sum = 0.0;
    for (double s : samples) sum += s;
    return sum / samples.size();
}

double CalculateStdDev(const std::vector<double>& samples) {
    if (samples.size() < 2) return 0.0;
    
    double mean = CalculateMean(samples);
    double sq_sum = 0.0;
    for (double s : samples) {
        sq_sum += (s - mean) * (s - mean);
    }
    return std::sqrt(sq_sum / samples.size());
}

ConfidenceInterval CalculateCI(const std::vector<double>& samples, double confidence) {
    return StatisticalMetrics::CalculateMeanCI(samples, confidence);
}

} // namespace baseline_utils

} // namespace rawrxd::benchmark
