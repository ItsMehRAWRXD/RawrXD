// result_aggregator.cpp
// Batch 14: Distributed Result Aggregation
//
// Aggregates results from multiple worker nodes
// Features: Statistical merging, consensus checking, outlier handling

#include <vector>
#include <map>
#include <string>
#include <numeric>
#include <algorithm>
#include <cmath>
#include <optional>

namespace Benchmark {
namespace Distributed {

// Partial result from a worker
struct PartialResult {
    std::string job_id;
    std::string node_id;
    std::string benchmark_id;
    int64_t timestamp;
    std::map<std::string, double> metrics;
    std::map<std::string, std::string> metadata;
    bool success;
    std::string error_message;
    int sample_count;
};

// Aggregated result
struct AggregatedResult {
    std::string job_id;
    std::string benchmark_id;
    int total_samples;
    int successful_nodes;
    int failed_nodes;
    std::map<std::string, double> aggregated_metrics;
    std::map<std::string, double> metric_std_devs;
    std::map<std::string, std::vector<double>> raw_values;
    double consensus_score;
    std::vector<std::string> outlier_nodes;
    std::vector<std::string> error_messages;
    int64_t aggregation_time;
};

// Result aggregator
class ResultAggregator {
public:
    struct Config {
        double outlier_threshold = 2.0;  // Standard deviations
        double min_consensus = 0.67;      // 2/3 majority
        bool exclude_outliers = true;
        bool require_consensus = true;
    };

    explicit ResultAggregator(const Config& config = Config())
        : config_(config) {}

    // Add partial result
    void AddPartialResult(const PartialResult& result) {
        partial_results_[result.node_id] = result;
    }

    // Aggregate all results
    AggregatedResult Aggregate(const std::string& job_id,
                                const std::string& benchmark_id) {
        AggregatedResult aggregated;
        aggregated.job_id = job_id;
        aggregated.benchmark_id = benchmark_id;
        aggregated.total_samples = partial_results_.size();

        auto start_time = std::chrono::steady_clock::now();

        // Separate successful and failed results
        std::vector<PartialResult> successful;
        for (const auto& [node_id, result] : partial_results_) {
            if (result.success) {
                successful.push_back(result);
            } else {
                aggregated.failed_nodes++;
                aggregated.error_messages.push_back(result.error_message);
            }
        }

        aggregated.successful_nodes = successful.size();

        if (successful.empty()) {
            aggregated.consensus_score = 0.0;
            return aggregated;
        }

        // Collect all metrics
        std::set<std::string> metric_names;
        for (const auto& result : successful) {
            for (const auto& [name, value] : result.metrics) {
                metric_names.insert(name);
                aggregated.raw_values[name].push_back(value);
            }
        }

        // Aggregate each metric
        for (const auto& metric_name : metric_names) {
            std::vector<double> values;
            for (const auto& result : successful) {
                auto it = result.metrics.find(metric_name);
                if (it != result.metrics.end()) {
                    values.push_back(it->second);
                }
            }

            if (values.empty()) continue;

            // Detect outliers
            auto outliers = DetectOutliers(values);
            if (!outliers.empty() && config_.exclude_outliers) {
                // Remove outliers
                for (auto it = values.begin(); it != values.end();) {
                    if (std::find(outliers.begin(), outliers.end(),
                                  std::distance(values.begin(), it)) != outliers.end()) {
                        it = values.erase(it);
                    } else {
                        ++it;
                    }
                }

                // Track outlier nodes
                for (size_t idx : outliers) {
                    aggregated.outlier_nodes.push_back(successful[idx].node_id);
                }
            }

            // Calculate statistics
            if (!values.empty()) {
                aggregated.aggregated_metrics[metric_name] = CalculateMean(values);
                aggregated.metric_std_devs[metric_name] = CalculateStdDev(values);
            }
        }

        // Calculate consensus score
        aggregated.consensus_score = CalculateConsensusScore(successful);

        auto end_time = std::chrono::steady_clock::now();
        aggregated.aggregation_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count();

        return aggregated;
    }

    // Check if results have consensus
    bool HasConsensus() const {
        if (partial_results_.size() < 3) return true;

        // Group results by similarity
        std::map<std::string, int> result_groups;

        for (const auto& [node_id, result] : partial_results_) {
            if (!result.success) continue;

            // Create fingerprint of key metrics
            std::string fingerprint;
            for (const auto& [name, value] : result.metrics) {
                if (name == "tps" || name == "latency" || name == "ttft") {
                    fingerprint += std::to_string(static_cast<int>(value)) + ",";
                }
            }

            result_groups[fingerprint]++;
        }

        // Find largest group
        int max_group = 0;
        for (const auto& [fingerprint, count] : result_groups) {
            max_group = std::max(max_group, count);
        }

        double consensus = static_cast<double>(max_group) / partial_results_.size();
        return consensus >= config_.min_consensus;
    }

    // Clear all results
    void Clear() {
        partial_results_.clear();
    }

    // Get partial result count
    size_t GetResultCount() const {
        return partial_results_.size();
    }

    // Get results from specific node
    std::optional<PartialResult> GetNodeResult(const std::string& node_id) const {
        auto it = partial_results_.find(node_id);
        if (it != partial_results_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

private:
    Config config_;
    std::map<std::string, PartialResult> partial_results_;

    std::vector<size_t> DetectOutliers(const std::vector<double>& values) {
        std::vector<size_t> outliers;

        if (values.size() < 3) return outliers;

        double mean = CalculateMean(values);
        double std_dev = CalculateStdDev(values);

        if (std_dev == 0.0) return outliers;

        for (size_t i = 0; i < values.size(); ++i) {
            double z_score = std::abs(values[i] - mean) / std_dev;
            if (z_score > config_.outlier_threshold) {
                outliers.push_back(i);
            }
        }

        return outliers;
    }

    double CalculateMean(const std::vector<double>& values) {
        if (values.empty()) return 0.0;
        return std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    }

    double CalculateStdDev(const std::vector<double>& values) {
        if (values.size() < 2) return 0.0;

        double mean = CalculateMean(values);
        double variance = 0.0;

        for (double value : values) {
            variance += (value - mean) * (value - mean);
        }

        variance /= values.size();
        return std::sqrt(variance);
    }

    double CalculateConsensusScore(const std::vector<PartialResult>& results) {
        if (results.size() < 2) return 1.0;

        // Calculate pairwise similarity
        double total_similarity = 0.0;
        int comparisons = 0;

        for (size_t i = 0; i < results.size(); ++i) {
            for (size_t j = i + 1; j < results.size(); ++j) {
                total_similarity += CalculateSimilarity(results[i], results[j]);
                comparisons++;
            }
        }

        return comparisons > 0 ? total_similarity / comparisons : 1.0;
    }

    double CalculateSimilarity(const PartialResult& a, const PartialResult& b) {
        if (a.metrics.empty() || b.metrics.empty()) return 0.0;

        double total_similarity = 0.0;
        int common_metrics = 0;

        for (const auto& [name, value_a] : a.metrics) {
            auto it = b.metrics.find(name);
            if (it != b.metrics.end()) {
                double value_b = it->second;

                // Calculate relative difference
                double max_val = std::max(std::abs(value_a), std::abs(value_b));
                if (max_val > 0) {
                    double diff = std::abs(value_a - value_b) / max_val;
                    total_similarity += 1.0 - diff;
                } else {
                    total_similarity += 1.0;
                }

                common_metrics++;
            }
        }

        return common_metrics > 0 ? total_similarity / common_metrics : 0.0;
    }
};

// Distributed statistics calculator
class DistributedStatistics {
public:
    // Calculate global statistics from partial results
    static std::map<std::string, double> CalculateGlobalStats(
        const std::vector<AggregatedResult>& results) {

        std::map<std::string, std::vector<double>> all_values;

        // Collect all values
        for (const auto& result : results) {
            for (const auto& [metric, value] : result.aggregated_metrics) {
                all_values[metric].push_back(value);
            }
        }

        // Calculate statistics
        std::map<std::string, double> stats;
        for (const auto& [metric, values] : all_values) {
            if (!values.empty()) {
                stats[metric + "_mean"] = CalculateMean(values);
                stats[metric + "_std"] = CalculateStdDev(values);
                stats[metric + "_min"] = *std::min_element(values.begin(), values.end());
                stats[metric + "_max"] = *std::max_element(values.begin(), values.end());
            }
        }

        return stats;
    }

    // Detect stragglers (slow nodes)
    static std::vector<std::string> DetectStragglers(
        const std::vector<PartialResult>& results,
        const std::string& metric = "execution_time") {

        std::vector<std::string> stragglers;

        if (results.size() < 3) return stragglers;

        // Collect execution times
        std::vector<double> times;
        for (const auto& result : results) {
            auto it = result.metrics.find(metric);
            if (it != result.metrics.end()) {
                times.push_back(it->second);
            }
        }

        if (times.size() < 3) return stragglers;

        // Calculate median
        std::sort(times.begin(), times.end());
        double median = times[times.size() / 2];

        // Find stragglers (2x median)
        for (const auto& result : results) {
            auto it = result.metrics.find(metric);
            if (it != result.metrics.end()) {
                if (it->second > median * 2.0) {
                    stragglers.push_back(result.node_id);
                }
            }
        }

        return stragglers;
    }

private:
    static double CalculateMean(const std::vector<double>& values) {
        if (values.empty()) return 0.0;
        return std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    }

    static double CalculateStdDev(const std::vector<double>& values) {
        if (values.size() < 2) return 0.0;

        double mean = CalculateMean(values);
        double variance = 0.0;

        for (double value : values) {
            variance += (value - mean) * (value - mean);
        }

        variance /= values.size();
        return std::sqrt(variance);
    }
};

// Result merger for incremental aggregation
class IncrementalResultMerger {
public:
    // Merge new partial result into existing aggregation
    void Merge(const PartialResult& new_result) {
        // Update running statistics
        for (const auto& [metric, value] : new_result.metrics) {
            auto& stats = running_stats_[metric];
            stats.count++;
            stats.sum += value;
            stats.sum_squares += value * value;
            stats.values.push_back(value);
        }
    }

    // Get current aggregated result
    AggregatedResult GetCurrentResult(const std::string& job_id) {
        AggregatedResult result;
        result.job_id = job_id;
        result.total_samples = GetSampleCount();

        for (const auto& [metric, stats] : running_stats_) {
            if (stats.count > 0) {
                result.aggregated_metrics[metric] = stats.sum / stats.count;
                result.metric_std_devs[metric] = CalculateStdDev(stats);
                result.raw_values[metric] = stats.values;
            }
        }

        return result;
    }

    // Get sample count
    int GetSampleCount() const {
        if (running_stats_.empty()) return 0;
        return running_stats_.begin()->second.count;
    }

    // Reset merger
    void Reset() {
        running_stats_.clear();
    }

private:
    struct RunningStats {
        int count = 0;
        double sum = 0.0;
        double sum_squares = 0.0;
        std::vector<double> values;
    };

    std::map<std::string, RunningStats> running_stats_;

    double CalculateStdDev(const RunningStats& stats) {
        if (stats.count < 2) return 0.0;

        double mean = stats.sum / stats.count;
        double variance = (stats.sum_squares / stats.count) - (mean * mean);

        return variance > 0.0 ? std::sqrt(variance) : 0.0;
    }
};

} // namespace Distributed
} // namespace Benchmark
