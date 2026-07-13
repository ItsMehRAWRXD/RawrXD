// anomaly_detector.cpp
// Batch 12: Anomaly Detection Engine
//
// Detects unusual patterns in benchmark results
// Features: Statistical, ML-based, and rule-based detection

#include <vector>
#include <cmath>
#include <numeric>
#include <algorithm>
#include <optional>
#include <map>

namespace Benchmark {
namespace Analytics {

// Anomaly detection result
struct AnomalyResult {
    size_t index;
    double value;
    double expected_value;
    double deviation;
    double severity;           // 0-1, higher = more anomalous
    std::string type;          // "statistical", "ml", "rule"
    std::string description;
    bool is_anomaly;
};

// Statistical anomaly detector
class StatisticalAnomalyDetector {
public:
    struct Config {
        double z_score_threshold = 3.0;      // Standard deviations
        double iqr_multiplier = 1.5;         // IQR method
        bool use_modified_zscore = false;    // Use MAD instead of std dev
        double min_severity = 0.5;           // Minimum to report
    };
    
    static std::vector<AnomalyResult> Detect(
        const std::vector<double>& data,
        const Config& config = Config()) {
        
        std::vector<AnomalyResult> anomalies;
        
        if (data.size() < 3) return anomalies;
        
        // Calculate statistics
        double mean = std::accumulate(data.begin(), data.end(), 0.0) / data.size();
        
        double variance = 0.0;
        for (double x : data) {
            variance += (x - mean) * (x - mean);
        }
        variance /= data.size();
        double std_dev = std::sqrt(variance);
        
        // Calculate median and MAD for modified z-score
        std::vector<double> sorted = data;
        std::sort(sorted.begin(), sorted.end());
        double median = sorted[sorted.size() / 2];
        
        std::vector<double> abs_deviations;
        for (double x : data) {
            abs_deviations.push_back(std::abs(x - median));
        }
        std::sort(abs_deviations.begin(), abs_deviations.end());
        double mad = abs_deviations[abs_deviations.size() / 2];
        
        // Calculate IQR
        size_t q1_idx = sorted.size() / 4;
        size_t q3_idx = 3 * sorted.size() / 4;
        double q1 = sorted[q1_idx];
        double q3 = sorted[q3_idx];
        double iqr = q3 - q1;
        double lower_bound = q1 - config.iqr_multiplier * iqr;
        double upper_bound = q3 + config.iqr_multiplier * iqr;
        
        // Detect anomalies
        for (size_t i = 0; i < data.size(); ++i) {
            AnomalyResult result = {};
            result.index = i;
            result.value = data[i];
            result.expected_value = mean;
            
            // Z-score method
            double z_score = (std_dev > 0) ? std::abs(data[i] - mean) / std_dev : 0.0;
            
            // Modified Z-score (using MAD)
            double modified_z_score = (mad > 0) ? 
                0.6745 * std::abs(data[i] - median) / mad : 0.0;
            
            // IQR method
            bool iqr_anomaly = data[i] < lower_bound || data[i] > upper_bound;
            
            // Determine if anomaly
            double score = config.use_modified_zscore ? modified_z_score : z_score;
            bool is_anomaly = score > config.z_score_threshold || iqr_anomaly;
            
            if (is_anomaly) {
                result.is_anomaly = true;
                result.deviation = data[i] - mean;
                result.severity = std::min(score / (config.z_score_threshold * 2), 1.0);
                result.type = "statistical";
                
                if (result.severity >= config.min_severity) {
                    if (data[i] > mean) {
                        result.description = "Unusually high value";
                    } else {
                        result.description = "Unusually low value";
                    }
                    anomalies.push_back(result);
                }
            }
        }
        
        return anomalies;
    }
    
    // Detect contextual anomalies (based on local context)
    static std::vector<AnomalyResult> DetectContextual(
        const std::vector<double>& data,
        size_t context_window = 10,
        double threshold = 2.0) {
        
        std::vector<AnomalyResult> anomalies;
        
        if (data.size() < context_window * 2) return anomalies;
        
        for (size_t i = context_window; i < data.size() - context_window; ++i) {
            // Calculate local statistics
            double local_sum = 0.0;
            for (size_t j = i - context_window; j < i; ++j) {
                local_sum += data[j];
            }
            for (size_t j = i + 1; j <= i + context_window; ++j) {
                local_sum += data[j];
            }
            double local_mean = local_sum / (context_window * 2);
            
            double local_var = 0.0;
            for (size_t j = i - context_window; j < i; ++j) {
                local_var += (data[j] - local_mean) * (data[j] - local_mean);
            }
            for (size_t j = i + 1; j <= i + context_window; ++j) {
                local_var += (data[j] - local_mean) * (data[j] - local_mean);
            }
            double local_std = std::sqrt(local_var / (context_window * 2));
            
            // Check if current point is anomalous in context
            double z_score = (local_std > 0) ? 
                std::abs(data[i] - local_mean) / local_std : 0.0;
            
            if (z_score > threshold) {
                AnomalyResult result;
                result.index = i;
                result.value = data[i];
                result.expected_value = local_mean;
                result.deviation = data[i] - local_mean;
                result.severity = std::min(z_score / (threshold * 2), 1.0);
                result.type = "contextual";
                result.is_anomaly = true;
                result.description = "Anomalous in local context";
                anomalies.push_back(result);
            }
        }
        
        return anomalies;
    }
};

// Isolation Forest (simplified implementation)
class IsolationForestDetector {
public:
    struct Config {
        int n_trees = 100;
        int sample_size = 256;
        double contamination = 0.1;  // Expected anomaly ratio
    };
    
    static std::vector<AnomalyResult> Detect(
        const std::vector<double>& data,
        const Config& config = Config()) {
        
        std::vector<AnomalyResult> anomalies;
        
        if (data.size() < 10) return anomalies;
        
        // Simplified isolation forest using random partitioning
        std::vector<double> scores(data.size(), 0.0);
        
        for (int tree = 0; tree < config.n_trees; ++tree) {
            // Random subsample
            std::vector<size_t> sample_indices;
            size_t actual_sample = std::min(config.sample_size, static_cast<int>(data.size()));
            
            for (size_t i = 0; i < actual_sample; ++i) {
                sample_indices.push_back(rand() % data.size());
            }
            
            // Build tree and calculate path lengths
            for (size_t i = 0; i < data.size(); ++i) {
                double path_length = CalculatePathLength(data, sample_indices, data[i]);
                scores[i] += path_length;
            }
        }
        
        // Average scores
        for (auto& score : scores) {
            score /= config.n_trees;
        }
        
        // Normalize and identify anomalies
        double mean_score = std::accumulate(scores.begin(), scores.end(), 0.0) / scores.size();
        double variance = 0.0;
        for (double s : scores) {
            variance += (s - mean_score) * (s - mean_score);
        }
        variance /= scores.size();
        double std_score = std::sqrt(variance);
        
        // Anomalies have lower path lengths (isolated faster)
        double threshold = mean_score - 2 * std_score;
        
        for (size_t i = 0; i < data.size(); ++i) {
            if (scores[i] < threshold) {
                AnomalyResult result;
                result.index = i;
                result.value = data[i];
                result.severity = 1.0 - (scores[i] / mean_score);
                result.type = "isolation_forest";
                result.is_anomaly = true;
                result.description = "Isolated quickly in random forest";
                anomalies.push_back(result);
            }
        }
        
        return anomalies;
    }

private:
    static double CalculatePathLength(const std::vector<double>& data,
                                       const std::vector<size_t>& sample_indices,
                                       double value,
                                       int current_depth = 0,
                                       int max_depth = 10) {
        if (current_depth >= max_depth || sample_indices.size() <= 1) {
            return current_depth;
        }
        
        // Find min and max in sample
        double min_val = data[sample_indices[0]];
        double max_val = data[sample_indices[0]];
        for (size_t idx : sample_indices) {
            min_val = std::min(min_val, data[idx]);
            max_val = std::max(max_val, data[idx]);
        }
        
        if (min_val == max_val) {
            return current_depth;
        }
        
        // Random split
        double split = min_val + static_cast<double>(rand()) / RAND_MAX * (max_val - min_val);
        
        // Partition
        std::vector<size_t> left, right;
        for (size_t idx : sample_indices) {
            if (data[idx] < split) {
                left.push_back(idx);
            } else {
                right.push_back(idx);
            }
        }
        
        // Recurse
        if (value < split) {
            return CalculatePathLength(data, left, value, current_depth + 1, max_depth);
        } else {
            return CalculatePathLength(data, right, value, current_depth + 1, max_depth);
        }
    }
};

// Rule-based anomaly detector
class RuleBasedAnomalyDetector {
public:
    using Rule = std::function<std::optional<AnomalyResult>(size_t, double)>;
    
    static std::vector<AnomalyResult> Detect(
        const std::vector<double>& data,
        const std::vector<Rule>& rules) {
        
        std::vector<AnomalyResult> anomalies;
        
        for (size_t i = 0; i < data.size(); ++i) {
            for (const auto& rule : rules) {
                auto result = rule(i, data[i]);
                if (result) {
                    anomalies.push_back(*result);
                }
            }
        }
        
        return anomalies;
    }
    
    // Predefined rules
    static Rule ThresholdRule(double min_val, double max_val) {
        return [min_val, max_val](size_t idx, double val) -> std::optional<AnomalyResult> {
            if (val < min_val || val > max_val) {
                AnomalyResult result;
                result.index = idx;
                result.value = val;
                result.type = "rule";
                result.is_anomaly = true;
                result.severity = (val < min_val) ? 
                    (min_val - val) / min_val : (val - max_val) / max_val;
                result.description = "Value outside acceptable threshold";
                return result;
            }
            return std::nullopt;
        };
    }
    
    static Rule RateOfChangeRule(double max_change) {
        double prev_value = 0.0;
        bool has_prev = false;
        
        return [max_change, &prev_value, &has_prev](size_t idx, double val) 
            -> std::optional<AnomalyResult> {
            
            if (!has_prev) {
                prev_value = val;
                has_prev = true;
                return std::nullopt;
            }
            
            double change = std::abs(val - prev_value);
            if (change > max_change) {
                AnomalyResult result;
                result.index = idx;
                result.value = val;
                result.type = "rule";
                result.is_anomaly = true;
                result.severity = change / max_change;
                result.description = "Excessive rate of change";
                
                prev_value = val;
                return result;
            }
            
            prev_value = val;
            return std::nullopt;
        };
    }
    
    static Rule BusinessHoursRule(int start_hour, int end_hour) {
        return [start_hour, end_hour](size_t idx, double val) -> std::optional<AnomalyResult> {
            // Simplified: assume idx corresponds to hour
            int hour = idx % 24;
            if (hour < start_hour || hour > end_hour) {
                AnomalyResult result;
                result.index = idx;
                result.value = val;
                result.type = "rule";
                result.is_anomaly = true;
                result.severity = 0.3;
                result.description = "Activity outside business hours";
                return result;
            }
            return std::nullopt;
        };
    }
};

// Ensemble anomaly detector
class EnsembleAnomalyDetector {
public:
    struct Config {
        bool use_statistical = true;
        bool use_isolation_forest = true;
        bool use_rules = true;
        double voting_threshold = 0.5;  // Fraction of detectors that must agree
    };
    
    static std::vector<AnomalyResult> Detect(
        const std::vector<double>& data,
        const Config& config = Config()) {
        
        std::vector<std::vector<AnomalyResult>> all_results;
        
        if (config.use_statistical) {
            all_results.push_back(
                StatisticalAnomalyDetector::Detect(data));
        }
        
        if (config.use_isolation_forest) {
            all_results.push_back(
                IsolationForestDetector::Detect(data));
        }
        
        // Combine results using voting
        std::map<size_t, std::vector<AnomalyResult>> votes;
        
        for (const auto& detector_results : all_results) {
            for (const auto& result : detector_results) {
                votes[result.index].push_back(result);
            }
        }
        
        std::vector<AnomalyResult> ensemble_results;
        int min_votes = static_cast<int>(all_results.size() * config.voting_threshold);
        
        for (const auto& [idx, results] : votes) {
            if (static_cast<int>(results.size()) >= min_votes) {
                // Average the results
                AnomalyResult ensemble;
                ensemble.index = idx;
                ensemble.value = results[0].value;
                ensemble.type = "ensemble";
                ensemble.is_anomaly = true;
                
                double total_severity = 0.0;
                for (const auto& r : results) {
                    total_severity += r.severity;
                }
                ensemble.severity = total_severity / results.size();
                ensemble.description = "Detected by " + 
                    std::to_string(results.size()) + " methods";
                
                ensemble_results.push_back(ensemble);
            }
        }
        
        return ensemble_results;
    }
};

// Anomaly report generator
struct AnomalyReport {
    size_t total_points;
    size_t anomaly_count;
    double anomaly_rate;
    std::vector<AnomalyResult> anomalies;
    std::map<std::string, size_t> anomalies_by_type;
    std::string summary;
    
    static AnomalyReport Generate(const std::vector<double>& data,
                                   const std::vector<AnomalyResult>& anomalies) {
        AnomalyReport report;
        report.total_points = data.size();
        report.anomaly_count = anomalies.size();
        report.anomaly_rate = data.size() > 0 ? 
            static_cast<double>(anomalies.size()) / data.size() : 0.0;
        report.anomalies = anomalies;
        
        for (const auto& a : anomalies) {
            report.anomalies_by_type[a.type]++;
        }
        
        // Generate summary
        if (report.anomaly_rate < 0.01) {
            report.summary = "No significant anomalies detected";
        } else if (report.anomaly_rate < 0.05) {
            report.summary = "Low anomaly rate - within normal bounds";
        } else if (report.anomaly_rate < 0.1) {
            report.summary = "Moderate anomaly rate - investigate recommended";
        } else {
            report.summary = "High anomaly rate - immediate attention required";
        }
        
        return report;
    }
};

} // namespace Analytics
} // namespace Benchmark
