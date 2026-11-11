//============================================================================
// nevm_trend_tracker.hpp
// RawrXD N-EVM - Historical Trend Tracking
// Stores validation results over time for drift detection
//============================================================================

#pragma once

#include <vector>
#include <string>
#include <map>
#include <json/json.h>
#include <chrono>
#include <fstream>
#include <filesystem>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Historical Data Point
//============================================================================

struct HistoricalDataPoint {
    std::string timestamp;
    std::string git_commit;
    std::string branch;
    
    // Performance metrics
    float throughput_tok_s;
    float memory_mb;
    float latency_p99_ms;
    float latency_p95_ms;
    float latency_mean_ms;
    
    // Stability metrics
    float throughput_variance;
    float rss_slope;
    float throughput_drift;
    
    // Status
    bool all_gates_passed;
    int gates_passed;
    int gates_failed;
    
    Json::Value ToJSON() const {
        Json::Value point;
        point["timestamp"] = timestamp;
        point["git_commit"] = git_commit;
        point["branch"] = branch;
        point["throughput_tok_s"] = throughput_tok_s;
        point["memory_mb"] = memory_mb;
        point["latency_p99_ms"] = latency_p99_ms;
        point["latency_p95_ms"] = latency_p95_ms;
        point["latency_mean_ms"] = latency_mean_ms;
        point["throughput_variance"] = throughput_variance;
        point["rss_slope"] = rss_slope;
        point["throughput_drift"] = throughput_drift;
        point["all_gates_passed"] = all_gates_passed;
        point["gates_passed"] = gates_passed;
        point["gates_failed"] = gates_failed;
        return point;
    }
    
    static HistoricalDataPoint FromJSON(const Json::Value& json) {
        HistoricalDataPoint point;
        point.timestamp = json.get("timestamp", "").asString();
        point.git_commit = json.get("git_commit", "").asString();
        point.branch = json.get("branch", "").asString();
        point.throughput_tok_s = json.get("throughput_tok_s", 0.0f).asFloat();
        point.memory_mb = json.get("memory_mb", 0.0f).asFloat();
        point.latency_p99_ms = json.get("latency_p99_ms", 0.0f).asFloat();
        point.latency_p95_ms = json.get("latency_p95_ms", 0.0f).asFloat();
        point.latency_mean_ms = json.get("latency_mean_ms", 0.0f).asFloat();
        point.throughput_variance = json.get("throughput_variance", 0.0f).asFloat();
        point.rss_slope = json.get("rss_slope", 0.0f).asFloat();
        point.throughput_drift = json.get("throughput_drift", 0.0f).asFloat();
        point.all_gates_passed = json.get("all_gates_passed", false).asBool();
        point.gates_passed = json.get("gates_passed", 0).asInt();
        point.gates_failed = json.get("gates_failed", 0).asInt();
        return point;
    }
};

//============================================================================
// Trend Analysis Result
//============================================================================

struct TrendAnalysis {
    std::string metric_name;
    float slope;              // Linear regression slope
    float r_squared;          // Goodness of fit
    float mean;               // Average value
    float std_dev;            // Standard deviation
    float min_val;            // Minimum observed
    float max_val;            // Maximum observed
    float current_val;        // Most recent value
    float change_pct;         // Percentage change from first to last
    
    bool IsSignificant(float threshold_pct = 5.0f) const {
        return std::abs(change_pct) > threshold_pct;
    }
    
    bool IsDegrading() const {
        return slope < 0 && IsSignificant();
    }
    
    bool IsImproving() const {
        return slope > 0 && IsSignificant();
    }
    
    Json::Value ToJSON() const {
        Json::Value trend;
        trend["metric_name"] = metric_name;
        trend["slope"] = slope;
        trend["r_squared"] = r_squared;
        trend["mean"] = mean;
        trend["std_dev"] = std_dev;
        trend["min"] = min_val;
        trend["max"] = max_val;
        trend["current"] = current_val;
        trend["change_pct"] = change_pct;
        trend["is_significant"] = IsSignificant();
        trend["is_degrading"] = IsDegrading();
        trend["is_improving"] = IsImproving();
        return trend;
    }
};

//============================================================================
// Drift Detection
//============================================================================

class DriftDetector {
public:
    struct Config {
        float throughput_drift_threshold_pct = 5.0f;
        float memory_growth_threshold_pct = 10.0f;
        float latency_regression_threshold_pct = 10.0f;
        int min_samples = 5;
    };
    
    DriftDetector(const Config& config = Config()) : config_(config) {}
    
    // Detect performance drift
    std::vector<std::string> DetectDrift(const std::vector<HistoricalDataPoint>& history) {
        std::vector<std::string> alerts;
        
        if (history.size() < config_.min_samples) {
            return alerts;  // Not enough data
        }
        
        // Analyze throughput trend
        auto throughput_trend = AnalyzeTrend(history, 
            [](const HistoricalDataPoint& p) { return p.throughput_tok_s; });
        
        if (throughput_trend.IsDegrading() && 
            std::abs(throughput_trend.change_pct) > config_.throughput_drift_threshold_pct) {
            alerts.push_back("Throughput degradation detected: " + 
                           std::to_string(throughput_trend.change_pct) + "% change");
        }
        
        // Analyze memory trend
        auto memory_trend = AnalyzeTrend(history,
            [](const HistoricalDataPoint& p) { return p.memory_mb; });
        
        if (memory_trend.IsDegrading() &&
            std::abs(memory_trend.change_pct) > config_.memory_growth_threshold_pct) {
            alerts.push_back("Memory growth detected: " +
                           std::to_string(memory_trend.change_pct) + "% change");
        }
        
        // Analyze latency trend
        auto latency_trend = AnalyzeTrend(history,
            [](const HistoricalDataPoint& p) { return p.latency_p99_ms; });
        
        if (latency_trend.IsDegrading() &&
            std::abs(latency_trend.change_pct) > config_.latency_regression_threshold_pct) {
            alerts.push_back("Latency regression detected: " +
                           std::to_string(latency_trend.change_pct) + "% change");
        }
        
        return alerts;
    }
    
    // Get trend analysis for all metrics
    std::vector<TrendAnalysis> AnalyzeAllTrends(const std::vector<HistoricalDataPoint>& history) {
        std::vector<TrendAnalysis> trends;
        
        if (history.size() < 2) return trends;
        
        trends.push_back(AnalyzeTrend(history, 
            [](const HistoricalDataPoint& p) { return p.throughput_tok_s; }, "throughput_tok_s"));
        trends.push_back(AnalyzeTrend(history,
            [](const HistoricalDataPoint& p) { return p.memory_mb; }, "memory_mb"));
        trends.push_back(AnalyzeTrend(history,
            [](const HistoricalDataPoint& p) { return p.latency_p99_ms; }, "latency_p99_ms"));
        trends.push_back(AnalyzeTrend(history,
            [](const HistoricalDataPoint& p) { return p.throughput_variance; }, "throughput_variance"));
        
        return trends;
    }

private:
    Config config_;
    
    template<typename T>
    TrendAnalysis AnalyzeTrend(const std::vector<HistoricalDataPoint>& history,
                               std::function<float(const HistoricalDataPoint&)> extractor,
                               const std::string& name = "") {
        TrendAnalysis trend;
        trend.metric_name = name;
        
        if (history.empty()) return trend;
        
        // Calculate statistics
        float sum = 0.0f;
        float min_val = std::numeric_limits<float>::max();
        float max_val = std::numeric_limits<float>::lowest();
        
        for (const auto& point : history) {
            float val = extractor(point);
            sum += val;
            min_val = std::min(min_val, val);
            max_val = std::max(max_val, val);
        }
        
        trend.mean = sum / history.size();
        trend.min_val = min_val;
        trend.max_val = max_val;
        trend.current_val = extractor(history.back());
        
        // Calculate standard deviation
        float variance = 0.0f;
        for (const auto& point : history) {
            float diff = extractor(point) - trend.mean;
            variance += diff * diff;
        }
        trend.std_dev = std::sqrt(variance / history.size());
        
        // Linear regression
        if (history.size() >= 2) {
            float n = static_cast<float>(history.size());
            float sum_x = 0.0f, sum_y = 0.0f, sum_xy = 0.0f, sum_x2 = 0.0f;
            
            for (size_t i = 0; i < history.size(); ++i) {
                float x = static_cast<float>(i);
                float y = extractor(history[i]);
                sum_x += x;
                sum_y += y;
                sum_xy += x * y;
                sum_x2 += x * x;
            }
            
            float denominator = n * sum_x2 - sum_x * sum_x;
            if (denominator != 0.0f) {
                trend.slope = (n * sum_xy - sum_x * sum_y) / denominator;
            }
            
            // Calculate R-squared (simplified)
            float ss_res = 0.0f, ss_tot = 0.0f;
            for (size_t i = 0; i < history.size(); ++i) {
                float predicted = trend.mean + trend.slope * (static_cast<float>(i) - sum_x / n);
                float actual = extractor(history[i]);
                ss_res += (actual - predicted) * (actual - predicted);
                ss_tot += (actual - trend.mean) * (actual - trend.mean);
            }
            trend.r_squared = (ss_tot > 0.0f) ? 1.0f - (ss_res / ss_tot) : 0.0f;
            
            // Calculate percentage change
            float first = extractor(history.front());
            float last = extractor(history.back());
            if (first != 0.0f) {
                trend.change_pct = ((last - first) / first) * 100.0f;
            }
        }
        
        return trend;
    }
};

//============================================================================
// Trend Database
//============================================================================

class TrendDatabase {
public:
    TrendDatabase(const std::string& db_path = "trend_history.json") 
        : db_path_(db_path) {
        Load();
    }
    
    // Add a new data point
    void AddPoint(const HistoricalDataPoint& point) {
        history_.push_back(point);
        Save();
    }
    
    // Get all history
    const std::vector<HistoricalDataPoint>& GetHistory() const {
        return history_;
    }
    
    // Get recent history (last N points)
    std::vector<HistoricalDataPoint> GetRecentHistory(size_t n) const {
        if (n >= history_.size()) return history_;
        return std::vector<HistoricalDataPoint>(
            history_.end() - n, history_.end());
    }
    
    // Get history for branch
    std::vector<HistoricalDataPoint> GetBranchHistory(const std::string& branch) const {
        std::vector<HistoricalDataPoint> branch_history;
        for (const auto& point : history_) {
            if (point.branch == branch) {
                branch_history.push_back(point);
            }
        }
        return branch_history;
    }
    
    // Clear old data (keep last N days)
    void PruneOldData(int days_to_keep = 90) {
        auto cutoff = std::chrono::system_clock::now() - 
                      std::chrono::hours(24 * days_to_keep);
        
        // Would parse timestamps and filter
        // For now, keep last 1000 points
        if (history_.size() > 1000) {
            history_.erase(history_.begin(), history_.end() - 1000);
        }
        
        Save();
    }
    
    // Export to CSV for external analysis
    void ExportToCSV(const std::string& csv_path) const {
        std::ofstream file(csv_path);
        
        // Header
        file << "timestamp,git_commit,branch,throughput_tok_s,memory_mb,";
        file << "latency_p99_ms,latency_p95_ms,latency_mean_ms,";
        file << "throughput_variance,rss_slope,throughput_drift,";
        file << "all_gates_passed,gates_passed,gates_failed\n";
        
        // Data
        for (const auto& point : history_) {
            file << point.timestamp << ",";
            file << point.git_commit << ",";
            file << point.branch << ",";
            file << point.throughput_tok_s << ",";
            file << point.memory_mb << ",";
            file << point.latency_p99_ms << ",";
            file << point.latency_p95_ms << ",";
            file << point.latency_mean_ms << ",";
            file << point.throughput_variance << ",";
            file << point.rss_slope << ",";
            file << point.throughput_drift << ",";
            file << (point.all_gates_passed ? "true" : "false") << ",";
            file << point.gates_passed << ",";
            file << point.gates_failed << "\n";
        }
    }
    
    // Generate trend report
    Json::Value GenerateReport(int days = 30) const {
        Json::Value report;
        
        auto recent = GetRecentHistory(days);
        
        report["summary"]["total_runs"] = static_cast<int>(history_.size());
        report["summary"]["recent_runs"] = static_cast<int>(recent.size());
        report["summary"]["db_path"] = db_path_;
        
        if (!recent.empty()) {
            DriftDetector detector;
            auto trends = detector.AnalyzeAllTrends(recent);
            
            Json::Value trends_json(Json::arrayValue);
            for (const auto& trend : trends) {
                trends_json.append(trend.ToJSON());
            }
            report["trends"] = trends_json;
            
            auto alerts = detector.DetectDrift(recent);
            Json::Value alerts_json(Json::arrayValue);
            for (const auto& alert : alerts) {
                alerts_json.append(alert);
            }
            report["alerts"] = alerts_json;
        }
        
        return report;
    }

private:
    std::string db_path_;
    std::vector<HistoricalDataPoint> history_;
    
    void Load() {
        if (!std::filesystem::exists(db_path_)) return;
        
        std::ifstream file(db_path_);
        if (!file) return;
        
        Json::Value root;
        file >> root;
        
        const Json::Value& points = root["history"];
        for (const auto& point : points) {
            history_.push_back(HistoricalDataPoint::FromJSON(point));
        }
    }
    
    void Save() {
        Json::Value root;
        Json::Value points(Json::arrayValue);
        
        for (const auto& point : history_) {
            points.append(point.ToJSON());
        }
        
        root["history"] = points;
        root["last_updated"] = GetCurrentTimestamp();
        
        std::ofstream file(db_path_);
        Json::StreamWriterBuilder builder;
        std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
        writer->write(root, &file);
    }
    
    std::string GetCurrentTimestamp() const {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

} // namespace NEVM
} // namespace RawrXD
