// Phase D.6 Batch 2/5: Anomaly Detection
// Statistical and ML-Based Anomaly Detection
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "SovereignPredictiveAutoscaling.hpp"
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Sovereign {
namespace Intelligence {

// ============================================================================
// Anomaly Types
// ============================================================================

enum class AnomalyType {
    POINT_ANOMALY = 0,       // Single outlier point
    CONTEXTUAL_ANOMALY = 1,  // Anomalous in context
    COLLECTIVE_ANOMALY = 2,  // Group of points forming anomaly
    SEASONAL_ANOMALY = 3,    // Anomalous seasonal pattern
    TREND_ANOMALY = 4,       // Unexpected trend change
    CORRELATION_ANOMALY = 5  // Broken correlation between metrics
};

enum class AnomalySeverity {
    INFO = 0,
    WARNING = 1,
    CRITICAL = 2,
    EMERGENCY = 3
};

struct Anomaly {
    std::string anomaly_id;
    std::string metric_name;
    AnomalyType type;
    AnomalySeverity severity;
    double score = 0.0;  // 0.0 to 1.0
    std::chrono::steady_clock::time_point detected_at;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    double expected_value = 0.0;
    double actual_value = 0.0;
    std::map<std::string, std::string> context;
    std::vector<std::string> related_metrics;
    bool acknowledged = false;
    std::string root_cause;
};

// ============================================================================
// Detection Algorithms
// ============================================================================

enum class DetectionAlgorithm {
    STATISTICAL_ZSCORE = 0,
    ISOLATION_FOREST = 1,
    ONE_CLASS_SVM = 2,
    LSTM_AUTOENCODER = 3,
    DBSCAN = 4,
    GAUSSIAN_MIXTURE = 5,
    ENSEMBLE = 6
};

class AnomalyDetector {
public:
    struct Config {
        DetectionAlgorithm algorithm = DetectionAlgorithm::ENSEMBLE;
        double sensitivity = 0.95;  // True positive rate target
        double specificity = 0.99;  // True negative rate target
        int window_size = 100;
        int min_points = 10;
        bool enable_baseline_learning = true;
        int baseline_learning_hours = 168;  // 1 week
    };
    
    explicit AnomalyDetector(const Config& config);
    ~AnomalyDetector();
    
    bool Initialize();
    void Shutdown();
    
    // Detection
    std::vector<Anomaly> Detect(const std::string& metric_name,
                                 const TimeSeries& series);
    std::vector<Anomaly> DetectRealtime(const std::string& metric_name,
                                         double value,
                                         const std::map<std::string, std::string>& context);
    
    // Baseline management
    bool LearnBaseline(const std::string& metric_name,
                       const TimeSeries& historical_data);
    bool UpdateBaseline(const std::string& metric_name,
                        const TimeSeries& new_data);
    void ClearBaseline(const std::string& metric_name);
    
    // Threshold management
    void SetThreshold(const std::string& metric_name,
                       double lower_bound,
                       double upper_bound);
    void SetDynamicThreshold(const std::string& metric_name,
                              double std_dev_multiplier);
    
    // Model management
    bool ExportModel(const std::string& path);
    bool ImportModel(const std::string& path);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    struct Baseline {
        double mean = 0.0;
        double std_dev = 0.0;
        double min_value = 0.0;
        double max_value = 0.0;
        std::map<std::string, double> seasonal_patterns;
        std::chrono::steady_clock::time_point last_updated;
    };
    
    mutable std::mutex baselines_mutex_;
    std::map<std::string, Baseline> baselines_;
    
    std::vector<Anomaly> RunStatisticalDetection(const TimeSeries& series);
    std::vector<Anomaly> RunIsolationForest(const TimeSeries& series);
    std::vector<Anomaly> RunLSTMAutoencoder(const TimeSeries& series);
    std::vector<Anomaly> RunEnsemble(const TimeSeries& series);
    
    AnomalySeverity CalculateSeverity(double score);
};

// ============================================================================
// Root Cause Analyzer
// ============================================================================

class RootCauseAnalyzer {
public:
    struct Config {
        int correlation_window_minutes = 30;
        double correlation_threshold = 0.8;
        int max_depth = 5;
        bool enable_causal_inference = true;
    };
    
    explicit RootCauseAnalyzer(const Config& config);
    
    bool Initialize();
    
    // Analysis
    struct RootCause {
        std::string primary_cause;
        double confidence = 0.0;
        std::vector<std::string> contributing_factors;
        std::map<std::string, double> metric_correlations;
        std::chrono::steady_clock::time_point analysis_time;
        std::string recommended_action;
    };
    
    RootCause Analyze(const Anomaly& anomaly,
                      const std::map<std::string, TimeSeries>& related_metrics);
    
    // Correlation analysis
    std::map<std::string, double> FindCorrelations(
        const std::string& metric_name,
        const std::map<std::string, TimeSeries>& all_metrics);
    
    // Causal graph
    struct CausalNode {
        std::string metric_name;
        double impact_score = 0.0;
        std::vector<std::shared_ptr<CausalNode>> causes;
        std::vector<std::shared_ptr<CausalNode>> effects;
    };
    
    std::shared_ptr<CausalNode> BuildCausalGraph(
        const std::string& root_metric,
        const std::map<std::string, TimeSeries>& metrics);
    
private:
    Config config_;
    
    double CalculateCorrelation(const TimeSeries& series1,
                                 const TimeSeries& series2);
    std::vector<std::string> FindPotentialCauses(const Anomaly& anomaly,
                                                const std::map<std::string, double>& correlations);
};

// ============================================================================
// Alert Manager
// ============================================================================

class AlertManager {
public:
    struct Config {
        int deduplication_window_seconds = 300;
        int max_alerts_per_hour = 100;
        bool enable_alert_grouping = true;
        bool enable_severity_escalation = true;
    };
    
    struct AlertChannel {
        std::string channel_id;
        std::string type;  // "slack", "pagerduty", "email", "webhook"
        std::string endpoint;
        std::map<std::string, std::string> config;
        std::vector<AnomalySeverity> severity_filter;
    };
    
    explicit AlertManager(const Config& config);
    
    bool Initialize();
    
    // Channel management
    bool AddChannel(const AlertChannel& channel);
    bool RemoveChannel(const std::string& channel_id);
    std::vector<AlertChannel> GetChannels() const;
    
    // Alerting
    bool SendAlert(const Anomaly& anomaly);
    bool SendAlert(const std::vector<Anomaly>& anomalies);
    
    // Deduplication
    bool ShouldSuppress(const Anomaly& anomaly);
    void AcknowledgeAlert(const std::string& anomaly_id);
    
    // Alert history
    struct AlertHistory {
        std::string anomaly_id;
        AnomalySeverity severity;
        std::chrono::steady_clock::time_point sent_at;
        std::vector<std::string> channels_used;
        bool acknowledged = false;
        std::chrono::steady_clock::time_point acknowledged_at;
    };
    
    std::vector<AlertHistory> GetAlertHistory(int limit = 100) const;
    
private:
    Config config_;
    
    mutable std::mutex channels_mutex_;
    std::map<std::string, AlertChannel> channels_;
    
    mutable std::mutex history_mutex_;
    std::vector<AlertHistory> alert_history_;
    
    mutable std::mutex suppression_mutex_;
    std::map<std::string, std::chrono::steady_clock::time_point> last_alert_time_;
    
    bool SendToSlack(const Anomaly& anomaly, const AlertChannel& channel);
    bool SendToPagerDuty(const Anomaly& anomaly, const AlertChannel& channel);
    bool SendToEmail(const Anomaly& anomaly, const AlertChannel& channel);
    bool SendToWebhook(const Anomaly& anomaly, const AlertChannel& channel);
};

} // namespace Intelligence
} // namespace Sovereign
