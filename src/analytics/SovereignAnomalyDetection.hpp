// Phase D.18 Batch 3/5: Anomaly Detection
// Real-time anomaly detection and alerting
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace Analytics {

// Forward declarations
struct AnomalyDetector;
struct DetectionRule;
struct AnomalyEvent;

// ============================================================================
// Anomaly Detection Types
// ============================================================================

enum class DetectorType {
    STATISTICAL = 0,
    ML_BASED = 1,
    RULE_BASED = 2,
    THRESHOLD = 3,
    PATTERN = 4,
    ENSEMBLE = 5
};

enum class AnomalySeverity {
    INFO = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

enum class AnomalyStatus {
    ACTIVE = 0,
    ACKNOWLEDGED = 1,
    RESOLVED = 2,
    SUPPRESSED = 3
};

struct DetectionRule {
    std::string rule_id;
    std::string name;
    std::string description;
    DetectorType type;
    std::string metric_pattern;
    std::map<std::string, std::any> parameters;
    AnomalySeverity severity;
    bool enabled;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point last_triggered;
};

struct AnomalyEvent {
    std::string event_id;
    std::string rule_id;
    std::string metric_name;
    double observed_value;
    double expected_value;
    double deviation;
    AnomalySeverity severity;
    AnomalyStatus status;
    std::map<std::string, std::any> context;
    std::chrono::steady_clock::time_point detected_at;
    std::chrono::steady_clock::time_point acknowledged_at;
    std::chrono::steady_clock::time_point resolved_at;
    std::string acknowledged_by;
};

// ============================================================================
// Statistical Detector
// ============================================================================

class StatisticalDetector {
public:
    struct Config {
        int window_size = 100;
        double z_score_threshold = 3.0;
        double iqr_multiplier = 1.5;
        bool use_mad = true;  // Median Absolute Deviation
    };
    
    struct StatisticalProfile {
        double mean;
        double std_dev;
        double median;
        double mad;
        double q1;
        double q3;
        std::vector<double> historical_values;
    };
    
    explicit StatisticalDetector(const Config& config);
    ~StatisticalDetector();
    
    bool Initialize();
    void Shutdown();
    
    // Profile management
    void UpdateProfile(const std::string& metric_name, double value);
    StatisticalProfile GetProfile(const std::string& metric_name) const;
    
    // Detection
    std::optional<AnomalyEvent> Detect(const std::string& metric_name, double value);
    std::vector<AnomalyEvent> DetectBatch(const std::string& metric_name, 
                                          const std::vector<double>& values);
    
    // Methods
    bool IsOutlierZScore(double value, const StatisticalProfile& profile);
    bool IsOutlierIQR(double value, const StatisticalProfile& profile);
    bool IsOutlierMAD(double value, const StatisticalProfile& profile);
    
private:
    Config config_;
    std::map<std::string, StatisticalProfile> profiles_;
    mutable std::mutex profiles_mutex_;
    
    void CalculateStatistics(StatisticalProfile& profile);
    double CalculateMAD(const std::vector<double>& values, double median);
};

// ============================================================================
// ML-Based Detector
// ============================================================================

class MLAnomalyDetector {
public:
    struct Config {
        std::string model_type = "isolation_forest";
        int contamination = 5;  // Expected % of anomalies
        int n_estimators = 100;
        bool auto_retrain = true;
        int retrain_interval_hours = 24;
    };
    
    struct DetectionResult {
        bool is_anomaly;
        double anomaly_score;
        double confidence;
        std::map<std::string, std::any> features;
    };
    
    explicit MLAnomalyDetector(const Config& config);
    ~MLAnomalyDetector();
    
    bool Initialize();
    void Shutdown();
    
    // Training
    bool Train(const std::vector<std::vector<double>>& normal_data);
    bool Retrain();
    bool IsTrained() const;
    
    // Detection
    DetectionResult Detect(const std::vector<double>& features);
    std::vector<DetectionResult> DetectBatch(const std::vector<std::vector<double>>& features);
    
    // Feedback
    bool ReportFalsePositive(const std::vector<double>& features);
    bool ReportTruePositive(const std::vector<double>& features);
    
private:
    Config config_;
    bool trained_;
    void* model_;
    mutable std::mutex model_mutex_;
    
    void* CreateIsolationForest();
    void* CreateOneClassSVM();
    void* CreateAutoencoder();
};

// ============================================================================
// Rule-Based Detector
// ============================================================================

class RuleBasedDetector {
public:
    struct Config {
        int max_rules = 1000;
        bool enable_rule_chaining = true;
    };
    
    struct RuleCondition {
        std::string metric;
        std::string operator_;  // >, <, ==, !=, >=, <=
        double threshold;
        std::chrono::seconds duration;
    };
    
    explicit RuleBasedDetector(const Config& config);
    ~RuleBasedDetector();
    
    bool Initialize();
    void Shutdown();
    
    // Rule management
    std::string AddRule(const std::string& name, const std::vector<RuleCondition>& conditions,
                        AnomalySeverity severity);
    bool RemoveRule(const std::string& rule_id);
    bool UpdateRule(const std::string& rule_id, const DetectionRule& rule);
    bool EnableRule(const std::string& rule_id);
    bool DisableRule(const std::string& rule_id);
    
    // Detection
    std::vector<AnomalyEvent> EvaluateRules(const std::map<std::string, double>& metrics);
    std::optional<AnomalyEvent> EvaluateRule(const std::string& rule_id,
                                             const std::map<std::string, double>& metrics);
    
    // Queries
    std::vector<DetectionRule> GetAllRules() const;
    std::vector<DetectionRule> GetRulesBySeverity(AnomalySeverity severity) const;
    
private:
    Config config_;
    std::map<std::string, DetectionRule> rules_;
    std::map<std::string, std::vector<RuleCondition>> rule_conditions_;
    mutable std::mutex rules_mutex_;
    
    bool EvaluateCondition(const RuleCondition& condition, double value);
};

// ============================================================================
// Pattern Detector
// ============================================================================

class PatternDetector {
public:
    struct Config {
        int pattern_window = 10;
        double similarity_threshold = 0.8;
        bool detect_seasonality = true;
        int seasonality_period = 24;  // hours
    };
    
    struct Pattern {
        std::string pattern_id;
        std::vector<double> sequence;
        std::string pattern_type;
        double frequency;
        std::chrono::steady_clock::time_point last_seen;
    };
    
    struct PatternMatch {
        bool matched;
        std::string pattern_id;
        double similarity;
        int offset;
        bool is_anomaly;
    };
    
    explicit PatternDetector(const Config& config);
    ~PatternDetector();
    
    bool Initialize();
    void Shutdown();
    
    // Pattern learning
    bool LearnPattern(const std::string& metric_name, const std::vector<double>& sequence);
    bool LearnFromHistory(const std::string& metric_name, std::chrono::hours window);
    
    // Detection
    PatternMatch DetectPattern(const std::string& metric_name, 
                               const std::vector<double>& sequence);
    std::optional<AnomalyEvent> DetectPatternBreak(const std::string& metric_name,
                                                    const std::vector<double>& sequence);
    
    // Seasonality
    bool DetectSeasonality(const std::string& metric_name);
    std::vector<int> GetSeasonalPeriods(const std::string& metric_name) const;
    
private:
    Config config_;
    std::map<std::string, std::vector<Pattern>> patterns_;
    mutable std::mutex patterns_mutex_;
    
    double CalculateSimilarity(const std::vector<double>& a, const std::vector<double>& b);
    std::vector<double> Normalize(const std::vector<double>& sequence);
};

// ============================================================================
// Anomaly Alert Manager
// ============================================================================

class AnomalyAlertManager {
public:
    struct Config {
        std::chrono::seconds alert_cooldown{300};
        int max_alerts_per_hour = 100;
        bool deduplicate = true;
        std::chrono::seconds dedup_window{60};
    };
    
    struct AlertChannel {
        std::string name;
        std::string type;  // webhook, email, slack, pagerduty
        std::map<std::string, std::string> config;
        std::vector<AnomalySeverity> severities;
        bool enabled;
    };
    
    explicit AnomalyAlertManager(const Config& config);
    ~AnomalyAlertManager();
    
    bool Initialize();
    void Shutdown();
    
    // Alert handling
    bool SendAlert(const AnomalyEvent& event);
    bool AcknowledgeAlert(const std::string& event_id, const std::string& user);
    bool ResolveAlert(const std::string& event_id, const std::string& resolution);
    bool SuppressAlert(const std::string& event_id, std::chrono::minutes duration);
    
    // Channel management
    bool AddChannel(const AlertChannel& channel);
    bool RemoveChannel(const std::string& name);
    bool UpdateChannel(const std::string& name, const AlertChannel& channel);
    
    // Queries
    std::vector<AnomalyEvent> GetActiveAlerts() const;
    std::vector<AnomalyEvent> GetAlertHistory(std::chrono::hours window) const;
    std::vector<AnomalyEvent> GetAlertsBySeverity(AnomalySeverity severity) const;
    
private:
    Config config_;
    std::vector<AlertChannel> channels_;
    std::map<std::string, AnomalyEvent> active_alerts_;
    std::vector<AnomalyEvent> alert_history_;
    mutable std::mutex alerts_mutex_;
    
    bool ShouldAlert(const AnomalyEvent& event);
    bool IsDuplicate(const AnomalyEvent& event);
    bool SendToChannel(const AnomalyEvent& event, const AlertChannel& channel);
};

// ============================================================================
// Anomaly Detection Runtime
// ============================================================================

class AnomalyDetectionRuntime {
public:
    struct Config {
        StatisticalDetector::Config statistical;
        MLAnomalyDetector::Config ml;
        RuleBasedDetector::Config rules;
        PatternDetector::Config patterns;
        AnomalyAlertManager::Config alerts;
    };
    
    explicit AnomalyDetectionRuntime(const Config& config);
    ~AnomalyDetectionRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    StatisticalDetector* GetStatisticalDetector();
    MLAnomalyDetector* GetMLDetector();
    RuleBasedDetector* GetRuleDetector();
    PatternDetector* GetPatternDetector();
    AnomalyAlertManager* GetAlertManager();
    
    // High-level API
    std::vector<AnomalyEvent> DetectAnomalies(const std::map<std::string, double>& metrics);
    std::string AddDetectionRule(const std::string& name, DetectorType type,
                                  const std::map<std::string, std::any>& params);
    
    bool AcknowledgeAnomaly(const std::string& event_id, const std::string& user);
    bool ResolveAnomaly(const std::string& event_id);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<StatisticalDetector> statistical_detector_;
    std::unique_ptr<MLAnomalyDetector> ml_detector_;
    std::unique_ptr<RuleBasedDetector> rule_detector_;
    std::unique_ptr<PatternDetector> pattern_detector_;
    std::unique_ptr<AnomalyAlertManager> alert_manager_;
};

} // namespace Analytics
} // namespace Sovereign
