// Phase Q.1/5: Anomaly Detection System
// RawrXD Anomaly Detector - ML-powered anomaly detection

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <functional>
#include <optional>

namespace RawrXD {
namespace Intelligent {

// Anomaly types
enum class AnomalyType {
    PERFORMANCE_DEGRADATION,    // Latency, throughput issues
    RESOURCE_EXHAUSTION,        // Memory, CPU, GPU exhaustion
    ERROR_RATE_SPIKE,           // Sudden error increase
    TRAFFIC_ANOMALY,            // Unusual traffic patterns
    SECURITY_THREAT,            // Potential security issues
    DRIFT,                      // Model or data drift
    CONFIGURATION_CHANGE,       // Unexpected config changes
    DEPENDENCY_FAILURE,         // External dependency issues
    CAPACITY_ISSUE,             // Insufficient capacity
    CUSTOM                       // User-defined anomaly
};

// Anomaly severity
enum class AnomalySeverity {
    INFO,       // Informational, no action needed
    LOW,        // Minor issue, monitor
    MEDIUM,     // Moderate issue, investigate
    HIGH,       // Serious issue, act soon
    CRITICAL    // Critical issue, immediate action
};

// Time series data point
struct DataPoint {
    std::chrono::system_clock::time_point timestamp;
    double value;
    std::unordered_map<std::string, std::string> labels;
};

// Anomaly detection result
struct AnomalyResult {
    std::string id;
    AnomalyType type;
    AnomalySeverity severity;
    
    std::string metric_name;
    std::chrono::system_clock::time_point detected_at;
    std::chrono::system_clock::time_point started_at;  // When anomaly began
    
    double expected_value;
    double actual_value;
    double deviation_score;     // How far from normal (0-1)
    double confidence;          // Detection confidence (0-1)
    
    std::string description;
    std::vector<std::string> affected_resources;
    std::unordered_map<std::string, std::string> context;
    
    // Historical context
    std::vector<DataPoint> historical_baseline;
    std::vector<DataPoint> anomalous_period;
};

// Detection algorithm types
enum class DetectionAlgorithm {
    STATISTICAL_ZSCORE,         // Z-score based
    STATISTICAL_IQR,            // Interquartile range
    ML_ISOLATION_FOREST,        // Isolation forest
    ML_ONE_CLASS_SVM,           // One-class SVM
    ML_LSTM_AUTOENCODER,        // LSTM autoencoder
    SEASONAL_DECOMPOSITION,     // STL decomposition
    PROPRIETARY                 // Custom algorithm
};

// Detector configuration
struct DetectorConfig {
    std::string id;
    std::string name;
    std::string metric_pattern;   // Regex for metric names
    DetectionAlgorithm algorithm;
    
    // Algorithm parameters
    struct Parameters {
        double sensitivity;         // Detection sensitivity (0-1)
        double min_anomaly_ratio;   // Minimum anomalous points
        uint32_t window_size;       // Analysis window
        uint32_t seasonality_period; // For seasonal data
        double threshold;           // Detection threshold
    } parameters;
    
    // Alerting
    AnomalySeverity min_severity;
    std::vector<std::string> notification_channels;
    bool auto_suppress;         // Suppress known patterns
    
    // Learning
    bool online_learning;       // Adapt to new patterns
    uint32_t training_samples;  // Samples for initial training
};

// Anomaly detector interface
class IAnomalyDetector {
public:
    virtual ~IAnomalyDetector() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Configuration
    virtual std::string CreateDetector(const DetectorConfig& config) = 0;
    virtual bool UpdateDetector(const DetectorConfig& config) = 0;
    virtual bool DeleteDetector(const std::string& detector_id) = 0;
    virtual std::optional<DetectorConfig> GetDetector(const std::string& detector_id) = 0;
    virtual std::vector<DetectorConfig> ListDetectors() = 0;
    virtual bool EnableDetector(const std::string& detector_id) = 0;
    virtual bool DisableDetector(const std::string& detector_id) = 0;
    
    // Data ingestion
    virtual bool IngestMetric(const std::string& metric_name, 
                               const DataPoint& point) = 0;
    virtual bool IngestMetricsBatch(const std::string& metric_name,
                                     const std::vector<DataPoint>& points) = 0;
    
    // Detection
    virtual std::vector<AnomalyResult> DetectAnomalies(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end) = 0;
    virtual std::vector<AnomalyResult> DetectAnomaliesRealtime(
        const std::string& metric_name) = 0;
    
    // Anomaly management
    virtual std::vector<AnomalyResult> GetActiveAnomalies() = 0;
    virtual std::vector<AnomalyResult> GetAnomalyHistory(
        std::chrono::hours lookback = std::chrono::hours(24)) = 0;
    virtual bool AcknowledgeAnomaly(const std::string& anomaly_id,
                                     const std::string& user_id) = 0;
    virtual bool SuppressAnomaly(const std::string& anomaly_id,
                                  const std::string& reason,
                                  std::chrono::hours duration) = 0;
    virtual bool ResolveAnomaly(const std::string& anomaly_id,
                                 const std::string& resolution) = 0;
    
    // Learning and feedback
    virtual bool MarkFalsePositive(const std::string& anomaly_id) = 0;
    virtual bool MarkTruePositive(const std::string& anomaly_id) = 0;
    virtual bool TrainOnHistoricalData(const std::string& metric_name,
                                        std::chrono::hours lookback) = 0;
    
    // Correlation
    virtual std::vector<std::string> FindCorrelatedMetrics(
        const std::string& metric_name,
        std::chrono::system_clock::time_point anomaly_time) = 0;
    virtual std::vector<std::string> FindRootCauseCandidates(
        const std::string& anomaly_id) = 0;
    
    // Statistics
    virtual struct DetectionStatistics {
        uint32_t total_detections;
        uint32_t false_positives;
        uint32_t true_positives;
        uint32_t currently_active;
        double precision;
        double recall;
        double f1_score;
        double avg_detection_time_ms;
    } GetStatistics(std::chrono::hours lookback = std::chrono::hours(168)) = 0;
};

// Statistical anomaly detector
class StatisticalAnomalyDetector : public IAnomalyDetector {
public:
    StatisticalAnomalyDetector();
    ~StatisticalAnomalyDetector() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string CreateDetector(const DetectorConfig& config) override;
    bool UpdateDetector(const DetectorConfig& config) override;
    bool DeleteDetector(const std::string& detector_id) override;
    std::optional<DetectorConfig> GetDetector(const std::string& detector_id) override;
    std::vector<DetectorConfig> ListDetectors() override;
    bool EnableDetector(const std::string& detector_id) override;
    bool DisableDetector(const std::string& detector_id) override;
    
    bool IngestMetric(const std::string& metric_name, 
                       const DataPoint& point) override;
    bool IngestMetricsBatch(const std::string& metric_name,
                             const std::vector<DataPoint>& points) override;
    
    std::vector<AnomalyResult> DetectAnomalies(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end) override;
    std::vector<AnomalyResult> DetectAnomaliesRealtime(
        const std::string& metric_name) override;
    
    std::vector<AnomalyResult> GetActiveAnomalies() override;
    std::vector<AnomalyResult> GetAnomalyHistory(
        std::chrono::hours lookback = std::chrono::hours(24)) override;
    bool AcknowledgeAnomaly(const std::string& anomaly_id,
                             const std::string& user_id) override;
    bool SuppressAnomaly(const std::string& anomaly_id,
                          const std::string& reason,
                          std::chrono::hours duration) override;
    bool ResolveAnomaly(const std::string& anomaly_id,
                         const std::string& resolution) override;
    
    bool MarkFalsePositive(const std::string& anomaly_id) override;
    bool MarkTruePositive(const std::string& anomaly_id) override;
    bool TrainOnHistoricalData(const std::string& metric_name,
                                std::chrono::hours lookback) override;
    
    std::vector<std::string> FindCorrelatedMetrics(
        const std::string& metric_name,
        std::chrono::system_clock::time_point anomaly_time) override;
    std::vector<std::string> FindRootCauseCandidates(
        const std::string& anomaly_id) override;
    
    DetectionStatistics GetStatistics(std::chrono::hours lookback = std::chrono::hours(168)) override;
    
private:
    std::unordered_map<std::string, DetectorConfig> detectors_;
    std::unordered_map<std::string, std::vector<DataPoint>> metric_data_;
    std::vector<AnomalyResult> active_anomalies_;
    std::vector<AnomalyResult> anomaly_history_;
    bool initialized_ = false;
    
    AnomalyResult DetectStatisticalAnomaly(const std::string& metric_name,
                                            const DataPoint& point,
                                            const DetectorConfig& config);
    double CalculateZScore(const std::vector<double>& values, double current);
    double CalculateIQRScore(const std::vector<double>& values, double current);
};

// ML-based anomaly detector
class MLAnomalyDetector : public IAnomalyDetector {
public:
    MLAnomalyDetector();
    ~MLAnomalyDetector() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string CreateDetector(const DetectorConfig& config) override;
    bool UpdateDetector(const DetectorConfig& config) override;
    bool DeleteDetector(const std::string& detector_id) override;
    std::optional<DetectorConfig> GetDetector(const std::string& detector_id) override;
    std::vector<DetectorConfig> ListDetectors() override;
    bool EnableDetector(const std::string& detector_id) override;
    bool DisableDetector(const std::string& detector_id) override;
    
    bool IngestMetric(const std::string& metric_name, 
                       const DataPoint& point) override;
    bool IngestMetricsBatch(const std::string& metric_name,
                             const std::vector<DataPoint>& points) override;
    
    std::vector<AnomalyResult> DetectAnomalies(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end) override;
    std::vector<AnomalyResult> DetectAnomaliesRealtime(
        const std::string& metric_name) override;
    
    std::vector<AnomalyResult> GetActiveAnomalies() override;
    std::vector<AnomalyResult> GetAnomalyHistory(
        std::chrono::hours lookback = std::chrono::hours(24)) override;
    bool AcknowledgeAnomaly(const std::string& anomaly_id,
                             const std::string& user_id) override;
    bool SuppressAnomaly(const std::string& anomaly_id,
                          const std::string& reason,
                          std::chrono::hours duration) override;
    bool ResolveAnomaly(const std::string& anomaly_id,
                         const std::string& resolution) override;
    
    bool MarkFalsePositive(const std::string& anomaly_id) override;
    bool MarkTruePositive(const std::string& anomaly_id) override;
    bool TrainOnHistoricalData(const std::string& metric_name,
                                std::chrono::hours lookback) override;
    
    std::vector<std::string> FindCorrelatedMetrics(
        const std::string& metric_name,
        std::chrono::system_clock::time_point anomaly_time) override;
    std::vector<std::string> FindRootCauseCandidates(
        const std::string& anomaly_id) override;
    
    DetectionStatistics GetStatistics(std::chrono::hours lookback = std::chrono::hours(168)) override;
    
private:
    // ML model management
    class Model;
    std::unordered_map<std::string, std::unique_ptr<Model>> models_;
    bool initialized_ = false;
    
    bool TrainModel(const std::string& metric_name, 
                    const std::vector<DataPoint>& data);
    double ScoreDataPoint(const std::string& metric_name,
                          const DataPoint& point);
};

// Pattern-based anomaly detection
class PatternAnomalyDetector {
public:
    // Learn normal patterns
    bool LearnPattern(const std::string& metric_name,
                      const std::vector<DataPoint>& normal_data);
    
    // Detect pattern deviations
    struct PatternDeviation {
        std::string pattern_name;
        double expected_pattern[24];  // Hourly pattern
        double actual_pattern[24];
        double deviation_score;
    };
    
    std::vector<PatternDeviation> DetectPatternDeviations(
        const std::string& metric_name,
        const std::vector<DataPoint>& recent_data);
    
    // Seasonal anomaly detection
    bool IsSeasonalAnomaly(const std::string& metric_name,
                             const DataPoint& point,
                             double threshold = 0.95);
};

// Global anomaly detector
extern std::unique_ptr<IAnomalyDetector> g_anomaly_detector;

// Initialize anomaly detection
bool InitializeAnomalyDetection(const std::string& config_path);
void ShutdownAnomalyDetection();
bool IsAnomalyDetectionEnabled();

} // namespace Intelligent
} // namespace RawrXD
