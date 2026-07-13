// Phase D.6 Batch 1/5: Predictive Autoscaling
// ML-Based Load Prediction and Proactive Scaling
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>

namespace Sovereign {
namespace Intelligence {

// ============================================================================
// Time Series Data Types
// ============================================================================

struct TimeSeriesPoint {
    std::chrono::steady_clock::time_point timestamp;
    double value = 0.0;
    std::map<std::string, std::string> labels;
};

struct TimeSeries {
    std::string metric_name;
    std::vector<TimeSeriesPoint> points;
    std::chrono::milliseconds interval{60000};  // 1 minute default
    
    void AddPoint(const TimeSeriesPoint& point);
    std::vector<double> GetValues() const;
    TimeSeries Resample(std::chrono::milliseconds new_interval) const;
};

// ============================================================================
// Forecasting Models
// ============================================================================

enum class ForecastingModel {
    ARIMA = 0,           // Auto-Regressive Integrated Moving Average
    PROPHET = 1,         // Facebook Prophet
    LSTM = 2,            // Long Short-Term Memory Neural Network
    EXPONENTIAL_SMOOTHING = 3,
    SEASONAL_NAIVE = 4,
    ENSEMBLE = 5         // Combined model
};

struct ForecastResult {
    std::vector<double> predicted_values;
    std::vector<double> confidence_lower;
    std::vector<double> confidence_upper;
    std::chrono::steady_clock::time_point forecast_time;
    int horizon_steps = 0;
    double model_accuracy = 0.0;
    ForecastingModel model_used;
};

class ForecastingEngine {
public:
    struct Config {
        ForecastingModel default_model = ForecastingModel::ENSEMBLE;
        int training_window_hours = 168;  // 1 week
        int forecast_horizon_minutes = 60;
        double confidence_level = 0.95;
        bool enable_seasonality = true;
        bool enable_trend = true;
        int retrain_interval_minutes = 60;
    };
    
    explicit ForecastingEngine(const Config& config);
    ~ForecastingEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Model training
    bool TrainModel(const std::string& metric_name, 
                    const TimeSeries& historical_data);
    bool RetrainModel(const std::string& metric_name);
    
    // Forecasting
    ForecastResult Forecast(const std::string& metric_name,
                            int horizon_steps);
    ForecastResult Forecast(const TimeSeries& series,
                            int horizon_steps);
    
    // Model management
    double GetModelAccuracy(const std::string& metric_name) const;
    std::vector<std::string> GetTrainedMetrics() const;
    bool ExportModel(const std::string& metric_name, 
                     const std::string& path);
    bool ImportModel(const std::string& path);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::thread training_thread_;
    
    struct ModelState {
        ForecastingModel model_type;
        std::vector<uint8_t> model_data;
        double accuracy = 0.0;
        std::chrono::steady_clock::time_point last_trained;
        TimeSeries training_data;
    };
    
    mutable std::mutex models_mutex_;
    std::map<std::string, ModelState> models_;
    
    void TrainingLoop();
    ForecastResult RunARIMA(const TimeSeries& series, int horizon);
    ForecastResult RunProphet(const TimeSeries& series, int horizon);
    ForecastResult RunLSTM(const TimeSeries& series, int horizon);
    ForecastResult RunEnsemble(const TimeSeries& series, int horizon);
};

// ============================================================================
// Load Predictor
// ============================================================================

class LoadPredictor {
public:
    struct Config {
        int prediction_horizon_minutes = 30;
        double scale_up_threshold = 0.8;    // Predicted load > 80%
        double scale_down_threshold = 0.3;  // Predicted load < 30%
        int min_scale_up_headroom = 2;      // Minimum nodes to add
        int cooldown_minutes = 5;
    };
    
    explicit LoadPredictor(const Config& config);
    
    bool Initialize(ForecastingEngine* engine);
    
    // Prediction
    struct Prediction {
        double predicted_load = 0.0;
        double confidence = 0.0;
        std::chrono::steady_clock::time_point timestamp;
        bool scale_up_recommended = false;
        bool scale_down_recommended = false;
        int recommended_nodes = 0;
        std::string reason;
    };
    
    Prediction PredictLoad(const std::string& service_name,
                           std::chrono::minutes horizon);
    
    // Historical analysis
    std::map<std::string, double> GetSeasonalPatterns(const std::string& service_name);
    std::map<std::string, double> GetDailyPatterns(const std::string& service_name);
    
    // Threshold management
    void SetScaleUpThreshold(double threshold);
    void SetScaleDownThreshold(double threshold);
    
private:
    Config config_;
    ForecastingEngine* engine_ = nullptr;
    
    mutable std::mutex thresholds_mutex_;
    double scale_up_threshold_;
    double scale_down_threshold_;
};

// ============================================================================
// Proactive Scaler
// ============================================================================

class ProactiveScaler {
public:
    struct Config {
        bool enable_proactive_scaling = true;
        bool enable_reactive_scaling = true;
        int proactive_lead_time_minutes = 10;
        int max_scale_up_rate = 2;          // 2x current capacity
        int max_scale_down_rate = 2;
        int stabilization_minutes = 5;
        bool respect_cooldown = true;
    };
    
    explicit ProactiveScaler(const Config& config);
    ~ProactiveScaler();
    
    bool Initialize(LoadPredictor* predictor);
    void Shutdown();
    
    // Scaling operations
    bool ScaleUp(const std::string& service_name, int node_count);
    bool ScaleDown(const std::string& service_name, int node_count);
    bool SetDesiredCapacity(const std::string& service_name, int capacity);
    
    // Decision making
    struct ScalingDecision {
        bool should_scale = false;
        int current_capacity = 0;
        int desired_capacity = 0;
        std::string direction;  // "up", "down", "none"
        std::string reason;
        double confidence = 0.0;
        std::chrono::steady_clock::time_point timestamp;
    };
    
    ScalingDecision EvaluateScaling(const std::string& service_name);
    
    // History
    struct ScalingEvent {
        std::string service_name;
        std::string direction;
        int from_capacity = 0;
        int to_capacity = 0;
        std::string trigger;  // "proactive", "reactive", "manual"
        std::chrono::steady_clock::time_point timestamp;
        bool successful = false;
    };
    
    std::vector<ScalingEvent> GetScalingHistory(const std::string& service_name,
                                                 int limit = 100) const;
    
private:
    Config config_;
    LoadPredictor* predictor_ = nullptr;
    std::atomic<bool> running_{false};
    std::thread decision_thread_;
    
    mutable std::mutex history_mutex_;
    std::vector<ScalingEvent> scaling_history_;
    
    std::map<std::string, std::chrono::steady_clock::time_point> last_scale_time_;
    mutable std::mutex cooldown_mutex_;
    
    void DecisionLoop();
    bool CheckCooldown(const std::string& service_name);
    bool ExecuteScaling(const ScalingDecision& decision);
};

// ============================================================================
// Pattern Detector
// ============================================================================

class PatternDetector {
public:
    struct Config {
        int pattern_window_hours = 24;
        double similarity_threshold = 0.85;
        bool enable_anomaly_filtering = true;
    };
    
    explicit PatternDetector(const Config& config);
    
    // Pattern detection
    enum class PatternType {
        DAILY_CYCLE = 0,
        WEEKLY_CYCLE = 1,
        SEASONAL = 2,
        TREND = 3,
        SPIKE = 4,
        STEP_CHANGE = 5,
        UNKNOWN = 6
    };
    
    struct DetectedPattern {
        PatternType type;
        double confidence = 0.0;
        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point end_time;
        std::map<std::string, double> parameters;
        std::string description;
    };
    
    std::vector<DetectedPattern> DetectPatterns(const TimeSeries& series);
    PatternType ClassifyPattern(const TimeSeries& series);
    
    // Similarity matching
    double CalculateSimilarity(const TimeSeries& series1, 
                               const TimeSeries& series2);
    std::vector<std::string> FindSimilarServices(const std::string& service_name);
    
private:
    Config config_;
    
    DetectedPattern DetectDailyCycle(const TimeSeries& series);
    DetectedPattern DetectWeeklyCycle(const TimeSeries& series);
    DetectedPattern DetectTrend(const TimeSeries& series);
    DetectedPattern DetectSpike(const TimeSeries& series);
};

} // namespace Intelligence
} // namespace Sovereign
