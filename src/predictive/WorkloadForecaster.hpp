// WorkloadForecaster.hpp
// Phase C.3 — Predictive Analytics and Workload Forecasting

#ifndef WORKLOAD_FORECASTER_HPP
#define WORKLOAD_FORECASTER_HPP

#include <vector>
#include <map>
#include <memory>
#include <string>
#include <chrono>
#include <atomic>
#include <mutex>
#include <functional>
#include <queue>
#include <thread>

namespace Predictive {

// ============================================================================
// Time Series Data Point
// ============================================================================

struct TimeSeriesPoint {
    std::chrono::steady_clock::time_point timestamp;
    double value;
    std::map<std::string, double> features;
    
    TimeSeriesPoint() : value(0.0) {}
    TimeSeriesPoint(std::chrono::steady_clock::time_point ts, double val)
        : timestamp(ts), value(val) {}
};

// ============================================================================
// Forecast Result
// ============================================================================

struct ForecastResult {
    std::vector<double> predicted_values;
    std::vector<double> confidence_intervals_lower;
    std::vector<double> confidence_intervals_upper;
    std::vector<std::chrono::steady_clock::time_point> timestamps;
    
    double accuracy;
    double mse; // Mean Squared Error
    double mae; // Mean Absolute Error
    double rmse; // Root Mean Squared Error
    double mape; // Mean Absolute Percentage Error
    
    std::string model_name;
    std::chrono::steady_clock::time_point generated_at;
    
    ForecastResult()
        : accuracy(0.0), mse(0.0), mae(0.0), rmse(0.0), mape(0.0) {}
};

// ============================================================================
// Forecasting Models
// ============================================================================

enum class ForecastingModel {
    NAIVE,           // Last value
    MOVING_AVERAGE,  // Simple MA
    EXPONENTIAL_SMOOTHING,
    ARIMA,           // Auto-Regressive Integrated Moving Average
    PROPHET,         // Facebook Prophet-like
    LSTM,            // Neural network
    ENSEMBLE,        // Combined models
    ADAPTIVE         // Auto-select best
};

// ============================================================================
// Model Configuration
// ============================================================================

struct ForecastingConfig {
    ForecastingModel model = ForecastingModel::ADAPTIVE;
    
    // Window sizes
    uint32_t history_window_hours = 24;
    uint32_t forecast_horizon_hours = 4;
    uint32_t update_interval_minutes = 5;
    
    // Model parameters
    uint32_t ma_window = 10;
    double alpha = 0.3; // Exponential smoothing factor
    uint32_t arima_p = 2; // AR order
    uint32_t arima_d = 1; // Differencing
    uint32_t arima_q = 2; // MA order
    
    // Seasonality
    bool detect_seasonality = true;
    uint32_t seasonality_period = 24; // Hours
    
    // Confidence intervals
    double confidence_level = 0.95;
    
    // Ensemble
    std::vector<ForecastingModel> ensemble_models = {
        ForecastingModel::MOVING_AVERAGE,
        ForecastingModel::EXPONENTIAL_SMOOTHING,
        ForecastingModel::ARIMA
    };
    
    // Adaptive selection
    bool auto_select_best = true;
    uint32_t evaluation_window = 12; // Hours
};

// ============================================================================
// Base Forecasting Model
// ============================================================================

class ForecastingModelBase {
public:
    virtual ~ForecastingModelBase() = default;
    
    virtual std::string GetName() const = 0;
    virtual void Train(const std::vector<TimeSeriesPoint>& data) = 0;
    virtual ForecastResult Forecast(uint32_t horizon) = 0;
    virtual double Evaluate(const std::vector<TimeSeriesPoint>& test_data) = 0;
    virtual void Update(const TimeSeriesPoint& new_point) = 0;
    virtual void Reset() = 0;
};

// ============================================================================
// Naive Model
// ============================================================================

class NaiveModel : public ForecastingModelBase {
public:
    std::string GetName() const override { return "Naive"; }
    void Train(const std::vector<TimeSeriesPoint>& data) override;
    ForecastResult Forecast(uint32_t horizon) override;
    double Evaluate(const std::vector<TimeSeriesPoint>& test_data) override;
    void Update(const TimeSeriesPoint& new_point) override;
    void Reset() override;
    
private:
    double last_value_ = 0.0;
    std::chrono::steady_clock::time_point last_timestamp_;
};

// ============================================================================
// Moving Average Model
// ============================================================================

class MovingAverageModel : public ForecastingModelBase {
public:
    explicit MovingAverageModel(uint32_t window = 10);
    
    std::string GetName() const override { return "MovingAverage"; }
    void Train(const std::vector<TimeSeriesPoint>& data) override;
    ForecastResult Forecast(uint32_t horizon) override;
    double Evaluate(const std::vector<TimeSeriesPoint>& test_data) override;
    void Update(const TimeSeriesPoint& new_point) override;
    void Reset() override;
    
private:
    uint32_t window_;
    std::vector<double> history_;
};

// ============================================================================
// Exponential Smoothing Model
// ============================================================================

class ExponentialSmoothingModel : public ForecastingModelBase {
public:
    explicit ExponentialSmoothingModel(double alpha = 0.3);
    
    std::string GetName() const override { return "ExponentialSmoothing"; }
    void Train(const std::vector<TimeSeriesPoint>& data) override;
    ForecastResult Forecast(uint32_t horizon) override;
    double Evaluate(const std::vector<TimeSeriesPoint>& test_data) override;
    void Update(const TimeSeriesPoint& new_point) override;
    void Reset() override;
    
private:
    double alpha_;
    double smoothed_value_ = 0.0;
    double trend_ = 0.0;
    bool initialized_ = false;
};

// ============================================================================
// ARIMA Model (Simplified)
// ============================================================================

class ARIMAModel : public ForecastingModelBase {
public:
    ARIMAModel(uint32_t p = 2, uint32_t d = 1, uint32_t q = 2);
    
    std::string GetName() const override { return "ARIMA"; }
    void Train(const std::vector<TimeSeriesPoint>& data) override;
    ForecastResult Forecast(uint32_t horizon) override;
    double Evaluate(const std::vector<TimeSeriesPoint>& test_data) override;
    void Update(const TimeSeriesPoint& new_point) override;
    void Reset() override;
    
private:
    uint32_t p_, d_, q_;
    std::vector<double> ar_coefficients_;
    std::vector<double> ma_coefficients_;
    std::vector<double> differenced_data_;
    std::vector<double> residuals_;
    
    void Difference(const std::vector<double>& data, uint32_t order);
    void FitAR();
    void FitMA();
};

// ============================================================================
// Ensemble Model
// ============================================================================

class EnsembleModel : public ForecastingModelBase {
public:
    explicit EnsembleModel(const std::vector<std::shared_ptr<ForecastingModelBase>>& models);
    
    std::string GetName() const override { return "Ensemble"; }
    void Train(const std::vector<TimeSeriesPoint>& data) override;
    ForecastResult Forecast(uint32_t horizon) override;
    double Evaluate(const std::vector<TimeSeriesPoint>& test_data) override;
    void Update(const TimeSeriesPoint& new_point) override;
    void Reset() override;
    
private:
    std::vector<std::shared_ptr<ForecastingModelBase>> models_;
    std::vector<double> model_weights_;
    
    void CalculateWeights(const std::vector<TimeSeriesPoint>& validation_data);
};

// ============================================================================
// Workload Metrics
// ============================================================================

struct WorkloadMetrics {
    // Task metrics
    double tasks_per_second;
    double tasks_per_minute;
    double tasks_per_hour;
    
    // Resource metrics
    double cpu_utilization;
    double memory_utilization;
    double network_io_mbps;
    
    // Queue metrics
    uint32_t queue_depth;
    double average_wait_time_ms;
    double p95_wait_time_ms;
    double p99_wait_time_ms;
    
    // Pattern metrics
    double burstiness; // Coefficient of variation
    double trend_slope;
    double seasonality_strength;
    
    // Timestamps
    std::chrono::steady_clock::time_point timestamp;
};

// ============================================================================
// Workload Forecaster
// ============================================================================

class WorkloadForecaster {
public:
    explicit WorkloadForecaster(const ForecastingConfig& config = ForecastingConfig{});
    ~WorkloadForecaster();
    
    // Lifecycle
    void Initialize();
    void Start();
    void Stop();
    void Shutdown();
    
    // Data collection
    void RecordMetric(const WorkloadMetrics& metrics);
    void RecordTimeSeries(const std::string& series_name, double value);
    void RecordTimeSeries(const std::string& series_name, const TimeSeriesPoint& point);
    
    // Forecasting
    ForecastResult ForecastWorkload(uint32_t hours_ahead);
    ForecastResult ForecastMetric(const std::string& metric_name, uint32_t hours_ahead);
    
    // Multi-horizon forecasting
    std::map<uint32_t, ForecastResult> ForecastMultipleHorizons(
        const std::vector<uint32_t>& horizons);
    
    // Anomaly detection
    bool IsAnomaly(const std::string& metric_name, double value);
    std::vector<std::string> DetectAnomalies();
    
    // Pattern detection
    struct Pattern {
        std::string type;
        double strength;
        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point end_time;
    };
    
    std::vector<Pattern> DetectPatterns(const std::string& metric_name);
    
    // Model management
    void SelectBestModel();
    std::string GetCurrentModelName() const;
    std::map<std::string, double> GetModelPerformance() const;
    
    // Alerts
    using AlertCallback = std::function<void(const std::string& alert_type, 
                                              const std::string& message)>;
    void SetAlertCallback(AlertCallback callback);
    void SetThreshold(const std::string& metric_name, double threshold);
    
    // Statistics
    struct ForecasterStats {
        uint64_t data_points_collected;
        uint64_t forecasts_generated;
        uint64_t anomalies_detected;
        double average_forecast_accuracy;
        std::chrono::steady_clock::time_point last_training;
        std::chrono::steady_clock::time_point last_forecast;
    };
    
    ForecasterStats GetStats() const;
    
    // Export
    void ExportForecast(const std::string& metric_name, const std::string& path) const;
    void ExportTrainingData(const std::string& path) const;
    
private:
    ForecastingConfig config_;
    
    // Data storage
    std::map<std::string, std::vector<TimeSeriesPoint>> time_series_data_;
    std::vector<WorkloadMetrics> workload_history_;
    mutable std::mutex data_mutex_;
    
    // Models
    std::map<std::string, std::shared_ptr<ForecastingModelBase>> models_;
    std::shared_ptr<ForecastingModelBase> active_model_;
    mutable std::mutex model_mutex_;
    
    // Alerting
    AlertCallback alert_callback_;
    std::map<std::string, double> thresholds_;
    
    // Statistics
    ForecasterStats stats_;
    mutable std::mutex stats_mutex_;
    
    // Background thread
    std::atomic<bool> running_{false};
    std::thread forecast_thread_;
    
    void ForecastLoop();
    void TrainModels();
    void EvaluateModels();
    void CheckThresholds(const std::string& metric_name, double predicted_value);
    
    std::shared_ptr<ForecastingModelBase> CreateModel(ForecastingModel type);
    std::vector<TimeSeriesPoint> GetTrainingData(const std::string& metric_name);
};

// ============================================================================
// Predictive Scheduler Integration
// ============================================================================

class PredictiveSchedulerIntegration {
public:
    PredictiveSchedulerIntegration(WorkloadForecaster* forecaster);
    
    // Pre-warming
    void PreWarmWorkers(uint32_t minutes_ahead);
    void PreLoadModels(uint32_t minutes_ahead);
    void ScaleResources(const ForecastResult& forecast);
    
    // Scheduling hints
    struct SchedulingHint {
        std::chrono::steady_clock::time_point optimal_time;
        double expected_load;
        uint32_t recommended_workers;
        std::string reason;
    };
    
    SchedulingHint GetOptimalSchedulingTime(uint32_t flexibility_minutes);
    std::vector<SchedulingHint> GetSchedulingPlan(uint32_t hours_ahead);
    
    // Cost optimization
    double EstimateExecutionCost(const std::chrono::steady_clock::time_point& time);
    std::chrono::steady_clock::time_point FindCheapestExecutionWindow(
        uint32_t window_hours);
    
private:
    WorkloadForecaster* forecaster_;
};

// ============================================================================
// Utility Functions
// ============================================================================

namespace ForecastingUtils {
    // Statistical functions
    double CalculateMean(const std::vector<double>& data);
    double CalculateStdDev(const std::vector<double>& data);
    double CalculateVariance(const std::vector<double>& data);
    double CalculateCov(const std::vector<double>& data); // Coefficient of variation
    
    // Time series operations
    std::vector<double> Difference(const std::vector<double>& data, uint32_t order);
    std::vector<double> MovingAverage(const std::vector<double>& data, uint32_t window);
    std::vector<double> ExponentialSmoothing(const std::vector<double>& data, double alpha);
    
    // Seasonality detection
    bool HasSeasonality(const std::vector<TimeSeriesPoint>& data, uint32_t period);
    double CalculateSeasonalityStrength(const std::vector<TimeSeriesPoint>& data, 
                                         uint32_t period);
    
    // Trend detection
    std::pair<double, double> LinearRegression(const std::vector<double>& x, 
                                                const std::vector<double>& y);
    double CalculateTrend(const std::vector<TimeSeriesPoint>& data);
    
    // Autocorrelation
    double Autocorrelation(const std::vector<double>& data, uint32_t lag);
    std::vector<double> AutocorrelationFunction(const std::vector<double>& data, 
                                                uint32_t max_lag);
    
    // Error metrics
    double CalculateMSE(const std::vector<double>& actual, 
                         const std::vector<double>& predicted);
    double CalculateMAE(const std::vector<double>& actual, 
                         const std::vector<double>& predicted);
    double CalculateRMSE(const std::vector<double>& actual, 
                          const std::vector<double>& predicted);
    double CalculateMAPE(const std::vector<double>& actual, 
                          const std::vector<double>& predicted);
    
    // Confidence intervals
    std::pair<double, double> CalculateConfidenceInterval(const std::vector<double>& errors,
                                                        double confidence_level);
} // namespace ForecastingUtils

} // namespace Predictive

#endif // WORKLOAD_FORECASTER_HPP
