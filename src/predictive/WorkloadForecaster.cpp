// WorkloadForecaster.cpp
// Phase C.3 — Predictive Analytics and Workload Forecasting Implementation

#include "WorkloadForecaster.hpp"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace Predictive {

// ============================================================================
// NaiveModel Implementation
// ============================================================================

void NaiveModel::Train(const std::vector<TimeSeriesPoint>& data) {
    if (!data.empty()) {
        last_value_ = data.back().value;
        last_timestamp_ = data.back().timestamp;
    }
}

ForecastResult NaiveModel::Forecast(uint32_t horizon) {
    ForecastResult result;
    
    for (uint32_t i = 0; i < horizon; ++i) {
        result.predicted_values.push_back(last_value_);
        result.confidence_intervals_lower.push_back(last_value_ * 0.9);
        result.confidence_intervals_upper.push_back(last_value_ * 1.1);
        result.timestamps.push_back(last_timestamp_ + std::chrono::hours(i));
    }
    
    result.model_name = GetName();
    result.generated_at = std::chrono::steady_clock::now();
    
    return result;
}

double NaiveModel::Evaluate(const std::vector<TimeSeriesPoint>& test_data) {
    if (test_data.empty()) return 0.0;
    
    double mse = 0.0;
    for (const auto& point : test_data) {
        double error = point.value - last_value_;
        mse += error * error;
    }
    
    return mse / test_data.size();
}

void NaiveModel::Update(const TimeSeriesPoint& new_point) {
    last_value_ = new_point.value;
    last_timestamp_ = new_point.timestamp;
}

void NaiveModel::Reset() {
    last_value_ = 0.0;
}

// ============================================================================
// MovingAverageModel Implementation
// ============================================================================

MovingAverageModel::MovingAverageModel(uint32_t window) : window_(window) {}

void MovingAverageModel::Train(const std::vector<TimeSeriesPoint>& data) {
    history_.clear();
    for (const auto& point : data) {
        history_.push_back(point.value);
    }
}

ForecastResult MovingAverageModel::Forecast(uint32_t horizon) {
    ForecastResult result;
    
    if (history_.empty()) {
        return result;
    }
    
    // Calculate moving average
    double sum = 0.0;
    uint32_t count = std::min(window_, static_cast<uint32_t>(history_.size()));
    
    for (size_t i = history_.size() - count; i < history_.size(); ++i) {
        sum += history_[i];
    }
    
    double ma = sum / count;
    double stddev = 0.0;
    
    for (size_t i = history_.size() - count; i < history_.size(); ++i) {
        stddev += std::pow(history_[i] - ma, 2);
    }
    stddev = std::sqrt(stddev / count);
    
    // Generate forecast
    auto last_time = std::chrono::steady_clock::now();
    
    for (uint32_t i = 0; i < horizon; ++i) {
        result.predicted_values.push_back(ma);
        result.confidence_intervals_lower.push_back(ma - 1.96 * stddev);
        result.confidence_intervals_upper.push_back(ma + 1.96 * stddev);
        result.timestamps.push_back(last_time + std::chrono::hours(i));
    }
    
    result.model_name = GetName();
    result.generated_at = std::chrono::steady_clock::now();
    
    return result;
}

double MovingAverageModel::Evaluate(const std::vector<TimeSeriesPoint>& test_data) {
    if (test_data.empty() || history_.empty()) return 0.0;
    
    double sum = 0.0;
    uint32_t count = std::min(window_, static_cast<uint32_t>(history_.size()));
    
    for (size_t i = history_.size() - count; i < history_.size(); ++i) {
        sum += history_[i];
    }
    
    double ma = sum / count;
    
    double mse = 0.0;
    for (const auto& point : test_data) {
        double error = point.value - ma;
        mse += error * error;
    }
    
    return mse / test_data.size();
}

void MovingAverageModel::Update(const TimeSeriesPoint& new_point) {
    history_.push_back(new_point.value);
    
    // Keep only recent history
    while (history_.size() > window_ * 10) {
        history_.erase(history_.begin());
    }
}

void MovingAverageModel::Reset() {
    history_.clear();
}

// ============================================================================
// ExponentialSmoothingModel Implementation
// ============================================================================

ExponentialSmoothingModel::ExponentialSmoothingModel(double alpha) : alpha_(alpha) {}

void ExponentialSmoothingModel::Train(const std::vector<TimeSeriesPoint>& data) {
    if (data.empty()) return;
    
    smoothed_value_ = data[0].value;
    initialized_ = true;
    
    for (size_t i = 1; i < data.size(); ++i) {
        double new_smoothed = alpha_ * data[i].value + (1.0 - alpha_) * smoothed_value_;
        trend_ = new_smoothed - smoothed_value_;
        smoothed_value_ = new_smoothed;
    }
}

ForecastResult ExponentialSmoothingModel::Forecast(uint32_t horizon) {
    ForecastResult result;
    
    if (!initialized_) {
        return result;
    }
    
    auto last_time = std::chrono::steady_clock::now();
    
    for (uint32_t i = 1; i <= horizon; ++i) {
        double forecast = smoothed_value_ + i * trend_;
        result.predicted_values.push_back(forecast);
        result.confidence_intervals_lower.push_back(forecast * 0.9);
        result.confidence_intervals_upper.push_back(forecast * 1.1);
        result.timestamps.push_back(last_time + std::chrono::hours(i));
    }
    
    result.model_name = GetName();
    result.generated_at = std::chrono::steady_clock::now();
    
    return result;
}

double ExponentialSmoothingModel::Evaluate(const std::vector<TimeSeriesPoint>& test_data) {
    if (test_data.empty() || !initialized_) return 0.0;
    
    double mse = 0.0;
    double forecast = smoothed_value_;
    
    for (const auto& point : test_data) {
        double error = point.value - forecast;
        mse += error * error;
        forecast = alpha_ * point.value + (1.0 - alpha_) * forecast;
    }
    
    return mse / test_data.size();
}

void ExponentialSmoothingModel::Update(const TimeSeriesPoint& new_point) {
    if (!initialized_) {
        smoothed_value_ = new_point.value;
        initialized_ = true;
    } else {
        double new_smoothed = alpha_ * new_point.value + (1.0 - alpha_) * smoothed_value_;
        trend_ = new_smoothed - smoothed_value_;
        smoothed_value_ = new_smoothed;
    }
}

void ExponentialSmoothingModel::Reset() {
    smoothed_value_ = 0.0;
    trend_ = 0.0;
    initialized_ = false;
}

// ============================================================================
// ARIMAModel Implementation (Simplified)
// ============================================================================

ARIMAModel::ARIMAModel(uint32_t p, uint32_t d, uint32_t q) 
    : p_(p), d_(d), q_(q) {}

void ARIMAModel::Train(const std::vector<TimeSeriesPoint>& data) {
    if (data.size() < p_ + q_ + d_ + 1) return;
    
    // Extract values
    std::vector<double> values;
    for (const auto& point : data) {
        values.push_back(point.value);
    }
    
    // Difference data
    Difference(values, d_);
    
    // Fit AR component (simplified)
    FitAR();
    
    // Fit MA component (simplified)
    FitMA();
}

ForecastResult ARIMAModel::Forecast(uint32_t horizon) {
    ForecastResult result;
    
    if (differenced_data_.empty()) {
        return result;
    }
    
    // Simplified forecast
    double last_value = differenced_data_.back();
    
    auto last_time = std::chrono::steady_clock::now();
    
    for (uint32_t i = 1; i <= horizon; ++i) {
        // Simple AR forecast
        double forecast = last_value;
        for (size_t j = 0; j < ar_coefficients_.size() && j < differenced_data_.size(); ++j) {
            forecast += ar_coefficients_[j] * differenced_data_[differenced_data_.size() - 1 - j];
        }
        
        result.predicted_values.push_back(forecast);
        result.confidence_intervals_lower.push_back(forecast * 0.85);
        result.confidence_intervals_upper.push_back(forecast * 1.15);
        result.timestamps.push_back(last_time + std::chrono::hours(i));
    }
    
    result.model_name = GetName();
    result.generated_at = std::chrono::steady_clock::now();
    
    return result;
}

double ARIMAModel::Evaluate(const std::vector<TimeSeriesPoint>& test_data) {
    if (test_data.empty()) return 0.0;
    
    // Simplified evaluation
    double mse = 0.0;
    for (const auto& point : test_data) {
        double error = point.value; // Simplified
        mse += error * error;
    }
    
    return mse / test_data.size();
}

void ARIMAModel::Update(const TimeSeriesPoint& new_point) {
    differenced_data_.push_back(new_point.value);
    
    // Keep limited history
    while (differenced_data_.size() > 1000) {
        differenced_data_.erase(differenced_data_.begin());
    }
}

void ARIMAModel::Reset() {
    ar_coefficients_.clear();
    ma_coefficients_.clear();
    differenced_data_.clear();
    residuals_.clear();
}

void ARIMAModel::Difference(const std::vector<double>& data, uint32_t order) {
    differenced_data_ = data;
    
    for (uint32_t i = 0; i < order; ++i) {
        std::vector<double> diff;
        for (size_t j = 1; j < differenced_data_.size(); ++j) {
            diff.push_back(differenced_data_[j] - differenced_data_[j - 1]);
        }
        differenced_data_ = diff;
    }
}

void ARIMAModel::FitAR() {
    // Simplified AR fitting - would use Yule-Walker or least squares in production
    ar_coefficients_.resize(p_, 0.1);
}

void ARIMAModel::FitMA() {
    // Simplified MA fitting
    ma_coefficients_.resize(q_, 0.1);
}

// ============================================================================
// EnsembleModel Implementation
// ============================================================================

EnsembleModel::EnsembleModel(const std::vector<std::shared_ptr<ForecastingModelBase>>& models)
    : models_(models) {
    model_weights_.resize(models.size(), 1.0 / models.size());
}

void EnsembleModel::Train(const std::vector<TimeSeriesPoint>& data) {
    for (auto& model : models_) {
        model->Train(data);
    }
}

ForecastResult EnsembleModel::Forecast(uint32_t horizon) {
    ForecastResult result;
    
    if (models_.empty()) {
        return result;
    }
    
    // Get forecasts from all models
    std::vector<ForecastResult> forecasts;
    for (auto& model : models_) {
        forecasts.push_back(model->Forecast(horizon));
    }
    
    // Combine forecasts using weights
    for (uint32_t i = 0; i < horizon; ++i) {
        double weighted_sum = 0.0;
        double variance = 0.0;
        
        for (size_t m = 0; m < models_.size(); ++m) {
            if (i < forecasts[m].predicted_values.size()) {
                weighted_sum += model_weights_[m] * forecasts[m].predicted_values[i];
            }
        }
        
        // Calculate variance for confidence intervals
        for (size_t m = 0; m < models_.size(); ++m) {
            if (i < forecasts[m].predicted_values.size()) {
                variance += model_weights_[m] * std::pow(
                    forecasts[m].predicted_values[i] - weighted_sum, 2);
            }
        }
        
        double stddev = std::sqrt(variance);
        
        result.predicted_values.push_back(weighted_sum);
        result.confidence_intervals_lower.push_back(weighted_sum - 1.96 * stddev);
        result.confidence_intervals_upper.push_back(weighted_sum + 1.96 * stddev);
        result.timestamps.push_back(forecasts[0].timestamps[i]);
    }
    
    result.model_name = GetName();
    result.generated_at = std::chrono::steady_clock::now();
    
    return result;
}

double EnsembleModel::Evaluate(const std::vector<TimeSeriesPoint>& test_data) {
    if (models_.empty()) return 0.0;
    
    // Evaluate each model
    std::vector<double> errors;
    for (auto& model : models_) {
        errors.push_back(model->Evaluate(test_data));
    }
    
    // Weighted average of errors
    double weighted_error = 0.0;
    for (size_t i = 0; i < errors.size(); ++i) {
        weighted_error += model_weights_[i] * errors[i];
    }
    
    return weighted_error;
}

void EnsembleModel::Update(const TimeSeriesPoint& new_point) {
    for (auto& model : models_) {
        model->Update(new_point);
    }
}

void EnsembleModel::Reset() {
    for (auto& model : models_) {
        model->Reset();
    }
}

void EnsembleModel::CalculateWeights(const std::vector<TimeSeriesPoint>& validation_data) {
    if (models_.empty()) return;
    
    // Calculate inverse error for each model
    std::vector<double> inverse_errors;
    double total_inverse_error = 0.0;
    
    for (auto& model : models_) {
        double error = model->Evaluate(validation_data);
        double inv_error = (error > 1e-10) ? 1.0 / error : 1.0;
        inverse_errors.push_back(inv_error);
        total_inverse_error += inv_error;
    }
    
    // Normalize to get weights
    for (size_t i = 0; i < inverse_errors.size(); ++i) {
        model_weights_[i] = inverse_errors[i] / total_inverse_error;
    }
}

// ============================================================================
// WorkloadForecaster Implementation
// ============================================================================

WorkloadForecaster::WorkloadForecaster(const ForecastingConfig& config)
    : config_(config)
    , stats_{} {}

WorkloadForecaster::~WorkloadForecaster() {
    Shutdown();
}

void WorkloadForecaster::Initialize() {
    // Create models for each metric
    std::vector<std::string> metrics = {
        "tasks_per_second",
        "cpu_utilization",
        "memory_utilization",
        "queue_depth",
        "average_wait_time"
    };
    
    for (const auto& metric : metrics) {
        models_[metric] = CreateModel(config_.model);
    }
    
    active_model_ = models_["tasks_per_second"];
}

void WorkloadForecaster::Start() {
    running_ = true;
    forecast_thread_ = std::thread(&WorkloadForecaster::ForecastLoop, this);
}

void WorkloadForecaster::Stop() {
    running_ = false;
    
    if (forecast_thread_.joinable()) {
        forecast_thread_.join();
    }
}

void WorkloadForecaster::Shutdown() {
    Stop();
}

void WorkloadForecaster::RecordMetric(const WorkloadMetrics& metrics) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    workload_history_.push_back(metrics);
    
    // Keep limited history
    while (workload_history_.size() > config_.history_window_hours * 12) {
        workload_history_.erase(workload_history_.begin());
    }
    
    // Update stats
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.data_points_collected++;
    }
}

void WorkloadForecaster::RecordTimeSeries(const std::string& series_name, double value) {
    TimeSeriesPoint point;
    point.timestamp = std::chrono::steady_clock::now();
    point.value = value;
    
    RecordTimeSeries(series_name, point);
}

void WorkloadForecaster::RecordTimeSeries(const std::string& series_name, 
                                          const TimeSeriesPoint& point) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    time_series_data_[series_name].push_back(point);
    
    // Keep limited history
    auto cutoff = std::chrono::steady_clock::now() - std::chrono::hours(config_.history_window_hours);
    auto& series = time_series_data_[series_name];
    series.erase(
        std::remove_if(series.begin(), series.end(),
            [cutoff](const TimeSeriesPoint& p) { return p.timestamp < cutoff; }),
        series.end());
    
    // Update model
    auto it = models_.find(series_name);
    if (it != models_.end()) {
        it->second->Update(point);
    }
}

ForecastResult WorkloadForecaster::ForecastWorkload(uint32_t hours_ahead) {
    return ForecastMetric("tasks_per_second", hours_ahead);
}

ForecastResult WorkloadForecaster::ForecastMetric(const std::string& metric_name, 
                                                   uint32_t hours_ahead) {
    std::lock_guard<std::mutex> lock(model_mutex_);
    
    auto it = models_.find(metric_name);
    if (it == models_.end()) {
        return ForecastResult{};
    }
    
    auto result = it->second->Forecast(hours_ahead);
    
    // Update stats
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.forecasts_generated++;
        stats_.last_forecast = std::chrono::steady_clock::now();
    }
    
    // Check thresholds
    if (!result.predicted_values.empty()) {
        CheckThresholds(metric_name, result.predicted_values[0]);
    }
    
    return result;
}

std::map<uint32_t, ForecastResult> WorkloadForecaster::ForecastMultipleHorizons(
    const std::vector<uint32_t>& horizons) {
    
    std::map<uint32_t, ForecastResult> results;
    
    for (uint32_t horizon : horizons) {
        results[horizon] = ForecastWorkload(horizon);
    }
    
    return results;
}

bool WorkloadForecaster::IsAnomaly(const std::string& metric_name, double value) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    auto it = time_series_data_.find(metric_name);
    if (it == time_series_data_.end() || it->second.size() < 10) {
        return false;
    }
    
    // Calculate mean and stddev
    double sum = 0.0;
    for (const auto& point : it->second) {
        sum += point.value;
    }
    double mean = sum / it->second.size();
    
    double variance = 0.0;
    for (const auto& point : it->second) {
        variance += std::pow(point.value - mean, 2);
    }
    double stddev = std::sqrt(variance / it->second.size());
    
    // Check if value is more than 3 stddev from mean
    return std::abs(value - mean) > 3.0 * stddev;
}

std::vector<std::string> WorkloadForecaster::DetectAnomalies() {
    std::vector<std::string> anomalies;
    
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    for (const auto& [name, series] : time_series_data_) {
        if (series.empty()) continue;
        
        double latest_value = series.back().value;
        if (IsAnomaly(name, latest_value)) {
            anomalies.push_back(name);
            
            // Update stats
            {
                std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                stats_.anomalies_detected++;
            }
        }
    }
    
    return anomalies;
}

std::vector<WorkloadForecaster::Pattern> WorkloadForecaster::DetectPatterns(
    const std::string& metric_name) {
    
    std::vector<Pattern> patterns;
    
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    auto it = time_series_data_.find(metric_name);
    if (it == time_series_data_.end() || it->second.size() < 24) {
        return patterns;
    }
    
    // Detect trend
    double trend = ForecastingUtils::CalculateTrend(it->second);
    if (std::abs(trend) > 0.1) {
        Pattern pattern;
        pattern.type = (trend > 0) ? "uptrend" : "downtrend";
        pattern.strength = std::abs(trend);
        pattern.start_time = it->second.front().timestamp;
        pattern.end_time = it->second.back().timestamp;
        patterns.push_back(pattern);
    }
    
    // Detect seasonality
    if (config_.detect_seasonality) {
        double seasonality = ForecastingUtils::CalculateSeasonalityStrength(
            it->second, config_.seasonality_period);
        if (seasonality > 0.3) {
            Pattern pattern;
            pattern.type = "seasonal";
            pattern.strength = seasonality;
            pattern.start_time = it->second.front().timestamp;
            pattern.end_time = it->second.back().timestamp;
            patterns.push_back(pattern);
        }
    }
    
    return patterns;
}

void WorkloadForecaster::SelectBestModel() {
    if (!config_.auto_select_best) return;
    
    // Evaluate all models and select best
    std::string best_model;
    double best_score = std::numeric_limits<double>::infinity();
    
    for (const auto& [name, model] : models_) {
        auto data = GetTrainingData(name);
        if (data.size() < 24) continue;
        
        // Split data for validation
        size_t split = data.size() * 0.8;
        std::vector<TimeSeriesPoint> train_data(data.begin(), data.begin() + split);
        std::vector<TimeSeriesPoint> test_data(data.begin() + split, data.end());
        
        model->Train(train_data);
        double score = model->Evaluate(test_data);
        
        if (score < best_score) {
            best_score = score;
            best_model = name;
        }
    }
    
    if (!best_model.empty()) {
        std::lock_guard<std::mutex> lock(model_mutex_);
        active_model_ = models_[best_model];
    }
}

std::string WorkloadForecaster::GetCurrentModelName() const {
    std::lock_guard<std::mutex> lock(model_mutex_);
    return active_model_ ? active_model_->GetName() : "None";
}

std::map<std::string, double> WorkloadForecaster::GetModelPerformance() const {
    std::map<std::string, double> performance;
    
    std::lock_guard<std::mutex> lock(model_mutex_);
    
    for (const auto& [name, model] : models_) {
        auto data = GetTrainingData(name);
        if (data.size() >= 24) {
            performance[name] = model->Evaluate(data);
        }
    }
    
    return performance;
}

void WorkloadForecaster::SetAlertCallback(AlertCallback callback) {
    alert_callback_ = callback;
}

void WorkloadForecaster::SetThreshold(const std::string& metric_name, double threshold) {
    thresholds_[metric_name] = threshold;
}

WorkloadForecaster::ForecasterStats WorkloadForecaster::GetStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void WorkloadForecaster::ExportForecast(const std::string& metric_name, 
                                        const std::string& path) const {
    auto forecast = ForecastMetric(metric_name, config_.forecast_horizon_hours);
    
    std::ofstream file(path);
    if (!file.is_open()) return;
    
    file << "timestamp,predicted,lower_bound,upper_bound\n";
    
    for (size_t i = 0; i < forecast.predicted_values.size(); ++i) {
        auto time_t = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now() + 
            (forecast.timestamps[i] - std::chrono::steady_clock::now()));
        
        file << time_t << ","
             << forecast.predicted_values[i] << ","
             << forecast.confidence_intervals_lower[i] << ","
             << forecast.confidence_intervals_upper[i] << "\n";
    }
}

void WorkloadForecaster::ExportTrainingData(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return;
    
    file << "metric,timestamp,value\n";
    
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    for (const auto& [name, series] : time_series_data_) {
        for (const auto& point : series) {
            auto time_t = std::chrono::system_clock::to_time_t(
                std::chrono::system_clock::now() + 
                (point.timestamp - std::chrono::steady_clock::now()));
            
            file << name << "," << time_t << "," << point.value << "\n";
        }
    }
}

void WorkloadForecaster::ForecastLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::minutes(config_.update_interval_minutes));
        
        if (!running_) break;
        
        // Train models
        TrainModels();
        
        // Evaluate models
        if (config_.auto_select_best) {
            EvaluateModels();
            SelectBestModel();
        }
        
        // Detect anomalies
        DetectAnomalies();
    }
}

void WorkloadForecaster::TrainModels() {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    for (auto& [name, model] : models_) {
        auto data = GetTrainingData(name);
        if (data.size() >= 24) {
            model->Train(data);
        }
    }
    
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.last_training = std::chrono::steady_clock::now();
    }
}

void WorkloadForecaster::EvaluateModels() {
    // Models are evaluated in SelectBestModel
}

void WorkloadForecaster::CheckThresholds(const std::string& metric_name, 
                                          double predicted_value) {
    auto it = thresholds_.find(metric_name);
    if (it == thresholds_.end()) return;
    
    if (predicted_value > it->second) {
        if (alert_callback_) {
            alert_callback_("THRESHOLD_EXCEEDED", 
                          metric_name + " predicted to exceed threshold");
        }
    }
}

std::shared_ptr<ForecastingModelBase> WorkloadForecaster::CreateModel(ForecastingModel type) {
    switch (type) {
        case ForecastingModel::NAIVE:
            return std::make_shared<NaiveModel>();
        case ForecastingModel::MOVING_AVERAGE:
            return std::make_shared<MovingAverageModel>(config_.ma_window);
        case ForecastingModel::EXPONENTIAL_SMOOTHING:
            return std::make_shared<ExponentialSmoothingModel>(config_.alpha);
        case ForecastingModel::ARIMA:
            return std::make_shared<ARIMAModel>(config_.arima_p, config_.arima_d, config_.arima_q);
        case ForecastingModel::ENSEMBLE:
        case ForecastingModel::ADAPTIVE: {
            std::vector<std::shared_ptr<ForecastingModelBase>> ensemble_models;
            for (auto model_type : config_.ensemble_models) {
                ensemble_models.push_back(CreateModel(model_type));
            }
            return std::make_shared<EnsembleModel>(ensemble_models);
        }
        default:
            return std::make_shared<MovingAverageModel>(config_.ma_window);
    }
}

std::vector<TimeSeriesPoint> WorkloadForecaster::GetTrainingData(const std::string& metric_name) const {
    auto it = time_series_data_.find(metric_name);
    if (it != time_series_data_.end()) {
        return it->second;
    }
    return {};
}

// ============================================================================
// PredictiveSchedulerIntegration Implementation
// ============================================================================

PredictiveSchedulerIntegration::PredictiveSchedulerIntegration(WorkloadForecaster* forecaster)
    : forecaster_(forecaster) {}

void PredictiveSchedulerIntegration::PreWarmWorkers(uint32_t minutes_ahead) {
    auto forecast = forecaster_->ForecastWorkload(minutes_ahead / 60 + 1);
    
    if (!forecast.predicted_values.empty()) {
        double predicted_load = forecast.predicted_values[0];
        // Would trigger worker pre-warming in production
        (void)predicted_load;
    }
}

void PredictiveSchedulerIntegration::PreLoadModels(uint32_t minutes_ahead) {
    (void)minutes_ahead;
    // Would trigger model pre-loading in production
}

void PredictiveSchedulerIntegration::ScaleResources(const ForecastResult& forecast) {
    for (const auto& value : forecast.predicted_values) {
        // Would trigger resource scaling in production
        (void)value;
    }
}

PredictiveSchedulerIntegration::SchedulingHint 
PredictiveSchedulerIntegration::GetOptimalSchedulingTime(uint32_t flexibility_minutes) {
    SchedulingHint hint;
    
    // Forecast workload for the flexibility window
    auto forecast = forecaster_->ForecastWorkload(flexibility_minutes / 60 + 1);
    
    if (forecast.predicted_values.empty()) {
        hint.optimal_time = std::chrono::steady_clock::now();
        hint.expected_load = 0.5;
        hint.recommended_workers = 4;
        hint.reason = "No forecast available";
        return hint;
    }
    
    // Find time with lowest predicted load
    size_t min_idx = 0;
    double min_load = forecast.predicted_values[0];
    
    for (size_t i = 1; i < forecast.predicted_values.size(); ++i) {
        if (forecast.predicted_values[i] < min_load) {
            min_load = forecast.predicted_values[i];
            min_idx = i;
        }
    }
    
    hint.optimal_time = forecast.timestamps[min_idx];
    hint.expected_load = min_load;
    hint.recommended_workers = static_cast<uint32_t>(min_load / 10.0) + 2;
    hint.reason = "Lowest predicted workload";
    
    return hint;
}

std::vector<PredictiveSchedulerIntegration::SchedulingHint> 
PredictiveSchedulerIntegration::GetSchedulingPlan(uint32_t hours_ahead) {
    std::vector<SchedulingHint> plan;
    
    auto forecast = forecaster_->ForecastWorkload(hours_ahead);
    
    for (size_t i = 0; i < forecast.predicted_values.size(); ++i) {
        SchedulingHint hint;
        hint.optimal_time = forecast.timestamps[i];
        hint.expected_load = forecast.predicted_values[i];
        hint.recommended_workers = static_cast<uint32_t>(forecast.predicted_values[i] / 10.0) + 2;
        hint.reason = "Forecast-based scheduling";
        plan.push_back(hint);
    }
    
    return plan;
}

double PredictiveSchedulerIntegration::EstimateExecutionCost(
    const std::chrono::steady_clock::time_point& time) {
    (void)time;
    // Would estimate cost based on predicted load in production
    return 1.0;
}

std::chrono::steady_clock::time_point 
PredictiveSchedulerIntegration::FindCheapestExecutionWindow(uint32_t window_hours) {
    (void)window_hours;
    // Would find cheapest time window in production
    return std::chrono::steady_clock::now();
}

// ============================================================================
// ForecastingUtils Implementation
// ============================================================================

namespace ForecastingUtils {

double CalculateMean(const std::vector<double>& data) {
    if (data.empty()) return 0.0;
    return std::accumulate(data.begin(), data.end(), 0.0) / data.size();
}

double CalculateStdDev(const std::vector<double>& data) {
    if (data.size() < 2) return 0.0;
    
    double mean = CalculateMean(data);
    double variance = 0.0;
    
    for (double val : data) {
        variance += std::pow(val - mean, 2);
    }
    
    return std::sqrt(variance / data.size());
}

double CalculateVariance(const std::vector<double>& data) {
    if (data.size() < 2) return 0.0;
    
    double mean = CalculateMean(data);
    double variance = 0.0;
    
    for (double val : data) {
        variance += std::pow(val - mean, 2);
    }
    
    return variance / data.size();
}

double CalculateCov(const std::vector<double>& data) {
    double mean = CalculateMean(data);
    double stddev = CalculateStdDev(data);
    
    return (mean > 0.0) ? (stddev / mean) : 0.0;
}

std::vector<double> Difference(const std::vector<double>& data, uint32_t order) {
    std::vector<double> result = data;
    
    for (uint32_t i = 0; i < order; ++i) {
        std::vector<double> diff;
        for (size_t j = 1; j < result.size(); ++j) {
            diff.push_back(result[j] - result[j - 1]);
        }
        result = diff;
    }
    
    return result;
}

std::vector<double> MovingAverage(const std::vector<double>& data, uint32_t window) {
    std::vector<double> result;
    
    for (size_t i = window - 1; i < data.size(); ++i) {
        double sum = 0.0;
        for (size_t j = i - window + 1; j <= i; ++j) {
            sum += data[j];
        }
        result.push_back(sum / window);
    }
    
    return result;
}

std::vector<double> ExponentialSmoothing(const std::vector<double>& data, double alpha) {
    std::vector<double> result;
    
    if (data.empty()) return result;
    
    double smoothed = data[0];
    result.push_back(smoothed);
    
    for (size_t i = 1; i < data.size(); ++i) {
        smoothed = alpha * data[i] + (1.0 - alpha) * smoothed;
        result.push_back(smoothed);
    }
    
    return result;
}

bool HasSeasonality(const std::vector<TimeSeriesPoint>& data, uint32_t period) {
    if (data.size() < period * 2) return false;
    
    // Simple seasonality detection using autocorrelation
    std::vector<double> values;
    for (const auto& point : data) {
        values.push_back(point.value);
    }
    
    double autocorr = Autocorrelation(values, period);
    return autocorr > 0.5;
}

double CalculateSeasonalityStrength(const std::vector<TimeSeriesPoint>& data, 
                                     uint32_t period) {
    if (data.size() < period * 2) return 0.0;
    
    std::vector<double> values;
    for (const auto& point : data) {
        values.push_back(point.value);
    }
    
    return Autocorrelation(values, period);
}

double CalculateTrend(const std::vector<TimeSeriesPoint>& data) {
    if (data.size() < 2) return 0.0;
    
    std::vector<double> x;
    std::vector<double> y;
    
    for (size_t i = 0; i < data.size(); ++i) {
        x.push_back(static_cast<double>(i));
        y.push_back(data[i].value);
    }
    
    auto [slope, intercept] = LinearRegression(x, y);
    (void)intercept;
    
    return slope;
}

std::pair<double, double> LinearRegression(const std::vector<double>& x, 
                                            const std::vector<double>& y) {
    if (x.size() != y.size() || x.size() < 2) {
        return {0.0, 0.0};
    }
    
    double n = static_cast<double>(x.size());
    double sum_x = std::accumulate(x.begin(), x.end(), 0.0);
    double sum_y = std::accumulate(y.begin(), y.end(), 0.0);
    double sum_xy = 0.0;
    double sum_x2 = 0.0;
    
    for (size_t i = 0; i < x.size(); ++i) {
        sum_xy += x[i] * y[i];
        sum_x2 += x[i] * x[i];
    }
    
    double slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
    double intercept = (sum_y - slope * sum_x) / n;
    
    return {slope, intercept};
}

double Autocorrelation(const std::vector<double>& data, uint32_t lag) {
    if (data.size() < lag + 1) return 0.0;
    
    double mean = CalculateMean(data);
    double variance = CalculateVariance(data);
    
    if (variance < 1e-10) return 0.0;
    
    double autocov = 0.0;
    for (size_t i = lag; i < data.size(); ++i) {
        autocov += (data[i] - mean) * (data[i - lag] - mean);
    }
    autocov /= data.size();
    
    return autocov / variance;
}

std::vector<double> AutocorrelationFunction(const std::vector<double>& data, 
                                               uint32_t max_lag) {
    std::vector<double> acf;
    
    for (uint32_t lag = 0; lag <= max_lag; ++lag) {
        acf.push_back(Autocorrelation(data, lag));
    }
    
    return acf;
}

double CalculateMSE(const std::vector<double>& actual, 
                     const std::vector<double>& predicted) {
    if (actual.size() != predicted.size() || actual.empty()) {
        return 0.0;
    }
    
    double mse = 0.0;
    for (size_t i = 0; i < actual.size(); ++i) {
        mse += std::pow(actual[i] - predicted[i], 2);
    }
    
    return mse / actual.size();
}

double CalculateMAE(const std::vector<double>& actual, 
                     const std::vector<double>& predicted) {
    if (actual.size() != predicted.size() || actual.empty()) {
        return 0.0;
    }
    
    double mae = 0.0;
    for (size_t i = 0; i < actual.size(); ++i) {
        mae += std::abs(actual[i] - predicted[i]);
    }
    
    return mae / actual.size();
}

double CalculateRMSE(const std::vector<double>& actual, 
                      const std::vector<double>& predicted) {
    return std::sqrt(CalculateMSE(actual, predicted));
}

double CalculateMAPE(const std::vector<double>& actual, 
                        const std::vector<double>& predicted) {
    if (actual.size() != predicted.size() || actual.empty()) {
        return 0.0;
    }
    
    double mape = 0.0;
    uint32_t count = 0;
    
    for (size_t i = 0; i < actual.size(); ++i) {
        if (std::abs(actual[i]) > 1e-10) {
            mape += std::abs((actual[i] - predicted[i]) / actual[i]);
            ++count;
        }
    }
    
    return (count > 0) ? (mape / count * 100.0) : 0.0;
}

std::pair<double, double> CalculateConfidenceInterval(const std::vector<double>& errors,
                                                       double confidence_level) {
    double mean = CalculateMean(errors);
    double stddev = CalculateStdDev(errors);
    
    // Z-score for confidence level
    double z_score = 1.96; // 95% confidence
    if (confidence_level == 0.90) z_score = 1.645;
    else if (confidence_level == 0.99) z_score = 2.576;
    
    double margin = z_score * stddev / std::sqrt(errors.size());
    
    return {mean - margin, mean + margin};
}

} // namespace ForecastingUtils

} // namespace Predictive
