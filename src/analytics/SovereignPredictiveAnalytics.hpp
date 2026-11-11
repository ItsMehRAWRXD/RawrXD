// Phase D.18 Batch 4/5: Predictive Analytics
// Forecasting and predictive modeling
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
struct ForecastModel;
struct PredictionRequest;
struct ForecastResult;

// ============================================================================
// Predictive Analytics Types
// ============================================================================

enum class ForecastModelType {
    ARIMA = 0,
    EXPONENTIAL_SMOOTHING = 1,
    PROPHET = 2,
    LSTM = 3,
    LINEAR_REGRESSION = 4,
    ENSEMBLE = 5
};

enum class TrendType {
    NONE = 0,
    LINEAR = 1,
    EXPONENTIAL = 2,
    SEASONAL = 3
};

struct TimeSeriesPoint {
    std::chrono::steady_clock::time_point timestamp;
    double value;
    std::map<std::string, std::any> features;
};

struct ForecastModel {
    std::string model_id;
    std::string name;
    ForecastModelType type;
    std::map<std::string, std::any> parameters;
    std::map<std::string, double> metrics;
    std::chrono::steady_clock::time_point trained_at;
    std::chrono::steady_clock::time_point last_updated;
    bool is_active;
};

struct ForecastResult {
    std::string forecast_id;
    std::string model_id;
    std::vector<TimeSeriesPoint> predictions;
    std::vector<std::pair<double, double>> confidence_intervals;
    double confidence_level;
    TrendType detected_trend;
    std::map<std::string, std::any> metadata;
    std::chrono::steady_clock::time_point generated_at;
};

// ============================================================================
// Time Series Forecaster
// ============================================================================

class TimeSeriesForecaster {
public:
    struct Config {
        int default_horizon = 24;  // hours
        double confidence_level = 0.95;
        bool detect_seasonality = true;
        bool detect_trend = true;
        int min_data_points = 30;
    };
    
    struct ModelFitResult {
        bool success;
        std::map<std::string, double> coefficients;
        double aic;  // Akaike Information Criterion
        double bic;  // Bayesian Information Criterion
        double rmse;
        double mae;
        std::string error_message;
    };
    
    explicit TimeSeriesForecaster(const Config& config);
    ~TimeSeriesForecaster();
    
    bool Initialize();
    void Shutdown();
    
    // Model fitting
    ModelFitResult FitARIMA(const std::vector<TimeSeriesPoint>& data, int p, int d, int q);
    ModelFitResult FitExponentialSmoothing(const std::vector<TimeSeriesPoint>& data, 
                                            bool seasonal = false);
    ModelFitResult FitLinearRegression(const std::vector<TimeSeriesPoint>& data);
    
    // Forecasting
    ForecastResult Forecast(const std::string& model_id, int horizon);
    ForecastResult ForecastWithConfidence(const std::string& model_id, int horizon, 
                                          double confidence_level);
    
    // Model management
    std::string RegisterModel(const ForecastModel& model);
    bool UpdateModel(const std::string& model_id, const ForecastModel& model);
    bool DeleteModel(const std::string& model_id);
    ForecastModel GetModel(const std::string& model_id) const;
    
    // Analysis
    TrendType DetectTrend(const std::vector<TimeSeriesPoint>& data);
    std::vector<int> DetectSeasonality(const std::vector<TimeSeriesPoint>& data);
    std::map<std::string, double> CalculateMetrics(const std::vector<TimeSeriesPoint>& actual,
                                                   const std::vector<TimeSeriesPoint>& predicted);
    
private:
    Config config_;
    std::map<std::string, ForecastModel> models_;
    mutable std::mutex models_mutex_;
    
    std::vector<double> ExtractValues(const std::vector<TimeSeriesPoint>& data);
    std::vector<std::vector<double>> CreateFeatures(const std::vector<TimeSeriesPoint>& data);
};

// ============================================================================
// Capacity Planner
// ============================================================================

class CapacityPlanner {
public:
    struct Config {
        int planning_horizon_days = 90;
        double safety_factor = 1.2;
        bool consider_growth = true;
        double growth_rate = 0.05;  // 5% monthly
    };
    
    struct ResourceMetrics {
        std::string resource_name;
        double current_usage;
        double capacity;
        double utilization_percent;
        std::vector<TimeSeriesPoint> historical_usage;
        std::chrono::steady_clock::time_point measured_at;
    };
    
    struct CapacityPlan {
        std::string plan_id;
        std::string resource_name;
        double recommended_capacity;
        double projected_peak;
        std::chrono::steady_clock::time_point projected_date;
        std::vector<std::pair<std::chrono::steady_clock::time_point, double>> milestones;
        std::map<std::string, std::any> recommendations;
    };
    
    explicit CapacityPlanner(const Config& config);
    ~CapacityPlanner();
    
    bool Initialize();
    void Shutdown();
    
    // Planning
    CapacityPlan CreatePlan(const std::string& resource_name, 
                            const ResourceMetrics& metrics);
    std::vector<CapacityPlan> CreateMultiResourcePlan(
        const std::vector<ResourceMetrics>& resources);
    
    // What-if analysis
    CapacityPlan WhatIfScenario(const std::string& resource_name,
                                 const ResourceMetrics& metrics,
                                 double growth_multiplier);
    
    // Recommendations
    std::vector<std::string> GetOptimizationRecommendations(const std::string& resource_name);
    std::chrono::steady_clock::time_point PredictCapacityExhaustion(
        const std::string& resource_name, const ResourceMetrics& metrics);
    
private:
    Config config_;
    
    double ProjectUsage(const ResourceMetrics& metrics, int days_ahead);
    double CalculateSafetyMargin(double projected_usage);
};

// ============================================================================
// Demand Predictor
// ============================================================================

class DemandPredictor {
public:
    struct Config {
        int forecast_horizon = 30;  // days
        bool use_external_factors = true;
        std::vector<std::string> external_factors;
    };
    
    struct DemandForecast {
        std::string forecast_id;
        std::string product_id;
        std::vector<std::pair<std::chrono::steady_clock::time_point, double>> predictions;
        double confidence_interval;
        std::map<std::string, double> factor_impact;
        std::chrono::steady_clock::time_point generated_at;
    };
    
    explicit DemandPredictor(const Config& config);
    ~DemandPredictor();
    
    bool Initialize();
    void Shutdown();
    
    // Forecasting
    DemandForecast PredictDemand(const std::string& product_id,
                                  const std::vector<TimeSeriesPoint>& historical_sales);
    std::vector<DemandForecast> PredictDemandForCategory(
        const std::string& category_id,
        const std::map<std::string, std::vector<TimeSeriesPoint>>& product_sales);
    
    // Factor analysis
    std::map<std::string, double> AnalyzeFactors(const std::string& product_id);
    double CalculateSeasonalityIndex(const std::string& product_id);
    double CalculateTrendStrength(const std::string& product_id);
    
private:
    Config config_;
    
    std::vector<double> ExtractExternalFactors(const std::chrono::steady_clock::time_point& timestamp);
};

// ============================================================================
// Predictive Maintenance
// ============================================================================

class PredictiveMaintenance {
public:
    struct Config {
        double failure_threshold = 0.8;
        int prediction_horizon_hours = 168;  // 1 week
        bool enable_early_warning = true;
        double warning_threshold = 0.6;
    };
    
    struct EquipmentHealth {
        std::string equipment_id;
        double health_score;  // 0-1
        double failure_probability;
        std::chrono::steady_clock::time_point predicted_failure;
        std::vector<std::string> risk_factors;
        std::map<std::string, double> sensor_readings;
        std::chrono::steady_clock::time_point assessed_at;
    };
    
    struct MaintenanceRecommendation {
        std::string equipment_id;
        std::string maintenance_type;
        std::chrono::steady_clock::time_point recommended_date;
        std::string priority;
        std::vector<std::string> actions;
        double estimated_cost;
    };
    
    explicit PredictiveMaintenance(const Config& config);
    ~PredictiveMaintenance();
    
    bool Initialize();
    void Shutdown();
    
    // Health assessment
    EquipmentHealth AssessEquipment(const std::string& equipment_id,
                                     const std::map<std::string, double>& sensor_data);
    std::vector<EquipmentHealth> AssessAllEquipment();
    
    // Failure prediction
    double PredictFailureProbability(const std::string& equipment_id, int hours_ahead);
    std::chrono::steady_clock::time_point PredictRemainingLife(const std::string& equipment_id);
    
    // Recommendations
    std::vector<MaintenanceRecommendation> GenerateRecommendations();
    MaintenanceRecommendation GetRecommendation(const std::string& equipment_id);
    
    // Optimization
    std::vector<MaintenanceRecommendation> OptimizeSchedule(
        const std::vector<MaintenanceRecommendation>& recommendations);
    
private:
    Config config_;
    std::map<std::string, EquipmentHealth> equipment_health_;
    mutable std::mutex health_mutex_;
    
    double CalculateHealthScore(const std::map<std::string, double>& sensor_data);
    std::vector<std::string> IdentifyRiskFactors(const std::map<std::string, double>& sensor_data);
};

// ============================================================================
// Predictive Analytics Runtime
// ============================================================================

class PredictiveAnalyticsRuntime {
public:
    struct Config {
        TimeSeriesForecaster::Config forecaster;
        CapacityPlanner::Config planner;
        DemandPredictor::Config demand;
        PredictiveMaintenance::Config maintenance;
    };
    
    explicit PredictiveAnalyticsRuntime(const Config& config);
    ~PredictiveAnalyticsRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    TimeSeriesForecaster* GetForecaster();
    CapacityPlanner* GetPlanner();
    DemandPredictor* GetDemandPredictor();
    PredictiveMaintenance* GetMaintenance();
    
    // High-level API
    ForecastResult ForecastMetric(const std::string& metric_name, int horizon);
    CapacityPlan PlanCapacity(const std::string& resource_name);
    EquipmentHealth CheckEquipmentHealth(const std::string& equipment_id);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<TimeSeriesForecaster> forecaster_;
    std::unique_ptr<CapacityPlanner> planner_;
    std::unique_ptr<DemandPredictor> demand_predictor_;
    std::unique_ptr<PredictiveMaintenance> maintenance_;
};

} // namespace Analytics
} // namespace Sovereign
