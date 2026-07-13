// Phase D.6 Batch 3/5: Cost Optimization
// Resource Right-Sizing and Billing Analytics
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "SovereignPredictiveAutoscaling.hpp"
#include <vector>
#include <map>
#include <memory>
#include <chrono>

namespace Sovereign {
namespace Intelligence {

// ============================================================================
// Resource Types and Pricing
// ============================================================================

enum class ResourceType {
    COMPUTE = 0,
    STORAGE = 1,
    NETWORK = 2,
    MEMORY = 3,
    GPU = 4,
    LICENSE = 5
};

enum class PricingModel {
    ON_DEMAND = 0,
    RESERVED = 1,
    SPOT = 2,
    SAVINGS_PLANS = 3,
    COMMITTED_USE = 4
};

struct ResourcePricing {
    std::string sku;
    ResourceType resource_type;
    PricingModel pricing_model;
    double hourly_rate = 0.0;
    double monthly_rate = 0.0;
    std::string region;
    std::map<std::string, std::string> attributes;
};

struct ResourceUsage {
    std::string resource_id;
    ResourceType type;
    double quantity = 0.0;
    std::string unit;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    double cost = 0.0;
    std::map<std::string, std::string> labels;
};

// ============================================================================
// Cost Analyzer
// ============================================================================

class CostAnalyzer {
public:
    struct Config {
        std::string currency = "USD";
        int analysis_window_days = 30;
        bool enable_forecasting = true;
        int forecast_horizon_days = 90;
    };
    
    explicit CostAnalyzer(const Config& config);
    
    bool Initialize();
    
    // Cost analysis
    struct CostBreakdown {
        double total_cost = 0.0;
        std::map<ResourceType, double> cost_by_type;
        std::map<std::string, double> cost_by_service;
        std::map<std::string, double> cost_by_region;
        std::map<PricingModel, double> cost_by_pricing_model;
        double projected_monthly_cost = 0.0;
        double projected_annual_cost = 0.0;
    };
    
    CostBreakdown AnalyzeCosts(const std::vector<ResourceUsage>& usage_data);
    
    // Trend analysis
    struct CostTrend {
        double current_period_cost = 0.0;
        double previous_period_cost = 0.0;
        double percent_change = 0.0;
        std::string trend_direction;  // "increasing", "decreasing", "stable"
        std::vector<std::string> top_increases;
        std::vector<std::string> top_decreases;
    };
    
    CostTrend AnalyzeTrends(int days = 30);
    
    // Forecasting
    double ForecastMonthlyCost(int months_ahead = 1);
    std::map<std::string, double> ForecastByService(int months_ahead = 1);
    
    // Anomaly detection
    std::vector<std::string> DetectCostAnomalies();
    
private:
    Config config_;
    
    double CalculateProjectedCost(const std::vector<ResourceUsage>& usage);
};

// ============================================================================
// Right-Sizing Engine
// ============================================================================

class RightSizingEngine {
public:
    struct Config {
        double utilization_threshold_low = 0.3;   // Below 30% = underutilized
        double utilization_threshold_high = 0.8;  // Above 80% = overutilized
        int analysis_window_days = 7;
        bool enable_auto_recommendations = true;
        int min_instance_age_hours = 24;
    };
    
    struct ResourceMetrics {
        std::string resource_id;
        ResourceType type;
        double avg_cpu_utilization = 0.0;
        double peak_cpu_utilization = 0.0;
        double avg_memory_utilization = 0.0;
        double peak_memory_utilization = 0.0;
        double network_io_mbps = 0.0;
        double disk_io_mbps = 0.0;
        int uptime_hours = 0;
        double current_cost_per_hour = 0.0;
    };
    
    struct SizingRecommendation {
        std::string resource_id;
        std::string current_sku;
        std::string recommended_sku;
        double estimated_savings_percent = 0.0;
        double estimated_savings_monthly = 0.0;
        std::string reason;
        std::string risk_level;  // "low", "medium", "high"
        double confidence = 0.0;
        bool requires_migration = false;
    };
    
    explicit RightSizingEngine(const Config& config);
    
    bool Initialize();
    
    // Analysis
    std::vector<SizingRecommendation> AnalyzeResources(
        const std::vector<ResourceMetrics>& metrics);
    
    SizingRecommendation AnalyzeSingleResource(const ResourceMetrics& metrics);
    
    // Recommendation management
    bool ApplyRecommendation(const std::string& recommendation_id);
    bool ScheduleRecommendation(const std::string& recommendation_id,
                                 std::chrono::steady_clock::time_point when);
    bool DismissRecommendation(const std::string& recommendation_id);
    
    std::vector<SizingRecommendation> GetPendingRecommendations() const;
    std::vector<SizingRecommendation> GetAppliedRecommendations(int limit = 100) const;
    
    // Savings tracking
    struct SavingsReport {
        double total_savings_monthly = 0.0;
        double total_savings_annual = 0.0;
        int recommendations_applied = 0;
        int recommendations_pending = 0;
        double potential_additional_savings = 0.0;
    };
    
    SavingsReport GetSavingsReport() const;
    
private:
    Config config_;
    
    mutable std::mutex recommendations_mutex_;
    std::vector<SizingRecommendation> recommendations_;
    
    std::string FindOptimalSKU(const ResourceMetrics& metrics);
    double CalculateSavings(const std::string& current_sku, 
                           const std::string& recommended_sku);
};

// ============================================================================
// Spot Instance Manager
// ============================================================================

class SpotInstanceManager {
public:
    struct Config {
        double max_spot_percentage = 0.5;  // Max 50% spot instances
        double spot_discount_threshold = 0.7;  // Min 70% discount
        int min_instances = 2;
        int termination_buffer_minutes = 2;
        bool enable_fleet_management = true;
    };
    
    struct SpotInstance {
        std::string instance_id;
        std::string instance_type;
        std::string availability_zone;
        double spot_price = 0.0;
        double on_demand_price = 0.0;
        double discount_percent = 0.0;
        std::chrono::steady_clock::time_point launch_time;
        std::chrono::steady_clock::time_point termination_time;
        bool terminated = false;
        std::string termination_reason;
    };
    
    struct SpotMarket {
        std::string instance_type;
        std::string availability_zone;
        double current_price = 0.0;
        double average_price_24h = 0.0;
        double max_price_24h = 0.0;
        double interruption_rate = 0.0;
        std::chrono::steady_clock::time_point last_updated;
    };
    
    explicit SpotInstanceManager(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Market monitoring
    void UpdateMarketPrices();
    std::vector<SpotMarket> GetMarketPrices() const;
    SpotMarket GetMarketForInstanceType(const std::string& instance_type,
                                        const std::string& az) const;
    
    // Instance management
    std::string RequestSpotInstance(const std::string& instance_type,
                                    const std::string& availability_zone,
                                    double max_price);
    bool TerminateSpotInstance(const std::string& instance_id);
    std::vector<SpotInstance> GetActiveInstances() const;
    
    // Fleet optimization
    struct FleetOptimization {
        int target_spot_count = 0;
        int current_spot_count = 0;
        std::vector<std::string> instances_to_launch;
        std::vector<std::string> instances_to_terminate;
        double estimated_savings = 0.0;
        double interruption_risk = 0.0;
    };
    
    FleetOptimization OptimizeFleet(int target_capacity);
    
    // Interruption handling
    void HandleInterruptionWarning(const std::string& instance_id);
    void MigrateWorkload(const std::string& from_instance,
                         const std::string& to_instance);
    
    // Savings calculation
    double CalculateSpotSavings() const;
    double CalculatePotentialSavings() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::thread market_thread_;
    
    mutable std::mutex instances_mutex_;
    std::map<std::string, SpotInstance> instances_;
    
    mutable std::mutex market_mutex_;
    std::map<std::string, SpotMarket> market_data_;
    
    void MarketMonitoringLoop();
    std::string GetMarketKey(const std::string& instance_type,
                             const std::string& az);
};

// ============================================================================
// Reserved Instance Planner
// ============================================================================

class ReservedInstancePlanner {
public:
    struct Config {
        int planning_horizon_months = 12;
        double min_utilization_threshold = 0.7;
        bool enable_convertible_ri = true;
        int min_commitment_months = 1;
    };
    
    struct RIRecommendation {
        std::string instance_type;
        std::string platform;  // "Linux", "Windows"
        std::string tenancy;   // "default", "dedicated"
        int recommended_quantity = 0;
        std::string offering_class;  // "standard", "convertible"
        std::string term;  // "1yr", "3yr"
        std::string payment_option;  // "all_upfront", "partial_upfront", "no_upfront"
        double upfront_cost = 0.0;
        double monthly_cost = 0.0;
        double estimated_savings = 0.0;
        double savings_percent = 0.0;
        double break_even_months = 0.0;
        double utilization_prediction = 0.0;
    };
    
    explicit ReservedInstancePlanner(const Config& config);
    
    bool Initialize();
    
    // Planning
    std::vector<RIRecommendation> GenerateRecommendations(
        const std::vector<ResourceUsage>& usage_history);
    
    RIRecommendation RecommendForInstanceType(
        const std::string& instance_type,
        const std::vector<ResourceUsage>& usage_history);
    
    // Analysis
    struct RIUtilization {
        std::string reservation_id;
        int purchased_quantity = 0;
        int utilized_quantity = 0;
        double utilization_percent = 0.0;
        double waste_cost = 0.0;
        std::chrono::steady_clock::time_point expiry_date;
    };
    
    std::vector<RIUtilization> AnalyzeRIUtilization() const;
    
    // Optimization
    std::vector<std::string> IdentifyUnderutilizedRIs();
    std::vector<std::string> IdentifyCoverageGaps();
    
    // Savings projection
    struct RISavingsProjection {
        double current_monthly_cost = 0.0;
        double projected_monthly_cost = 0.0;
        double monthly_savings = 0.0;
        double annual_savings = 0.0;
        double roi_percent = 0.0;
    };
    
    RISavingsProjection ProjectSavings(
        const std::vector<RIRecommendation>& recommendations);
    
private:
    Config config_;
    
    double CalculateBreakEven(const RIRecommendation& recommendation);
    double PredictUtilization(const std::string& instance_type,
                               const std::vector<ResourceUsage>& history);
};

} // namespace Intelligence
} // namespace Sovereign
