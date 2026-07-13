// Phase P.1/5: Cost Tracking & Optimization
// RawrXD Cost Tracker - Infrastructure cost management

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <optional>

namespace RawrXD {
namespace Operations {

// Resource types for costing
enum class ResourceType {
    GPU_COMPUTE,        // GPU compute hours
    CPU_COMPUTE,        // CPU compute hours
    MEMORY,             // RAM usage
    STORAGE,            // Disk/storage
    NETWORK_INGRESS,    // Incoming data transfer
    NETWORK_EGRESS,     // Outgoing data transfer
    LOAD_BALANCER,      // Load balancer hours
    API_CALLS           // Number of API requests
};

// Cost rates (per unit)
struct CostRate {
    ResourceType resource_type;
    std::string region;
    double rate_per_unit;           // Cost per unit
    std::string unit;               // e.g., "hour", "GB", "million"
    std::string currency = "USD";
    std::chrono::system_clock::time_point effective_from;
    std::optional<std::chrono::system_clock::time_point> effective_until;
};

// Resource usage record
struct ResourceUsage {
    std::string resource_id;
    ResourceType type;
    std::string tenant_id;
    std::string user_id;
    std::string model_id;
    
    double quantity;                // Amount used
    std::string unit;
    
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    std::chrono::milliseconds duration_ms;
    
    std::unordered_map<std::string, std::string> metadata;
};

// Cost record
struct CostRecord {
    std::string id;
    ResourceUsage usage;
    double cost_amount;
    std::string currency;
    CostRate rate_applied;
    std::chrono::system_clock::time_point calculated_at;
    bool estimated;                 // True if projected cost
};

// Budget configuration
struct BudgetConfig {
    std::string id;
    std::string name;
    std::string tenant_id;          // Empty for global budget
    
    double monthly_limit;
    double alert_threshold_50;
    double alert_threshold_80;
    double alert_threshold_100;
    
    std::vector<ResourceType> included_resources;
    std::vector<std::string> included_models;
    std::vector<std::string> included_users;
    
    bool enforce_limit;             // Hard stop at limit
    std::string notification_email;
};

// Cost allocation
struct CostAllocation {
    std::string tenant_id;
    std::string user_id;
    std::string project_id;
    std::string model_id;
    
    double compute_cost;
    double storage_cost;
    double network_cost;
    double other_cost;
    double total_cost;
    
    uint64_t inference_requests;
    uint64_t tokens_processed;
    double avg_latency_ms;
};

// Cost optimization recommendation
struct CostRecommendation {
    std::string id;
    std::string title;
    std::string description;
    
    enum class Priority {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    } priority;
    
    enum class Category {
        RIGHT_SIZING,       // Adjust resource allocation
        SPOT_INSTANCES,     // Use spot/preemptible
        RESERVED_CAPACITY,  // Commit to reserved instances
        AUTO_SCALING,       // Optimize scaling policies
        MODEL_OPTIMIZATION, // Quantization, pruning
        SCHEDULING,         // Time-based scheduling
        STORAGE_TIERING,    // Move to cheaper storage
        NETWORK             // Optimize data transfer
    } category;
    
    double estimated_savings_monthly;
    double implementation_effort_hours;
    std::string implementation_guide;
    bool automated;                 // Can be auto-applied
    
    std::vector<std::string> affected_resources;
    std::chrono::system_clock::time_point generated_at;
};

// Cost tracker interface
class ICostTracker {
public:
    virtual ~ICostTracker() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Rate management
    virtual bool SetCostRate(const CostRate& rate) = 0;
    virtual std::optional<CostRate> GetCurrentRate(ResourceType type, 
                                                      const std::string& region = "default") = 0;
    virtual std::vector<CostRate> GetRateHistory(ResourceType type) = 0;
    
    // Usage tracking
    virtual bool RecordUsage(const ResourceUsage& usage) = 0;
    virtual bool RecordUsageBatch(const std::vector<ResourceUsage>& usages) = 0;
    
    // Cost calculation
    virtual CostRecord CalculateCost(const ResourceUsage& usage) = 0;
    virtual std::vector<CostRecord> GetCosts(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        const std::string& tenant_id = "") = 0;
    
    // Aggregation
    virtual std::unordered_map<ResourceType, double> GetCostsByResource(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        const std::string& tenant_id = "") = 0;
    
    virtual std::unordered_map<std::string, double> GetCostsByTenant(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end) = 0;
    
    virtual CostAllocation GetCostAllocation(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        const std::string& tenant_id) = 0;
    
    // Budget management
    virtual bool CreateBudget(const BudgetConfig& budget) = 0;
    virtual bool UpdateBudget(const BudgetConfig& budget) = 0;
    virtual bool DeleteBudget(const std::string& budget_id) = 0;
    virtual std::optional<BudgetConfig> GetBudget(const std::string& budget_id) = 0;
    virtual std::vector<BudgetConfig> ListBudgets(const std::string& tenant_id = "") = 0;
    
    // Budget monitoring
    virtual double GetCurrentSpend(const std::string& budget_id) = 0;
    virtual double GetProjectedSpend(const std::string& budget_id) = 0;
    virtual double GetBudgetUtilization(const std::string& budget_id) = 0;
    virtual bool CheckBudgetAlert(const std::string& budget_id) = 0;
    
    // Forecasting
    virtual double ForecastSpend(const std::string& budget_id,
                                  uint32_t days_ahead) = 0;
    virtual std::vector<double> GetSpendForecast(
        const std::string& tenant_id,
        uint32_t days_of_history,
        uint32_t days_to_forecast) = 0;
    
    // Optimization
    virtual std::vector<CostRecommendation> GenerateRecommendations(
        const std::string& tenant_id = "") = 0;
    virtual bool ApplyRecommendation(const std::string& recommendation_id) = 0;
    virtual double EstimateSavings(const std::vector<std::string>& recommendation_ids) = 0;
    
    // Reporting
    virtual bool GenerateCostReport(
        const std::string& output_path,
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        const std::string& format = "csv") = 0;
    
    // Showback/Charging
    virtual bool GenerateShowbackReport(
        std::chrono::system_clock::time_point month,
        const std::string& output_path) = 0;
};

// Local cost tracker implementation
class LocalCostTracker : public ICostTracker {
public:
    LocalCostTracker();
    ~LocalCostTracker() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    bool SetCostRate(const CostRate& rate) override;
    std::optional<CostRate> GetCurrentRate(ResourceType type, 
                                               const std::string& region = "default") override;
    std::vector<CostRate> GetRateHistory(ResourceType type) override;
    
    bool RecordUsage(const ResourceUsage& usage) override;
    bool RecordUsageBatch(const std::vector<ResourceUsage>& usages) override;
    
    CostRecord CalculateCost(const ResourceUsage& usage) override;
    std::vector<CostRecord> GetCosts(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        const std::string& tenant_id = "") override;
    
    std::unordered_map<ResourceType, double> GetCostsByResource(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        const std::string& tenant_id = "") override;
    
    std::unordered_map<std::string, double> GetCostsByTenant(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end) override;
    
    CostAllocation GetCostAllocation(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        const std::string& tenant_id) override;
    
    bool CreateBudget(const BudgetConfig& budget) override;
    bool UpdateBudget(const BudgetConfig& budget) override;
    bool DeleteBudget(const std::string& budget_id) override;
    std::optional<BudgetConfig> GetBudget(const std::string& budget_id) override;
    std::vector<BudgetConfig> ListBudgets(const std::string& tenant_id = "") override;
    
    double GetCurrentSpend(const std::string& budget_id) override;
    double GetProjectedSpend(const std::string& budget_id) override;
    double GetBudgetUtilization(const std::string& budget_id) override;
    bool CheckBudgetAlert(const std::string& budget_id) override;
    
    double ForecastSpend(const std::string& budget_id,
                         uint32_t days_ahead) override;
    std::vector<double> GetSpendForecast(
        const std::string& tenant_id,
        uint32_t days_of_history,
        uint32_t days_to_forecast) override;
    
    std::vector<CostRecommendation> GenerateRecommendations(
        const std::string& tenant_id = "") override;
    bool ApplyRecommendation(const std::string& recommendation_id) override;
    double EstimateSavings(const std::vector<std::string>& recommendation_ids) override;
    
    bool GenerateCostReport(
        const std::string& output_path,
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        const std::string& format = "csv") override;
    
    bool GenerateShowbackReport(
        std::chrono::system_clock::time_point month,
        const std::string& output_path) override;
    
private:
    std::unordered_map<ResourceType, std::vector<CostRate>> rates_;
    std::vector<CostRecord> cost_records_;
    std::unordered_map<std::string, BudgetConfig> budgets_;
    bool initialized_ = false;
    
    double CalculateUsageCost(const ResourceUsage& usage, const CostRate& rate);
    CostRate FindApplicableRate(ResourceType type, const std::string& region,
                                 std::chrono::system_clock::time_point timestamp);
};

// Cost optimization engine
class CostOptimizationEngine {
public:
    struct OptimizationConfig {
        bool enable_right_sizing = true;
        bool enable_spot_instances = true;
        bool enable_auto_scaling = true;
        bool enable_model_optimization = true;
        double min_savings_threshold = 10.0;  // Minimum savings to recommend
    };
    
    explicit CostOptimizationEngine(const OptimizationConfig& config);
    
    // Analysis
    std::vector<CostRecommendation> AnalyzeUsagePatterns(
        const std::vector<ResourceUsage>& usages);
    
    std::vector<CostRecommendation> AnalyzeIdleResources(
        const std::vector<ResourceUsage>& usages);
    
    std::vector<CostRecommendation> AnalyzeOverProvisioning(
        const std::vector<ResourceUsage& usages);
    
    // Specific optimizations
    CostRecommendation RecommendRightSizing(
        const std::string& resource_id,
        const std::vector<ResourceUsage>& history);
    
    CostRecommendation RecommendSpotInstance(
        const std::string& resource_id);
    
    CostRecommendation RecommendModelQuantization(
        const std::string& model_id);
    
    CostRecommendation RecommendBatching(
        const std::string& endpoint_id);
    
private:
    OptimizationConfig config_;
};

// Usage efficiency metrics
struct EfficiencyMetrics {
    double gpu_utilization_avg;
    double gpu_memory_utilization_avg;
    double cpu_utilization_avg;
    double memory_utilization_avg;
    
    double cost_per_token;
    double cost_per_request;
    double cost_per_hour;
    
    double idle_time_percentage;
    double overprovisioned_percentage;
    
    std::chrono::system_clock::time_point calculated_at;
};

// Global cost tracker
extern std::unique_ptr<ICostTracker> g_cost_tracker;

// Initialize cost tracking
bool InitializeCostTracking(const std::string& config_path);
void ShutdownCostTracking();
bool IsCostTrackingEnabled();

} // namespace Operations
} // namespace RawrXD
