// Phase N.1/5: Multi-Tenancy Support
// RawrXD Multi-Tenancy - Isolated tenant environments

#pragma once

#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <chrono>

namespace RawrXD {
namespace Enterprise {

// Tenant identification
using TenantID = std::string;

// Tenant isolation level
enum class IsolationLevel {
    SHARED,           // Shared resources, logical separation only
    SOFT,            // Shared compute, separate quotas
    HARD,            // Dedicated compute pools
    DEDICATED        // Fully dedicated infrastructure
};

// Tenant configuration
struct TenantConfig {
    TenantID id;
    std::string name;
    std::string description;
    IsolationLevel isolation_level;
    
    // Resource quotas
    struct ResourceQuotas {
        uint32_t max_concurrent_requests = 100;
        uint32_t max_tokens_per_minute = 100000;
        uint32_t max_requests_per_minute = 1000;
        uint64_t max_memory_mb = 8192;
        uint32_t max_gpu_memory_mb = 4096;
        uint32_t max_batch_size = 32;
        uint32_t max_context_length = 32768;
    } quotas;
    
    // Rate limiting
    struct RateLimiting {
        bool enabled = true;
        uint32_t burst_size = 10;
        uint32_t refill_rate = 1;  // per second
        uint32_t cooldown_seconds = 60;
    } rate_limiting;
    
    // Priority
    uint32_t priority = 5;  // 1-10, higher = more priority
    
    // Features
    struct FeatureFlags {
        bool enable_vision = false;
        bool enable_function_calling = false;
        bool enable_plugins = false;
        bool enable_streaming = true;
        bool enable_batching = true;
        std::vector<std::string> allowed_models;
    } features;
    
    // Security
    struct SecurityConfig {
        std::string api_key_prefix;
        bool require_mfa = false;
        std::vector<std::string> allowed_ip_ranges;
        std::vector<std::string> blocked_ip_ranges;
        uint32_t max_token_ttl_hours = 24;
    } security;
    
    // Metadata
    std::string created_by;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
    bool active = true;
    std::unordered_map<std::string, std::string> metadata;
};

// Tenant resource usage
struct TenantUsage {
    TenantID tenant_id;
    
    // Current usage
    uint32_t current_concurrent_requests = 0;
    uint32_t tokens_this_minute = 0;
    uint32_t requests_this_minute = 0;
    uint64_t current_memory_mb = 0;
    uint32_t current_gpu_memory_mb = 0;
    
    // Historical
    uint64_t total_tokens_processed = 0;
    uint64_t total_requests_processed = 0;
    uint64_t total_inference_time_ms = 0;
    
    // Rate limiting state
    std::chrono::system_clock::time_point last_request_time;
    uint32_t current_burst = 0;
    bool rate_limited = false;
    std::chrono::system_clock::time_point rate_limit_until;
};

// Tenant context for request processing
class TenantContext {
public:
    explicit TenantContext(const TenantConfig& config);
    
    // Accessors
    const TenantID& GetID() const { return config_.id; }
    const TenantConfig& GetConfig() const { return config_; }
    TenantUsage& GetUsage() { return usage_; }
    const TenantUsage& GetUsage() const { return usage_; }
    
    // Quota checks
    bool CanProcessRequest(uint32_t estimated_tokens) const;
    bool CheckRateLimit();
    bool AcquireResources(uint32_t memory_mb, uint32_t gpu_memory_mb = 0);
    void ReleaseResources(uint32_t memory_mb, uint32_t gpu_memory_mb = 0);
    
    // Usage tracking
    void RecordRequest(uint32_t tokens, uint32_t inference_time_ms);
    void RecordTokens(uint32_t token_count);
    
    // Feature checks
    bool HasFeature(const std::string& feature) const;
    bool CanUseModel(const std::string& model) const;
    
    // Security
    bool ValidateIPAddress(const std::string& ip) const;
    bool ValidateAPIKey(const std::string& key) const;
    
private:
    TenantConfig config_;
    TenantUsage usage_;
    mutable std::mutex mutex_;
};

// Multi-tenancy manager
class MultiTenancyManager {
public:
    MultiTenancyManager();
    ~MultiTenancyManager();
    
    // Initialization
    bool Initialize(const std::string& config_path);
    void Shutdown();
    
    // Tenant management
    bool CreateTenant(const TenantConfig& config);
    bool UpdateTenant(const TenantID& id, const TenantConfig& config);
    bool DeleteTenant(const TenantID& id);
    bool ActivateTenant(const TenantID& id);
    bool DeactivateTenant(const TenantID& id);
    
    // Tenant lookup
    std::shared_ptr<TenantContext> GetTenant(const TenantID& id);
    std::shared_ptr<TenantContext> GetTenantByAPIKey(const std::string& api_key);
    bool TenantExists(const TenantID& id) const;
    std::vector<TenantConfig> ListTenants() const;
    
    // Context management
    std::shared_ptr<TenantContext> CreateRequestContext(const TenantID& id);
    void DestroyRequestContext(const TenantID& id);
    
    // Resource management
    struct GlobalResources {
        uint64_t total_memory_mb;
        uint64_t used_memory_mb;
        uint32_t total_gpu_memory_mb;
        uint32_t used_gpu_memory_mb;
        uint32_t total_concurrent_requests;
        uint32_t active_concurrent_requests;
    };
    GlobalResources GetGlobalResources() const;
    bool AllocateResources(const TenantID& id, const ResourceRequest& request);
    void FreeResources(const TenantID& id, const ResourceRequest& request);
    
    // Usage aggregation
    struct AggregatedUsage {
        uint64_t total_tokens;
        uint64_t total_requests;
        double average_latency_ms;
        std::unordered_map<TenantID, TenantUsage> per_tenant;
    };
    AggregatedUsage GetAggregatedUsage(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end) const;
    
    // Health checks
    struct TenantHealth {
        TenantID tenant_id;
        bool healthy;
        std::string status;
        float quota_utilization;
        float rate_limit_utilization;
    };
    std::vector<TenantHealth> GetTenantHealth() const;
    
    // Isolation enforcement
    bool EnforceIsolation(const TenantID& id1, const TenantID& id2);
    
private:
    std::unordered_map<TenantID, std::shared_ptr<TenantContext>> tenants_;
    std::unordered_map<std::string, TenantID> api_key_map_;
    mutable std::shared_mutex mutex_;
    bool initialized_ = false;
    
    GlobalResources global_resources_;
    mutable std::mutex resource_mutex_;
    
    // Persistence
    bool SaveTenantConfig(const TenantConfig& config);
    bool LoadTenantConfig(const TenantID& id, TenantConfig& config);
    bool DeleteTenantConfig(const TenantID& id);
};

// Resource request
struct ResourceRequest {
    uint32_t estimated_memory_mb = 0;
    uint32_t estimated_gpu_memory_mb = 0;
    uint32_t estimated_tokens = 0;
    uint32_t max_latency_ms = 30000;
    bool requires_gpu = false;
    std::string model_id;
};

// Tenant-aware request wrapper
template<typename T>
class TenantAwareRequest {
public:
    TenantAwareRequest(std::shared_ptr<TenantContext> tenant, T request)
        : tenant_(tenant), request_(std::move(request)) {}
    
    std::shared_ptr<TenantContext> GetTenant() const { return tenant_; }
    const T& GetRequest() const { return request_; }
    T& GetRequest() { return request_; }
    
    bool Validate() const {
        return tenant_ != nullptr && tenant_->CanProcessRequest(0);
    }
    
private:
    std::shared_ptr<TenantContext> tenant_;
    T request_;
};

// Tenant middleware for API
class TenantMiddleware {
public:
    explicit TenantMiddleware(std::shared_ptr<MultiTenancyManager> manager);
    
    // Extract tenant from request
    std::shared_ptr<TenantContext> ExtractTenant(const std::string& api_key);
    std::shared_ptr<TenantContext> ExtractTenantFromHeader(const std::string& header);
    
    // Request validation
    bool ValidateRequest(std::shared_ptr<TenantContext> tenant, const ResourceRequest& request);
    
    // Response enrichment
    void AddTenantHeaders(std::shared_ptr<TenantContext> tenant, std::unordered_map<std::string, std::string>& headers);
    
private:
    std::shared_ptr<MultiTenancyManager> manager_;
};

// Global multi-tenancy configuration
extern std::unique_ptr<MultiTenancyManager> g_tenancy_manager;

// Initialize multi-tenancy
bool InitializeMultiTenancy(const std::string& config_path);
void ShutdownMultiTenancy();
bool IsMultiTenancyEnabled();

} // namespace Enterprise
} // namespace RawrXD
