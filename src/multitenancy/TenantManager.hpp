/**
 * TenantManager.hpp
 *
 * Phase P Batch 1/5: Tenant Management & Isolation
 *
 * Multi-tenant architecture with tenant isolation, resource management,
 * and tenant lifecycle management.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>

namespace MultiTenancy {

// ============================================================================
// Forward Declarations
// ============================================================================

class Tenant;
class TenantContext;
class TenantManager;
class ResourceQuota;

// ============================================================================
// Tenant Tier
// ============================================================================

enum class TenantTier {
    FREE,
    BASIC,
    STANDARD,
    PREMIUM,
    ENTERPRISE,
    CUSTOM
};

std::string TenantTierToString(TenantTier tier);
TenantTier TenantTierFromString(const std::string& str);

// ============================================================================
// Tenant Status
// ============================================================================

enum class TenantStatus {
    PENDING,
    ACTIVE,
    SUSPENDED,
    EXPIRED,
    CANCELLED,
    MAINTENANCE
};

// ============================================================================
// Tenant
// ============================================================================

/**
 * Tenant in the multi-tenant system.
 */
class Tenant {
public:
    struct Config {
        std::string tenantId;
        std::string name;
        std::string slug;
        std::optional<std::string> parentTenantId;
        TenantTier tier;
        TenantStatus status;
        std::chrono::system_clock::time_point createdAt;
        std::optional<std::chrono::system_clock::time_point> expiresAt;
        std::map<std::string, std::string> settings;
        std::map<std::string, std::string> metadata;
        std::optional<std::string> billingEmail;
        std::optional<std::string> technicalEmail;
        std::optional<std::string> supportEmail;
        std::string timezone;
        std::string locale;
        std::string currency;
    };
    
    explicit Tenant(const Config& config);
    
    // Accessors
    const std::string& GetTenantId() const { return config_.tenantId; }
    const std::string& GetName() const { return config_.name; }
    const std::string& GetSlug() const { return config_.slug; }
    TenantTier GetTier() const { return config_.tier; }
    TenantStatus GetStatus() const { return config_.status; }
    
    // Hierarchy
    std::optional<std::string> GetParentTenantId() const { return config_.parentTenantId; }
    bool IsSubtenant() const { return config_.parentTenantId.has_value(); }
    
    // Settings
    void SetSetting(const std::string& key, const std::string& value);
    std::optional<std::string> GetSetting(const std::string& key) const;
    const std::map<std::string, std::string>& GetSettings() const { return config_.settings; }
    
    // Metadata
    void SetMetadata(const std::string& key, const std::string& value);
    std::optional<std::string> GetMetadata(const std::string& key) const;
    
    // Status management
    void Activate();
    void Suspend(const std::string& reason);
    void Resume();
    void Cancel();
    void SetMaintenanceMode(bool enabled);
    bool IsActive() const { return config_.status == TenantStatus::ACTIVE; }
    
    // Tier management
    void UpgradeTier(TenantTier newTier);
    void DowngradeTier(TenantTier newTier);
    bool CanAccessFeature(const std::string& feature) const;
    
    // Expiration
    bool IsExpired() const;
    void ExtendExpiration(std::chrono::days extension);
    void SetExpiration(std::chrono::system_clock::time_point expiresAt);
    
    // Serialization
    std::string ToJson() const;
    static Tenant FromJson(const std::string& json);
    
private:
    Config config_;
    mutable std::mutex mutex_;
    
    std::map<std::string, bool> GetTierFeatures() const;
};

// ============================================================================
// Tenant Context
// ============================================================================

/**
 * Context for tenant-scoped operations.
 */
class TenantContext {
public:
    explicit TenantContext(std::shared_ptr<Tenant> tenant);
    
    // Tenant access
    std::shared_ptr<Tenant> GetTenant() const { return tenant_; }
    const std::string& GetTenantId() const { return tenant_->GetTenantId(); }
    
    // Scoped operations
    template<typename T>
    T Execute(std::function<T()> operation);
    
    // Database scoping
    std::string GetDatabaseName() const;
    std::string GetSchemaName() const;
    std::string GetTablePrefix() const;
    
    // Resource scoping
    std::string GetResourcePrefix() const;
    std::string GetCacheNamespace() const;
    std::string GetQueuePrefix() const;
    
    // Feature flags
    bool IsFeatureEnabled(const std::string& feature) const;
    void SetFeatureFlag(const std::string& feature, bool enabled);
    
    // Custom properties
    void SetProperty(const std::string& key, std::any value);
    std::optional<std::any> GetProperty(const std::string& key) const;
    
    // Static current context
    static std::optional<std::shared_ptr<TenantContext>> Current();
    static void SetCurrent(std::shared_ptr<TenantContext> context);
    static void ClearCurrent();
    
private:
    std::shared_ptr<Tenant> tenant_;
    std::map<std::string, bool> featureFlags_;
    std::map<std::string, std::any> properties_;
    mutable std::mutex mutex_;
    
    static thread_local std::shared_ptr<TenantContext> currentContext_;
};

// ============================================================================
// Resource Quota
// ============================================================================

/**
 * Resource quota for tenant isolation.
 */
class ResourceQuota {
public:
    struct Limits {
        // Compute
        std::optional<uint32_t> maxCpuCores;
        std::optional<uint64_t> maxMemoryBytes;
        std::optional<uint32_t> maxConcurrentRequests;
        std::optional<uint32_t> maxConcurrentWorkflows;
        
        // Storage
        std::optional<uint64_t> maxStorageBytes;
        std::optional<uint32_t> maxDatabases;
        std::optional<uint32_t> maxTables;
        std::optional<uint64_t> maxRowCount;
        
        // Network
        std::optional<uint64_t> maxBandwidthBps;
        std::optional<uint32_t> maxConnections;
        std::optional<uint32_t> maxApiCallsPerMinute;
        std::optional<uint32_t> maxApiCallsPerHour;
        
        // Users
        std::optional<uint32_t> maxUsers;
        std::optional<uint32_t> maxGroups;
        std::optional<uint32_t> maxRoles;
        
        // Features
        std::optional<uint32_t> maxWorkflows;
        std::optional<uint32_t> maxScheduledJobs;
        std::optional<uint32_t> maxWebhooks;
        std::optional<uint32_t> maxIntegrations;
    };
    
    struct Usage {
        uint32_t cpuCoresUsed;
        uint64_t memoryBytesUsed;
        uint32_t concurrentRequests;
        uint32_t concurrentWorkflows;
        uint64_t storageBytesUsed;
        uint32_t databaseCount;
        uint32_t tableCount;
        uint64_t rowCount;
        uint64_t bandwidthBpsUsed;
        uint32_t activeConnections;
        uint32_t apiCallsLastMinute;
        uint32_t apiCallsLastHour;
        uint32_t userCount;
        uint32_t groupCount;
        uint32_t roleCount;
        uint32_t workflowCount;
        uint32_t scheduledJobCount;
        uint32_t webhookCount;
        uint32_t integrationCount;
    };
    
    explicit ResourceQuota(const std::string& tenantId, const Limits& limits);
    
    // Limit management
    void SetLimits(const Limits& limits);
    Limits GetLimits() const;
    
    // Usage tracking
    void UpdateUsage(const Usage& usage);
    Usage GetUsage() const;
    
    // Quota checking
    bool CheckQuota(const std::string& resource, uint64_t requested) const;
    bool CheckAndReserve(const std::string& resource, uint64_t requested);
    void Release(const std::string& resource, uint64_t amount);
    
    // Utilization
    double GetUtilization(const std::string& resource) const;
    std::map<std::string, double> GetAllUtilization() const;
    
    // Alerts
    std::vector<std::string> GetExceededQuotas() const;
    std::vector<std::string> GetWarningQuotas(double threshold = 0.8) const;
    
    // Reset
    void ResetUsage();
    void ResetUsage(const std::string& resource);
    
private:
    std::string tenantId_;
    Limits limits_;
    Usage usage_;
    mutable std::mutex mutex_;
    
    std::optional<uint64_t> GetLimit(const std::string& resource) const;
    uint64_t GetUsage(const std::string& resource) const;
};

// ============================================================================
// Tenant Isolation
// ============================================================================

/**
 * Tenant isolation strategies.
 */
class TenantIsolation {
public:
    enum class Strategy {
        DATABASE_PER_TENANT,
        SCHEMA_PER_TENANT,
        SHARED_SCHEMA,
        TABLE_PER_TENANT,
        ROW_LEVEL_SECURITY
    };
    
    struct Config {
        Strategy strategy;
        bool enableEncryption;
        std::optional<std::string> encryptionKey;
        bool enableAuditLogging;
        bool enableDataMasking;
        std::vector<std::string> sensitiveFields;
    };
    
    explicit TenantIsolation(const Config& config);
    
    // Strategy
    Strategy GetStrategy() const { return config_.strategy; }
    std::string GetStrategyName() const;
    
    // Database operations
    std::string GetDatabaseName(const std::string& tenantId) const;
    std::string GetSchemaName(const std::string& tenantId) const;
    std::string GetTableName(const std::string& tenantId,
                              const std::string& table) const;
    
    // Query modification
    std::string ApplyTenantFilter(const std::string& query,
                                     const std::string& tenantId) const;
    std::map<std::string, std::string> GetTenantContext(const std::string& tenantId) const;
    
    // Encryption
    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& data,
                                   const std::string& tenantId);
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& data,
                                   const std::string& tenantId);
    
    // Data masking
    std::string MaskSensitiveData(const std::string& field,
                                     const std::string& value) const;
    std::map<std::string, std::string> MaskRecord(
        const std::map<std::string, std::string>& record) const;
    
private:
    Config config_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Tenant Manager
// ============================================================================

/**
 * Central tenant manager.
 */
class TenantManager {
public:
    struct Config {
        TenantIsolation::Config isolationConfig;
        bool enableAutoProvisioning;
        bool enableSelfService;
        std::chrono::seconds provisioningTimeout;
        std::string defaultTier;
        std::map<TenantTier, ResourceQuota::Limits> tierLimits;
    };
    
    explicit TenantManager(const Config& config);
    ~TenantManager();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Tenant CRUD
    std::shared_ptr<Tenant> CreateTenant(const Tenant::Config& config);
    bool DeleteTenant(const std::string& tenantId);
    std::shared_ptr<Tenant> GetTenant(const std::string& tenantId) const;
    std::shared_ptr<Tenant> GetTenantBySlug(const std::string& slug) const;
    std::vector<std::shared_ptr<Tenant>> GetAllTenants() const;
    std::vector<std::shared_ptr<Tenant>> GetTenantsByTier(TenantTier tier) const;
    std::vector<std::shared_ptr<Tenant>> GetActiveTenants() const;
    
    // Tenant hierarchy
    std::vector<std::shared_ptr<Tenant>> GetSubtenants(const std::string& tenantId) const;
    std::optional<std::shared_ptr<Tenant>> GetParentTenant(const std::string& tenantId) const;
    bool MoveTenant(const std::string& tenantId,
                    const std::optional<std::string>& newParentId);
    
    // Context management
    std::shared_ptr<TenantContext> CreateContext(const std::string& tenantId);
    std::shared_ptr<TenantContext> CreateContext(std::shared_ptr<Tenant> tenant);
    
    // Resource quotas
    void SetQuota(const std::string& tenantId, const ResourceQuota::Limits& limits);
    std::shared_ptr<ResourceQuota> GetQuota(const std::string& tenantId);
    bool CheckQuota(const std::string& tenantId,
                    const std::string& resource,
                    uint64_t requested);
    
    // Provisioning
    bool ProvisionTenant(const std::string& tenantId);
    bool DeprovisionTenant(const std::string& tenantId);
    bool IsProvisioned(const std::string& tenantId) const;
    
    // Migration
    bool MigrateTenant(const std::string& tenantId,
                       TenantIsolation::Strategy newStrategy);
    
    // Backup/Restore
    bool BackupTenant(const std::string& tenantId, const std::string& backupPath);
    bool RestoreTenant(const std::string& backupPath,
                       const std::optional<std::string>& newTenantId = std::nullopt);
    
    // Cloning
    std::string CloneTenant(const std::string& sourceTenantId,
                            const std::string& newTenantName);
    
    // Statistics
    struct ManagerStats {
        uint32_t totalTenants;
        uint32_t activeTenants;
        uint32_t suspendedTenants;
        std::map<TenantTier, uint32_t> tenantsByTier;
        uint64_t totalStorageUsed;
        uint64_t totalApiCalls;
    };
    ManagerStats GetStats() const;
    
    // Health check
    bool HealthCheck() const;
    std::map<std::string, bool> GetTenantHealth() const;
    
    // Events
    using TenantEventCallback = std::function<void(const std::string& event,
                                                       const std::string& tenantId)>;
    void SubscribeToEvents(TenantEventCallback callback);
    
private:
    Config config_;
    bool initialized_;
    
    std::map<std::string, std::shared_ptr<Tenant>> tenants_;
    std::map<std::string, std::shared_ptr<ResourceQuota>> quotas_;
    mutable std::mutex mutex_;
    
    std::unique_ptr<TenantIsolation> isolation_;
    std::vector<TenantEventCallback> eventCallbacks_;
    mutable std::mutex eventMutex_;
    
    void EmitEvent(const std::string& event, const std::string& tenantId);
    void ApplyTierDefaults(Tenant::Config& config);
    bool ValidateTenantConfig(const Tenant::Config& config) const;
};

// ============================================================================
// Tenant Middleware
// ============================================================================

/**
 * Middleware for tenant resolution in API requests.
 */
class TenantMiddleware {
public:
    enum class ResolutionStrategy {
        SUBDOMAIN,
        HEADER,
        PATH,
        JWT_CLAIM,
        CUSTOM
    };
    
    struct Config {
        ResolutionStrategy strategy;
        std::string headerName;
        std::string claimName;
        std::string baseDomain;
        std::function<std::optional<std::string>(const class HTTPRequest&)> customResolver;
        bool requireTenant;
        std::optional<std::string> defaultTenant;
    };
    
    explicit TenantMiddleware(std::shared_ptr<TenantManager> manager,
                               const Config& config);
    
    // Resolution
    std::optional<std::string> ResolveTenant(const class HTTPRequest& request) const;
    std::shared_ptr<TenantContext> ResolveAndCreateContext(
        const class HTTPRequest& request);
    
    // Strategy
    ResolutionStrategy GetStrategy() const { return config_.strategy; }
    
    // Validation
    bool ValidateTenant(const std::string& tenantId) const;
    bool IsTenantActive(const std::string& tenantId) const;
    
private:
    std::shared_ptr<TenantManager> manager_;
    Config config_;
    
    std::optional<std::string> ResolveFromSubdomain(const class HTTPRequest& request) const;
    std::optional<std::string> ResolveFromHeader(const class HTTPRequest& request) const;
    std::optional<std::string> ResolveFromPath(const class HTTPRequest& request) const;
    std::optional<std::string> ResolveFromJwt(const class HTTPRequest& request) const;
};

} // namespace MultiTenancy
