/**
 * FeatureFlags.hpp
 *
 * Phase P Batch 3/5: Feature Flags & Configuration Management
 *
 * Feature flag system with tenant-specific configuration,
 * gradual rollouts, and A/B testing capabilities.
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

class FeatureFlag;
class FeatureFlagManager;
class ConfigurationManager;
class Experiment;

// ============================================================================
// Feature Flag Type
// ============================================================================

enum class FeatureFlagType {
    BOOLEAN,
    STRING,
    INTEGER,
    DOUBLE,
    JSON
};

// ============================================================================
// Rollout Strategy
// ============================================================================

enum class RolloutStrategy {
    ALL_USERS,
    PERCENTAGE,
    USER_ID,
    USER_ATTRIBUTE,
    GEOGRAPHIC,
    TIME_BASED,
    TENANT_SPECIFIC
};

// ============================================================================
// Feature Flag
// ============================================================================

/**
 * Feature flag definition.
 */
class FeatureFlag {
public:
    struct Config {
        std::string key;
        std::string name;
        std::string description;
        FeatureFlagType type;
        std::any defaultValue;
        bool enabled;
        RolloutStrategy rolloutStrategy;
        std::map<std::string, std::any> rolloutParameters;
        std::vector<std::string> tenantWhitelist;
        std::vector<std::string> tenantBlacklist;
        std::chrono::system_clock::time_point createdAt;
        std::optional<std::chrono::system_clock::time_point> expiresAt;
        std::map<std::string, std::string> metadata;
    };
    
    struct EvaluationContext {
        std::optional<std::string> userId;
        std::optional<std::string> tenantId;
        std::optional<std::string> sessionId;
        std::optional<std::string> ipAddress;
        std::optional<std::string> country;
        std::map<std::string, std::any> userAttributes;
        std::chrono::system_clock::time_point timestamp;
    };
    
    explicit FeatureFlag(const Config& config);
    
    // Evaluation
    bool IsEnabled(const EvaluationContext& context) const;
    std::any GetValue(const EvaluationContext& context) const;
    
    template<typename T>
    T GetValue(const EvaluationContext& context, const T& defaultValue) const;
    
    // Boolean convenience
    bool IsEnabled() const;
    bool IsEnabledForUser(const std::string& userId) const;
    bool IsEnabledForTenant(const std::string& tenantId) const;
    
    // Configuration
    void Enable();
    void Disable();
    void SetRolloutPercentage(double percentage);
    void AddToWhitelist(const std::string& tenantId);
    void RemoveFromWhitelist(const std::string& tenantId);
    void AddToBlacklist(const std::string& tenantId);
    void RemoveFromBlacklist(const std::string& tenantId);
    
    // Accessors
    const std::string& GetKey() const { return config_.key; }
    const std::string& GetName() const { return config_.name; }
    FeatureFlagType GetType() const { return config_.type; }
    bool IsGloballyEnabled() const { return config_.enabled; }
    
    // Statistics
    struct FlagStats {
        uint64_t totalEvaluations;
        uint64_t enabledCount;
        uint64_t disabledCount;
        double enabledPercentage;
    };
    FlagStats GetStats() const;
    void ResetStats();
    
    // Serialization
    std::string ToJson() const;
    static FeatureFlag FromJson(const std::string& json);
    
private:
    Config config_;
    FlagStats stats_;
    mutable std::mutex mutex_;
    
    bool EvaluateRollout(const EvaluationContext& context) const;
    bool EvaluatePercentage(const EvaluationContext& context, double percentage) const;
    bool EvaluateUserId(const EvaluationContext& context) const;
    bool EvaluateUserAttribute(const EvaluationContext& context) const;
    bool EvaluateGeographic(const EvaluationContext& context) const;
    bool EvaluateTimeBased(const EvaluationContext& context) const;
    bool EvaluateTenantSpecific(const EvaluationContext& context) const;
    
    uint32_t HashUserId(const std::string& userId) const;
};

// ============================================================================
// Feature Flag Manager
// ============================================================================

/**
 * Central feature flag manager.
 */
class FeatureFlagManager {
public:
    struct Config {
        std::chrono::seconds refreshInterval;
        bool enableCaching;
        std::chrono::seconds cacheTtl;
        bool enableAnalytics;
    };
    
    explicit FeatureFlagManager(const Config& config);
    ~FeatureFlagManager();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Flag registration
    void RegisterFlag(std::shared_ptr<FeatureFlag> flag);
    void RegisterFlag(const FeatureFlag::Config& config);
    void UnregisterFlag(const std::string& key);
    std::shared_ptr<FeatureFlag> GetFlag(const std::string& key) const;
    std::vector<std::shared_ptr<FeatureFlag>> GetAllFlags() const;
    std::vector<std::shared_ptr<FeatureFlag>> GetEnabledFlags() const;
    
    // Evaluation
    bool IsEnabled(const std::string& key) const;
    bool IsEnabled(const std::string& key,
                   const FeatureFlag::EvaluationContext& context) const;
    
    template<typename T>
    T GetValue(const std::string& key,
               const FeatureFlag::EvaluationContext& context,
               const T& defaultValue) const;
    
    // Bulk evaluation
    std::map<std::string, bool> EvaluateAll(const FeatureFlag::EvaluationContext& context) const;
    std::map<std::string, std::any> GetAllValues(
        const FeatureFlag::EvaluationContext& context) const;
    
    // Context builders
    FeatureFlag::EvaluationContext BuildContext() const;
    FeatureFlag::EvaluationContext BuildContext(const std::string& userId) const;
    FeatureFlag::EvaluationContext BuildContext(const std::string& userId,
                                                 const std::string& tenantId) const;
    
    // Flag updates
    void UpdateFlag(const std::string& key, bool enabled);
    void UpdateFlag(const std::string& key, const std::any& value);
    void UpdateRolloutPercentage(const std::string& key, double percentage);
    
    // Import/Export
    void ExportToJson(const std::string& filePath) const;
    void ImportFromJson(const std::string& filePath);
    
    // Analytics
    struct FlagAnalytics {
        std::string flagKey;
        uint64_t totalEvaluations;
        uint64_t enabledCount;
        uint64_t disabledCount;
        std::map<std::string, uint64_t> evaluationsByTenant;
        std::map<std::string, uint64_t> evaluationsByUser;
    };
    std::vector<FlagAnalytics> GetAnalytics() const;
    FlagAnalytics GetAnalyticsForFlag(const std::string& key) const;
    
    // Events
    using FlagChangeCallback = std::function<void(const std::string& key, bool enabled)>;
    void OnFlagChange(FlagChangeCallback callback);
    
private:
    Config config_;
    bool initialized_;
    
    std::map<std::string, std::shared_ptr<FeatureFlag>> flags_;
    mutable std::mutex flagsMutex_;
    
    // Cache
    struct CacheEntry {
        std::any value;
        std::chrono::system_clock::time_point expiresAt;
    };
    std::map<std::string, CacheEntry> cache_;
    mutable std::mutex cacheMutex_;
    
    FlagChangeCallback changeCallback_;
    mutable std::mutex callbackMutex_;
    
    std::thread refreshThread_;
    std::atomic<bool> stopRefresh_;
    
    void RefreshLoop();
    void InvalidateCache(const std::string& key);
    std::string MakeCacheKey(const std::string& flagKey,
                              const FeatureFlag::EvaluationContext& context) const;
};

// ============================================================================
// Configuration Value
// ============================================================================

/**
 * Typed configuration value.
 */
class ConfigValue {
public:
    enum class Type {
        STRING,
        INTEGER,
        DOUBLE,
        BOOLEAN,
        ARRAY,
        OBJECT,
        NULL_VALUE
    };
    
    ConfigValue();
    explicit ConfigValue(const std::string& value);
    explicit ConfigValue(int64_t value);
    explicit ConfigValue(double value);
    explicit ConfigValue(bool value);
    explicit ConfigValue(const std::vector<ConfigValue>& value);
    explicit ConfigValue(const std::map<std::string, ConfigValue>& value);
    
    // Type checking
    Type GetType() const { return type_; }
    bool IsNull() const { return type_ == Type::NULL_VALUE; }
    bool IsString() const { return type_ == Type::STRING; }
    bool IsInteger() const { return type_ == Type::INTEGER; }
    bool IsDouble() const { return type_ == Type::DOUBLE; }
    bool IsBoolean() const { return type_ == Type::BOOLEAN; }
    bool IsArray() const { return type_ == Type::ARRAY; }
    bool IsObject() const { return type_ == Type::OBJECT; }
    
    // Value access
    template<typename T>
    T Get() const;
    
    template<typename T>
    std::optional<T> GetOptional() const;
    
    // Conversion
    std::string ToString() const;
    int64_t ToInteger() const;
    double ToDouble() const;
    bool ToBoolean() const;
    
    // Array/Object access
    size_t Size() const;
    ConfigValue Get(size_t index) const;
    ConfigValue Get(const std::string& key) const;
    bool HasKey(const std::string& key) const;
    std::vector<std::string> GetKeys() const;
    
    // Serialization
    std::string ToJson() const;
    static ConfigValue FromJson(const std::string& json);
    
private:
    Type type_;
    std::string stringValue_;
    int64_t intValue_;
    double doubleValue_;
    bool boolValue_;
    std::vector<ConfigValue> arrayValue_;
    std::map<std::string, ConfigValue> objectValue_;
};

// ============================================================================
// Configuration Source
// ============================================================================

/**
 * Configuration source interface.
 */
class ConfigSource {
public:
    virtual ~ConfigSource() = default;
    
    virtual std::optional<ConfigValue> Get(const std::string& key) = 0;
    virtual std::map<std::string, ConfigValue> GetAll() = 0;
    virtual bool Exists(const std::string& key) = 0;
    virtual std::string GetName() const = 0;
    virtual int GetPriority() const { return 100; }
};

/**
 * Environment variable configuration source.
 */
class EnvironmentConfigSource : public ConfigSource {
public:
    explicit EnvironmentConfigSource(const std::string& prefix = "");
    
    std::optional<ConfigValue> Get(const std::string& key) override;
    std::map<std::string, ConfigValue> GetAll() override;
    bool Exists(const std::string& key) override;
    std::string GetName() const override { return "Environment"; }
    int GetPriority() const override { return 200; }
    
private:
    std::string prefix_;
    
    std::string ToEnvKey(const std::string& key) const;
    std::string FromEnvKey(const std::string& envKey) const;
};

/**
 * File configuration source.
 */
class FileConfigSource : public ConfigSource {
public:
    explicit FileConfigSource(const std::string& filePath);
    
    std::optional<ConfigValue> Get(const std::string& key) override;
    std::map<std::string, ConfigValue> GetAll() override;
    bool Exists(const std::string& key) override;
    std::string GetName() const override { return "File:" + filePath_; }
    int GetPriority() const override { return 150; }
    
    void Reload();
    
private:
    std::string filePath_;
    std::map<std::string, ConfigValue> values_;
    mutable std::mutex mutex_;
    
    void Load();
};

/**
 * Database configuration source.
 */
class DatabaseConfigSource : public ConfigSource {
public:
    struct Config {
        std::string connectionString;
        std::string tableName;
        std::string keyColumn;
        std::string valueColumn;
        std::optional<std::string> tenantColumn;
        std::chrono::seconds cacheTtl;
    };
    
    explicit DatabaseConfigSource(const Config& config);
    
    std::optional<ConfigValue> Get(const std::string& key) override;
    std::map<std::string, ConfigValue> GetAll() override;
    bool Exists(const std::string& key) override;
    std::string GetName() const override { return "Database"; }
    int GetPriority() const override { return 100; }
    
    void SetTenant(const std::string& tenantId);
    void ClearTenant();
    
private:
    Config config_;
    std::optional<std::string> tenantId_;
    mutable std::mutex mutex_;
    
    std::map<std::string, ConfigValue> cache_;
    std::chrono::system_clock::time_point cacheExpires_;
    
    void LoadFromDatabase();
};

// ============================================================================
// Configuration Manager
// ============================================================================

/**
 * Central configuration manager.
 */
class ConfigurationManager {
public:
    struct Config {
        bool enableHotReload;
        std::chrono::seconds reloadInterval;
        bool enableValidation;
        std::string schemaPath;
    };
    
    explicit ConfigurationManager(const Config& config);
    ~ConfigurationManager();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Source management
    void AddSource(std::shared_ptr<ConfigSource> source);
    void RemoveSource(const std::string& name);
    std::vector<std::shared_ptr<ConfigSource>> GetSources() const;
    
    // Configuration access
    ConfigValue Get(const std::string& key) const;
    ConfigValue Get(const std::string& key, const ConfigValue& defaultValue) const;
    
    template<typename T>
    T Get(const std::string& key) const;
    
    template<typename T>
    T Get(const std::string& key, const T& defaultValue) const;
    
    bool Exists(const std::string& key) const;
    std::vector<std::string> GetKeys() const;
    std::map<std::string, ConfigValue> GetAll() const;
    
    // Typed accessors
    std::string GetString(const std::string& key,
                          const std::string& defaultValue = "") const;
    int64_t GetInteger(const std::string& key, int64_t defaultValue = 0) const;
    double GetDouble(const std::string& key, double defaultValue = 0.0) const;
    bool GetBoolean(const std::string& key, bool defaultValue = false) const;
    std::vector<ConfigValue> GetArray(const std::string& key) const;
    std::map<std::string, ConfigValue> GetObject(const std::string& key) const;
    
    // Tenant-specific configuration
    void SetTenant(const std::string& tenantId);
    void ClearTenant();
    ConfigValue GetForTenant(const std::string& tenantId, const std::string& key) const;
    void SetForTenant(const std::string& tenantId,
                      const std::string& key,
                      const ConfigValue& value);
    
    // Validation
    bool Validate() const;
    std::vector<std::string> GetValidationErrors() const;
    
    // Reload
    void Reload();
    void ReloadSource(const std::string& name);
    
    // Events
    using ConfigChangeCallback = std::function<void(const std::string& key,
                                                      const ConfigValue& oldValue,
                                                      const ConfigValue& newValue)>;
    void OnConfigChange(ConfigChangeCallback callback);
    
    // Secrets
    void RegisterSecret(const std::string& key, const std::string& encryptedValue);
    std::string GetSecret(const std::string& key) const;
    
private:
    Config config_;
    bool initialized_;
    
    std::vector<std::shared_ptr<ConfigSource>> sources_;
    mutable std::mutex sourcesMutex_;
    
    std::optional<std::string> currentTenant_;
    mutable std::mutex tenantMutex_;
    
    ConfigChangeCallback changeCallback_;
    mutable std::mutex callbackMutex_;
    
    std::thread reloadThread_;
    std::atomic<bool> stopReload_;
    
    void ReloadLoop();
    std::optional<ConfigValue> GetFromSources(const std::string& key) const;
};

// ============================================================================
// Experiment
// ============================================================================

/**
 * A/B testing experiment.
 */
class Experiment {
public:
    enum class Status {
        DRAFT,
        RUNNING,
        PAUSED,
        COMPLETED
    };
    
    struct Variant {
        std::string id;
        std::string name;
        std::string description;
        double trafficPercentage;
        std::map<std::string, ConfigValue> configOverrides;
        uint64_t participantCount;
        uint64_t conversionCount;
    };
    
    struct Metric {
        std::string name;
        std::string type;  // conversion, revenue, engagement
        std::function<double(const std::map<std::string, std::any>&)> calculator;
    };
    
    struct Config {
        std::string experimentId;
        std::string name;
        std::string description;
        std::string featureFlagKey;
        Status status;
        std::vector<Variant> variants;
        std::vector<Metric> metrics;
        std::chrono::system_clock::time_point startTime;
        std::optional<std::chrono::system_clock::time_point> endTime;
        uint64_t minSampleSize;
        double confidenceLevel;
        std::map<std::string, std::string> targetingRules;
    };
    
    explicit Experiment(const Config& config);
    
    // Lifecycle
    void Start();
    void Pause();
    void Resume();
    void Stop();
    
    // Variant assignment
    std::string AssignVariant(const std::string& userId);
    std::string GetVariantForUser(const std::string& userId) const;
    
    // Event tracking
    void TrackEvent(const std::string& userId,
                    const std::string& eventName,
                    const std::map<std::string, std::any>& properties);
    void TrackConversion(const std::string& userId,
                         const std::string& conversionName);
    
    // Analysis
    struct VariantResult {
        std::string variantId;
        uint64_t participants;
        uint64_t conversions;
        double conversionRate;
        double confidenceInterval;
        bool isWinner;
        double liftPercentage;
    };
    
    struct ExperimentResult {
        std::string experimentId;
        bool isSignificant;
        std::string winningVariant;
        std::vector<VariantResult> variantResults;
        std::chrono::milliseconds duration;
    };
    
    ExperimentResult GetResults() const;
    bool IsSignificant() const;
    std::string GetWinningVariant() const;
    
    // Accessors
    const std::string& GetExperimentId() const { return config_.experimentId; }
    Status GetStatus() const { return config_.status; }
    
private:
    Config config_;
    mutable std::mutex mutex_;
    
    std::map<std::string, std::string> userAssignments_;
    std::map<std::string, std::vector<std::map<std::string, std::any>>> events_;
    
    uint32_t HashUserId(const std::string& userId) const;
    bool ShouldIncludeUser(const std::string& userId) const;
    double CalculateConfidenceInterval(uint64_t conversions, uint64_t participants) const;
};

} // namespace MultiTenancy
