// Phase X.3/5: Production Configuration Management
// RawrXD Configuration Manager - Environment-specific settings and secrets management

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>
#include <variant>

namespace RawrXD {
namespace Operations {

// Configuration value types
using ConfigValue = std::variant<
    bool,
    int64_t,
    double,
    std::string,
    std::vector<std::string>,
    std::unordered_map<std::string, std::string>
>;

// Configuration source
enum class ConfigSource {
    DEFAULT,        // Built-in defaults
    FILE,           // Configuration file
    ENVIRONMENT,    // Environment variables
    SECRET_STORE,   // Secret management system
    COMMAND_LINE,   // Command line arguments
    REMOTE,         // Remote configuration service
    OVERRIDDEN      // Runtime override
};

// Configuration entry
struct ConfigEntry {
    std::string key;
    ConfigValue value;
    ConfigSource source;
    std::chrono::system_clock::time_point last_modified;
    std::string description;
    bool is_sensitive;  // Mask in logs
    bool is_readonly; // Cannot be overridden
};

// Configuration schema
struct ConfigSchema {
    std::string key_pattern;  // Regex pattern
    std::string type;         // "bool", "int", "float", "string", "list", "map"
    bool required;
    ConfigValue default_value;
    std::optional<ConfigValue> min_value;
    std::optional<ConfigValue> max_value;
    std::vector<std::string> allowed_values;  // For enums
    std::string description;
    std::string validation_regex;
};

// Environment configuration
struct EnvironmentConfig {
    std::string environment_id;
    std::string name;
    std::string description;
    
    // Inheritance
    std::string parent_environment;  // Inherit from parent
    
    // Settings
    std::unordered_map<std::string, ConfigEntry> settings;
    
    // Secrets reference
    std::vector<std::string> secret_keys;
    
    // Validation
    bool is_validated;
    std::vector<std::string> validation_errors;
};

// Secret reference
struct SecretReference {
    std::string key;
    std::string provider;  // "vault", "aws_secrets", "azure_keyvault", "file"
    std::string path;
    std::string version;   // Specific version, empty = latest
    std::chrono::seconds ttl;  // Cache TTL
};

// Configuration change
struct ConfigChange {
    std::string change_id;
    std::string key;
    ConfigValue old_value;
    ConfigValue new_value;
    std::string changed_by;
    std::chrono::system_clock::time_point changed_at;
    std::string reason;
    bool is_rolled_back;
};

// Feature flag
struct FeatureFlag {
    std::string flag_id;
    std::string name;
    std::string description;
    
    // State
    bool is_enabled;
    double rollout_percentage;  // 0-100
    
    // Targeting
    std::vector<std::string> target_users;
    std::vector<std::string> target_groups;
    std::unordered_map<std::string, std::string> target_attributes;
    
    // Scheduling
    std::optional<std::chrono::system_clock::time_point> enable_after;
    std::optional<std::chrono::system_clock::time_point> disable_after;
    
    // Dependencies
    std::vector<std::string> requires_flags;
    
    // Audit
    std::string created_by;
    std::chrono::system_clock::time_point created_at;
    std::string modified_by;
    std::chrono::system_clock::time_point modified_at;
};

// Configuration manager interface
class IConfigurationManager {
public:
    virtual ~IConfigurationManager() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Environment management
    virtual bool SetActiveEnvironment(const std::string& environment_id) = 0;
    virtual std::string GetActiveEnvironment() const = 0;
    virtual std::string CreateEnvironment(const EnvironmentConfig& config) = 0;
    virtual bool UpdateEnvironment(const EnvironmentConfig& config) = 0;
    virtual bool DeleteEnvironment(const std::string& environment_id) = 0;
    virtual std::optional<EnvironmentConfig> GetEnvironment(const std::string& environment_id) = 0;
    virtual std::vector<EnvironmentConfig> ListEnvironments() = 0;
    virtual bool ValidateEnvironment(const std::string& environment_id) = 0;
    
    // Configuration values
    virtual bool Set(const std::string& key, const ConfigValue& value, 
                      ConfigSource source = ConfigSource::OVERRIDDEN) = 0;
    virtual std::optional<ConfigValue> Get(const std::string& key) = 0;
    virtual bool Has(const std::string& key) = 0;
    virtual bool Remove(const std::string& key) = 0;
    virtual std::vector<std::string> GetAllKeys() = 0;
    
    // Typed getters
    virtual std::optional<bool> GetBool(const std::string& key) = 0;
    virtual std::optional<int64_t> GetInt(const std::string& key) = 0;
    virtual std::optional<double> GetFloat(const std::string& key) = 0;
    virtual std::optional<std::string> GetString(const std::string& key) = 0;
    virtual std::optional<std::vector<std::string>> GetList(const std::string& key) = 0;
    virtual std::optional<std::unordered_map<std::string, std::string>> GetMap(const std::string& key) = 0;
    
    // Configuration sources
    virtual bool LoadFromFile(const std::string& path, ConfigSource source = ConfigSource::FILE) = 0;
    virtual bool LoadFromEnvironment() = 0;
    virtual bool LoadFromCommandLine(int argc, char** argv) = 0;
    virtual bool LoadFromRemote(const std::string& url, const std::string& auth_token) = 0;
    
    // Schema validation
    virtual bool RegisterSchema(const ConfigSchema& schema) = 0;
    virtual bool ValidateAgainstSchema(std::vector<std::string>* errors = nullptr) = 0;
    virtual std::vector<ConfigSchema> GetSchema() = 0;
    
    // Secrets management
    virtual bool RegisterSecret(const SecretReference& secret) = 0;
    virtual std::optional<std::string> GetSecret(const std::string& key) = 0;
    virtual bool RotateSecret(const std::string& key) = 0;
    virtual bool ReloadSecrets() = 0;
    
    // Feature flags
    virtual std::string CreateFeatureFlag(const FeatureFlag& flag) = 0;
    virtual bool UpdateFeatureFlag(const FeatureFlag& flag) = 0;
    virtual bool DeleteFeatureFlag(const std::string& flag_id) = 0;
    virtual std::optional<FeatureFlag> GetFeatureFlag(const std::string& flag_id) = 0;
    virtual std::vector<FeatureFlag> ListFeatureFlags() = 0;
    virtual bool IsFeatureEnabled(const std::string& flag_id, 
                                   const std::unordered_map<std::string, std::string>& context = {}) = 0;
    virtual bool EnableFeature(const std::string& flag_id) = 0;
    virtual bool DisableFeature(const std::string& flag_id) = 0;
    virtual bool SetRolloutPercentage(const std::string& flag_id, double percentage) = 0;
    
    // Change tracking
    virtual std::vector<ConfigChange> GetChangeHistory(const std::string& key = "",
                                                          std::chrono::hours range = std::chrono::hours(24)) = 0;
    virtual bool RollbackChange(const std::string& change_id) = 0;
    
    // Import/Export
    virtual bool ExportToFile(const std::string& path, const std::string& format = "json") = 0;
    virtual bool ImportFromFile(const std::string& path, bool overwrite = false) = 0;
    
    // Hot reload
    virtual bool EnableHotReload(std::chrono::seconds interval = std::chrono::seconds(60)) = 0;
    virtual void DisableHotReload() = 0;
    virtual bool IsHotReloadEnabled() const = 0;
    
    // Notifications
    using ConfigChangeCallback = std::function<void(const std::string& key, 
                                                       const ConfigValue& old_value,
                                                       const ConfigValue& new_value)>;
    virtual void RegisterChangeCallback(const std::string& key_pattern, ConfigChangeCallback callback) = 0;
    virtual void UnregisterChangeCallback(const std::string& key_pattern) = 0;
    
    // Statistics
    virtual struct ConfigStatistics {
        uint32_t total_configurations;
        uint32_t environment_count;
        uint32_t feature_flag_count;
        uint32_t secret_count;
        uint64_t changes_24h;
        uint32_t hot_reload_count;
    } GetStatistics() = 0;
};

// Local configuration manager implementation
class LocalConfigurationManager : public IConfigurationManager {
public:
    LocalConfigurationManager();
    ~LocalConfigurationManager() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    bool SetActiveEnvironment(const std::string& environment_id) override;
    std::string GetActiveEnvironment() const override;
    std::string CreateEnvironment(const EnvironmentConfig& config) override;
    bool UpdateEnvironment(const EnvironmentConfig& config) override;
    bool DeleteEnvironment(const std::string& environment_id) override;
    std::optional<EnvironmentConfig> GetEnvironment(const std::string& environment_id) override;
    std::vector<EnvironmentConfig> ListEnvironments() override;
    bool ValidateEnvironment(const std::string& environment_id) override;
    
    bool Set(const std::string& key, const ConfigValue& value, 
              ConfigSource source = ConfigSource::OVERRIDDEN) override;
    std::optional<ConfigValue> Get(const std::string& key) override;
    bool Has(const std::string& key) override;
    bool Remove(const std::string& key) override;
    std::vector<std::string> GetAllKeys() override;
    
    std::optional<bool> GetBool(const std::string& key) override;
    std::optional<int64_t> GetInt(const std::string& key) override;
    std::optional<double> GetFloat(const std::string& key) override;
    std::optional<std::string> GetString(const std::string& key) override;
    std::optional<std::vector<std::string>> GetList(const std::string& key) override;
    std::optional<std::unordered_map<std::string, std::string>> GetMap(const std::string& key) override;
    
    bool LoadFromFile(const std::string& path, ConfigSource source = ConfigSource::FILE) override;
    bool LoadFromEnvironment() override;
    bool LoadFromCommandLine(int argc, char** argv) override;
    bool LoadFromRemote(const std::string& url, const std::string& auth_token) override;
    
    bool RegisterSchema(const ConfigSchema& schema) override;
    bool ValidateAgainstSchema(std::vector<std::string>* errors = nullptr) override;
    std::vector<ConfigSchema> GetSchema() override;
    
    bool RegisterSecret(const SecretReference& secret) override;
    std::optional<std::string> GetSecret(const std::string& key) override;
    bool RotateSecret(const std::string& key) override;
    bool ReloadSecrets() override;
    
    std::string CreateFeatureFlag(const FeatureFlag& flag) override;
    bool UpdateFeatureFlag(const FeatureFlag& flag) override;
    bool DeleteFeatureFlag(const std::string& flag_id) override;
    std::optional<FeatureFlag> GetFeatureFlag(const std::string& flag_id) override;
    std::vector<FeatureFlag> ListFeatureFlags() override;
    bool IsFeatureEnabled(const std::string& flag_id, 
                           const std::unordered_map<std::string, std::string>& context = {}) override;
    bool EnableFeature(const std::string& flag_id) override;
    bool DisableFeature(const std::string& flag_id) override;
    bool SetRolloutPercentage(const std::string& flag_id, double percentage) override;
    
    std::vector<ConfigChange> GetChangeHistory(const std::string& key = "",
                                                      std::chrono::hours range = std::chrono::hours(24)) override;
    bool RollbackChange(const std::string& change_id) override;
    
    bool ExportToFile(const std::string& path, const std::string& format = "json") override;
    bool ImportFromFile(const std::string& path, bool overwrite = false) override;
    
    bool EnableHotReload(std::chrono::seconds interval = std::chrono::seconds(60)) override;
    void DisableHotReload() override;
    bool IsHotReloadEnabled() const override;
    
    void RegisterChangeCallback(const std::string& key_pattern, ConfigChangeCallback callback) override;
    void UnregisterChangeCallback(const std::string& key_pattern) override;
    
    ConfigStatistics GetStatistics() override;
    
private:
    std::unordered_map<std::string, EnvironmentConfig> environments_;
    std::string active_environment_id_;
    std::unordered_map<std::string, ConfigEntry> config_;
    std::vector<ConfigSchema> schema_;
    std::unordered_map<std::string, SecretReference> secrets_;
    std::unordered_map<std::string, FeatureFlag> feature_flags_;
    std::vector<ConfigChange> change_history_;
    std::unordered_map<std::string, ConfigChangeCallback> callbacks_;
    bool initialized_ = false;
    bool hot_reload_enabled_ = false;
    
    void NotifyChange(const std::string& key, const ConfigValue& old_value, const ConfigValue& new_value);
    bool CheckFeatureTargeting(const FeatureFlag& flag, 
                                const std::unordered_map<std::string, std::string>& context);
    void HotReloadThread();
    std::string GenerateEnvironmentId();
    std::string GenerateFlagId();
    std::string GenerateChangeId();
};

// Global configuration manager
extern std::unique_ptr<IConfigurationManager> g_configuration_manager;

// Initialize configuration manager
bool InitializeConfigurationManager(const std::string& config_path);
void ShutdownConfigurationManager();
bool IsConfigurationManagerEnabled();

// Convenience template for getting config values
template<typename T>
std::optional<T> GetConfig(const std::string& key) {
    if (!g_configuration_manager) return std::nullopt;
    auto value = g_configuration_manager->Get(key);
    if (!value) return std::nullopt;
    if (std::holds_alternative<T>(*value)) {
        return std::get<T>(*value);
    }
    return std::nullopt;
}

} // namespace Operations
} // namespace RawrXD
