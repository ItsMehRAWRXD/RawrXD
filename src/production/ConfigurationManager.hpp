// RawrXD Configuration Manager
// Phase R.3: Dynamic configuration with hot reload and validation
// Environment-aware configuration with secrets integration

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <variant>

namespace RawrXD {
namespace Production {

// Forward declarations
class SecretManager;
class AuditLogger;

// Configuration value types
using ConfigValue = std::variant<
    std::monostate,  // null/undefined
    bool,
    int64_t,
    double,
    std::string,
    std::vector<ConfigValue>,
    std::map<std::string, ConfigValue>
>;

// Configuration source
enum class ConfigSource {
    DEFAULT,        // Built-in defaults
    FILE,           // Configuration file
    ENVIRONMENT,    // Environment variables
    COMMAND_LINE,   // Command line arguments
    REMOTE,         // Remote configuration service
    SECRET          // Secret manager
};

// Configuration entry
struct ConfigEntry {
    std::string key;
    ConfigValue value;
    ConfigSource source;
    std::chrono::system_clock::time_point lastModified;
    std::string description;
    bool isSecret{false};
    bool isReadOnly{false};
};

// Configuration schema
struct ConfigSchema {
    std::string key;
    std::string type;  // "string", "int", "float", "bool", "array", "object"
    bool required{false};
    ConfigValue defaultValue;
    std::vector<std::string> allowedValues;  // For enums
    std::function<bool(const ConfigValue&)> validator;
    std::string description;
    bool isSecret{false};
    bool hotReloadable{true};
};

// Configuration change event
struct ConfigChangeEvent {
    std::string key;
    ConfigValue oldValue;
    ConfigValue newValue;
    ConfigSource source;
    std::chrono::system_clock::time_point timestamp;
    std::string changedBy;
};

// Configuration manager
class ConfigurationManager {
public:
    ConfigurationManager(SecretManager* secrets, AuditLogger* audit);
    ~ConfigurationManager();
    
    // Lifecycle
    bool initialize(const std::string& configPath);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Schema registration
    bool registerSchema(const ConfigSchema& schema);
    bool unregisterSchema(const std::string& key);
    ConfigSchema getSchema(const std::string& key) const;
    std::vector<ConfigSchema> getAllSchemas() const;
    
    // Value getters
    template<typename T>
    T get(const std::string& key, const T& defaultValue = T{}) const;
    
    ConfigValue getValue(const std::string& key) const;
    std::string getString(const std::string& key, const std::string& defaultValue = "") const;
    int64_t getInt(const std::string& key, int64_t defaultValue = 0) const;
    double getFloat(const std::string& key, double defaultValue = 0.0) const;
    bool getBool(const std::string& key, bool defaultValue = false) const;
    std::vector<ConfigValue> getArray(const std::string& key) const;
    std::map<std::string, ConfigValue> getObject(const std::string& key) const;
    
    // Value setters
    bool set(const std::string& key, const ConfigValue& value, ConfigSource source = ConfigSource::FILE);
    bool setString(const std::string& key, const std::string& value);
    bool setInt(const std::string& key, int64_t value);
    bool setFloat(const std::string& key, double value);
    bool setBool(const std::string& key, bool value);
    
    // Secret integration
    bool setSecret(const std::string& key, const std::string& secretPath);
    bool resolveSecrets();
    
    // Environment variable loading
    bool loadFromEnvironment(const std::string& prefix = "RAWRXD_");
    bool loadFromFile(const std::string& path);
    bool loadFromCommandLine(int argc, char* argv[]);
    
    // Validation
    bool validate() const;
    bool validateKey(const std::string& key) const;
    std::vector<std::string> getValidationErrors() const;
    
    // Hot reload
    bool enableHotReload(std::chrono::seconds interval = std::chrono::seconds(30));
    bool disableHotReload();
    bool isHotReloadEnabled() const { return hotReloadEnabled_; }
    void triggerReload();
    
    // Callbacks
    using ConfigChangeCallback = std::function<void(const ConfigChangeEvent&)>;
    void addChangeCallback(const std::string& key, ConfigChangeCallback callback);
    void removeChangeCallback(const std::string& key);
    void addGlobalChangeCallback(ConfigChangeCallback callback);
    
    // Export/Import
    std::string exportToJson() const;
    std::string exportToYaml() const;
    bool importFromJson(const std::string& json);
    bool importFromYaml(const std::string& yaml);
    
    // Configuration sections
    std::vector<std::string> getKeys(const std::string& prefix = "") const;
    std::map<std::string, ConfigValue> getSection(const std::string& prefix) const;
    bool hasKey(const std::string& key) const;
    
    // Defaults
    bool resetToDefaults();
    bool resetKeyToDefault(const std::string& key);
    
    // History
    std::vector<ConfigChangeEvent> getChangeHistory(const std::string& key, uint32_t limit = 100) const;
    
    // Environment profiles
    void setEnvironment(const std::string& env);  // "development", "staging", "production"
    std::string getEnvironment() const { return environment_; }
    bool loadProfile(const std::string& profileName);
    
private:
    void hotReloadLoop();
    void notifyChange(const ConfigChangeEvent& event);
    bool validateValue(const std::string& key, const ConfigValue& value) const;
    ConfigValue resolveValue(const ConfigValue& value) const;
    std::string expandVariables(const std::string& value) const;
    
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    std::atomic<bool> hotReloadEnabled_{false};
    std::thread reloadThread_;
    mutable std::mutex mutex_;
    
    SecretManager* secrets_;
    AuditLogger* audit_;
    
    std::string configPath_;
    std::string environment_{"development"};
    std::map<std::string, ConfigSchema> schemas_;
    std::map<std::string, ConfigEntry> config_;
    std::map<std::string, std::vector<ConfigChangeCallback>> callbacks_;
    std::vector<ConfigChangeCallback> globalCallbacks_;
    std::map<std::string, std::vector<ConfigChangeEvent>> history_;
    
    std::chrono::system_clock::time_point lastFileModified_;
};

// Feature flags
class FeatureFlags {
public:
    FeatureFlags(ConfigurationManager* config);
    
    // Flag management
    bool isEnabled(const std::string& flag) const;
    void enable(const std::string& flag);
    void disable(const std::string& flag);
    void toggle(const std::string& flag);
    
    // Gradual rollout
    bool isEnabledFor(const std::string& flag, const std::string& entity) const;
    void setRolloutPercentage(const std::string& flag, uint32_t percentage);
    
    // A/B testing
    std::string getVariant(const std::string& experiment, const std::string& userId) const;
    void configureExperiment(const std::string& experiment, 
                            const std::vector<std::string>& variants,
                            const std::map<std::string, uint32_t>& weights);
    
    // Bulk operations
    std::map<std::string, bool> getAllFlags() const;
    void bulkUpdate(const std::map<std::string, bool>& flags);
    
private:
    ConfigurationManager* config_;
};

// Configuration templates
class ConfigTemplates {
public:
    // Template loading
    bool loadTemplate(const std::string& name, const std::string& path);
    bool unloadTemplate(const std::string& name);
    
    // Template application
    bool applyTemplate(const std::string& name, ConfigurationManager* config);
    
    // Variable substitution
    static std::string substitute(const std::string& templateStr,
                                  const std::map<std::string, std::string>& variables);
    
private:
    std::map<std::string, std::string> templates_;
};

} // namespace Production
} // namespace RawrXD
