#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <variant>
#include <functional>
#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Core {

using json = nlohmann::json;

// Forward declarations
class ConfigValidator;
class ConfigWatcher;

// Configuration value types
using ConfigValue = std::variant<
    std::nullptr_t,
    bool,
    int64_t,
    double,
    std::string,
    std::vector<ConfigValue>,
    std::map<std::string, ConfigValue>
>;

// Configuration change event
struct ConfigChangeEvent {
    std::string path;
    ConfigValue oldValue;
    ConfigValue newValue;
    std::chrono::system_clock::time_point timestamp;
};

// Configuration source
enum class ConfigSource {
    Default,
    File,
    Environment,
    CommandLine,
    Runtime,
    Remote
};

// Configuration entry with metadata
struct ConfigEntry {
    ConfigValue value;
    ConfigSource source;
    std::string description;
    bool isSecret;
    std::vector<std::string> tags;
};

// Configuration manager class
class ConfigManager {
public:
    ConfigManager();
    ~ConfigManager();

    // Delete copy/move
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    ConfigManager(ConfigManager&&) = delete;
    ConfigManager& operator=(ConfigManager&&) = delete;

    // Initialization
    bool Initialize(const std::string& configPath = "");
    bool InitializeFromJson(const json& config);
    void Shutdown();

    // Load/Save
    bool LoadFromFile(const std::string& path);
    bool LoadFromEnvironment();
    bool LoadFromCommandLine(int argc, char** argv);
    bool SaveToFile(const std::string& path) const;

    // Value getters
    template<typename T>
    std::optional<T> Get(const std::string& path) const;
    
    template<typename T>
    T GetOrDefault(const std::string& path, const T& defaultValue) const;
    
    template<typename T>
    T GetRequired(const std::string& path) const;

    // Value setters
    template<typename T>
    void Set(const std::string& path, const T& value, 
             ConfigSource source = ConfigSource::Runtime,
             const std::string& description = "");

    // Check existence
    bool Has(const std::string& path) const;
    bool HasValue(const std::string& path) const;

    // Remove values
    bool Remove(const std::string& path);
    void Clear();

    // Path operations
    std::vector<std::string> GetKeys(const std::string& path = "") const;
    std::vector<std::string> GetPaths() const;
    
    // Schema validation
    bool ValidateAgainstSchema(const std::string& schemaPath);
    bool ValidateAgainstSchemaJson(const json& schema);
    std::vector<std::string> GetValidationErrors() const;

    // Change notifications
    using ChangeCallback = std::function<void(const ConfigChangeEvent&)>;
    int SubscribeToChanges(const std::string& pathPattern, ChangeCallback callback);
    void UnsubscribeFromChanges(int subscriptionId);

    // File watching
    bool StartFileWatcher(const std::string& path);
    void StopFileWatcher();
    bool IsFileWatcherRunning() const;

    // Environment variable integration
    void SetEnvironmentPrefix(const std::string& prefix);
    void RegisterEnvironmentMapping(const std::string& envVar, const std::string& configPath);

    // Secrets management
    void MarkAsSecret(const std::string& path);
    void UnmarkAsSecret(const std::string& path);
    bool IsSecret(const std::string& path) const;
    std::string MaskSecrets(const std::string& text) const;

    // Import/Export
    json ExportToJson(bool includeSecrets = false) const;
    bool ImportFromJson(const json& config, ConfigSource source = ConfigSource::Runtime);
    bool MergeFromJson(const json& config, ConfigSource source = ConfigSource::Runtime);

    // Section management
    std::shared_ptr<ConfigManager> GetSection(const std::string& path) const;
    void SetSection(const std::string& path, const ConfigManager& section);

    // Reload
    bool Reload();
    bool ReloadIfChanged();

    // Statistics
    struct Statistics {
        size_t totalEntries;
        size_t secretEntries;
        size_t fileWatchers;
        size_t changeSubscribers;
        std::chrono::system_clock::time_point lastReload;
    };
    Statistics GetStatistics() const;

    // Static helpers
    static ConfigValue JsonToConfigValue(const json& j);
    static json ConfigValueToJson(const ConfigValue& value);
    static std::string ConfigValueToString(const ConfigValue& value);
    static ConfigValue StringToConfigValue(const std::string& str, const std::string& type = "auto");

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Template implementations

template<typename T>
std::optional<T> ConfigManager::Get(const std::string& path) const {
    auto value = Get<ConfigValue>(path);
    if (!value) return std::nullopt;
    
    try {
        return std::get<T>(*value);
    } catch (const std::bad_variant_access&) {
        return std::nullopt;
    }
}

template<typename T>
T ConfigManager::GetOrDefault(const std::string& path, const T& defaultValue) const {
    auto value = Get<T>(path);
    return value.value_or(defaultValue);
}

template<typename T>
T ConfigManager::GetRequired(const std::string& path) const {
    auto value = Get<T>(path);
    if (!value) {
        throw std::runtime_error("Required configuration value not found: " + path);
    }
    return *value;
}

template<typename T>
void ConfigManager::Set(const std::string& path, const T& value, 
                        ConfigSource source, const std::string& description) {
    Set(path, ConfigValue(value), source, description);
}

// Specialized template for setting ConfigValue directly
template<>
void ConfigManager::Set<ConfigValue>(const std::string& path, const ConfigValue& value,
                                     ConfigSource source, const std::string& description);

// Configuration builder for fluent API
class ConfigBuilder {
public:
    ConfigBuilder();
    
    ConfigBuilder& WithDefault(const std::string& path, const ConfigValue& value);
    ConfigBuilder& WithDefaults(const std::map<std::string, ConfigValue>& defaults);
    ConfigBuilder& WithFile(const std::string& path);
    ConfigBuilder& WithEnvironment(const std::string& prefix = "RAWRXD_");
    ConfigBuilder& WithCommandLine(int argc, char** argv);
    ConfigBuilder& WithSchema(const std::string& schemaPath);
    ConfigBuilder& WithValidation(bool strict = true);
    ConfigBuilder& WithFileWatching(bool enable = true);
    
    std::unique_ptr<ConfigManager> Build() const;
    
private:
    struct Config {
        std::map<std::string, ConfigValue> defaults;
        std::vector<std::string> files;
        std::string envPrefix;
        int argc = 0;
        char** argv = nullptr;
        std::string schemaPath;
        bool strictValidation = true;
        bool enableFileWatching = true;
    };
    
    std::unique_ptr<Config> config_;
};

// Global configuration accessor
ConfigManager& GetGlobalConfig();
void SetGlobalConfig(std::unique_ptr<ConfigManager> config);
void ResetGlobalConfig();

// Convenience functions
template<typename T>
inline std::optional<T> Config(const std::string& path) {
    return GetGlobalConfig().Get<T>(path);
}

template<typename T>
inline T ConfigOrDefault(const std::string& path, const T& defaultValue) {
    return GetGlobalConfig().GetOrDefault<T>(path, defaultValue);
}

template<typename T>
inline void SetConfig(const std::string& path, const T& value) {
    GetGlobalConfig().Set<T>(path, value);
}

} // namespace Core
} // namespace RawrXD
