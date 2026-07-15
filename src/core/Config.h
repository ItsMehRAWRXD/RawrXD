/**
 * @file Config.h
 * @brief Production-grade configuration management
 * 
 * Provides environment-based configuration, feature flags, and
 * hot-reload support for the unified architecture.
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>
#include <fstream>

namespace RawrXD {
namespace Core {

// ============================================================================
// Config Value Types
// ============================================================================

// Forward declaration for recursive types
struct ConfigValue;

// Config value types - using unique_ptr for recursive containers
using ConfigValueBase = std::variant<
    std::monostate,  // null/empty
    bool,
    int64_t,
    double,
    std::string
>;

struct ConfigValue {
    ConfigValueBase base;
    std::unique_ptr<std::vector<ConfigValue>> array;
    std::unique_ptr<std::map<std::string, ConfigValue>> object;
    
    ConfigValue() = default;
    ConfigValue(std::nullptr_t) : base(std::monostate{}) {}
    ConfigValue(bool v) : base(v) {}
    ConfigValue(int v) : base(static_cast<int64_t>(v)) {}
    ConfigValue(int64_t v) : base(v) {}
    ConfigValue(double v) : base(v) {}
    ConfigValue(const std::string& v) : base(v) {}
    ConfigValue(std::string&& v) : base(std::move(v)) {}
    ConfigValue(const char* v) : base(std::string(v)) {}
    
    bool IsNull() const { return std::holds_alternative<std::monostate>(base); }
    bool IsBool() const { return std::holds_alternative<bool>(base); }
    bool IsInt() const { return std::holds_alternative<int64_t>(base); }
    bool IsDouble() const { return std::holds_alternative<double>(base); }
    bool IsString() const { return std::holds_alternative<std::string>(base); }
    bool IsArray() const { return array != nullptr; }
    bool IsObject() const { return object != nullptr; }
    
    bool AsBool() const { return std::get<bool>(base); }
    int64_t AsInt() const { return std::get<int64_t>(base); }
    double AsDouble() const { return std::get<double>(base); }
    const std::string& AsString() const { return std::get<std::string>(base); }
    const std::vector<ConfigValue>& AsArray() const { return *array; }
    const std::map<std::string, ConfigValue>& AsObject() const { return *object; }
};

// ============================================================================
// Config Source Interface
// ============================================================================

class ConfigSource {
public:
    virtual ~ConfigSource() = default;
    virtual std::unordered_map<std::string, ConfigValue> Load() = 0;
    virtual bool CanReload() const { return false; }
    virtual bool Reload() { return false; }
};

// ============================================================================
// Config
// ============================================================================

class Config {
public:
    using ChangeCallback = std::function<void(const std::string& key, const ConfigValue& oldValue, const ConfigValue& newValue)>;
    
    // Singleton access
    static Config& GetInstance();
    
    // Load from sources
    bool LoadFromFile(const std::string& path);
    bool LoadFromEnvironment(const std::string& prefix = "RAWRXD_");
    bool LoadFromArgs(int argc, char* argv[]);
    void AddSource(std::shared_ptr<ConfigSource> source);
    
    // Reload configuration
    bool Reload();
    
    // Get values with type safety
    template<typename T>
    std::optional<T> Get(const std::string& key) const {
        auto value = GetValue(key);
        if (!value) return std::nullopt;
        
        if constexpr (std::is_same_v<T, bool>) {
            if (std::holds_alternative<bool>(*value)) return std::get<bool>(*value);
        } else if constexpr (std::is_integral_v<T>) {
            if (std::holds_alternative<int64_t>(*value)) return static_cast<T>(std::get<int64_t>(*value));
        } else if constexpr (std::is_floating_point_v<T>) {
            if (std::holds_alternative<double>(*value)) return static_cast<T>(std::get<double>(*value));
        } else if constexpr (std::is_same_v<T, std::string>) {
            if (std::holds_alternative<std::string>(*value)) return std::get<std::string>(*value);
        }
        return std::nullopt;
    }
    
    template<typename T>
    T GetOrDefault(const std::string& key, const T& defaultValue) const {
        auto value = Get<T>(key);
        return value ? *value : defaultValue;
    }
    
    // Set values
    void Set(const std::string& key, const ConfigValue& value);
    void SetBool(const std::string& key, bool value);
    void SetInt(const std::string& key, int64_t value);
    void SetDouble(const std::string& key, double value);
    void SetString(const std::string& key, const std::string& value);
    
    // Check if key exists
    bool Has(const std::string& key) const;
    
    // Remove key
    void Remove(const std::string& key);
    
    // Get all keys
    std::vector<std::string> GetKeys() const;
    
    // Feature flags
    bool IsFeatureEnabled(const std::string& feature) const;
    void EnableFeature(const std::string& feature);
    void DisableFeature(const std::string& feature);
    void ToggleFeature(const std::string& feature);
    std::set<std::string> GetEnabledFeatures() const;
    
    // Watch for changes
    int Watch(const std::string& key, ChangeCallback callback);
    void Unwatch(int watchId);
    void Unwatch(const std::string& key);
    
    // Environment helpers
    static std::string GetEnv(const std::string& name, const std::string& defaultValue = "");
    static bool HasEnv(const std::string& name);
    
    // Export
    std::string ToJSON() const;
    bool SaveToFile(const std::string& path) const;
    
private:
    Config() = default;
    ~Config() = default;
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
    
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, ConfigValue> m_values;
    std::set<std::string> m_enabledFeatures;
    std::vector<std::shared_ptr<ConfigSource>> m_sources;
    
    struct WatchEntry {
        int id;
        std::string key;
        ChangeCallback callback;
    };
    int m_nextWatchId = 1;
    std::unordered_map<int, WatchEntry> m_watches;
    std::unordered_map<std::string, std::vector<int>> m_keyWatches;
    
    std::optional<ConfigValue> GetValue(const std::string& key) const;
    void NotifyWatchers(const std::string& key, const ConfigValue& oldValue, const ConfigValue& newValue);
    void ParseCommandLineArg(const std::string& arg);
};

// ============================================================================
// Feature Flag Helper
// ============================================================================

class FeatureFlag {
public:
    explicit FeatureFlag(const std::string& name);
    
    bool IsEnabled() const;
    void Enable();
    void Disable();
    void Toggle();
    
    operator bool() const { return IsEnabled(); }
    
private:
    std::string m_name;
};

// ============================================================================
// Scoped Config Override (for testing)
// ============================================================================

class ScopedConfigOverride {
public:
    template<typename T>
    ScopedConfigOverride(const std::string& key, const T& value) : m_key(key) {
        auto& config = Config::GetInstance();
        m_oldValue = config.GetValue(key);
        config.Set(key, value);
    }
    
    ~ScopedConfigOverride();
    
private:
    std::string m_key;
    std::optional<ConfigValue> m_oldValue;
};

} // namespace Core
} // namespace RawrXD
