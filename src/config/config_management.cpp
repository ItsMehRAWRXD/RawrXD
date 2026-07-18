// RawrXD Configuration Management
// Phase 9 - Task 20: Configuration Management

#include <windows.h>
#include <cstring>
#include <string>
#include <map>
#include <vector>
#include <mutex>
#include <fstream>
#include <sstream>
#include <functional>
#include <chrono>

// Configuration value types
enum ConfigValueType {
    CONFIG_STRING,
    CONFIG_INT,
    CONFIG_BOOL,
    CONFIG_DOUBLE,
    CONFIG_ARRAY,
    CONFIG_OBJECT
};

// Configuration value
struct ConfigValue {
    ConfigValueType type;
    std::string stringValue;
    int intValue;
    bool boolValue;
    double doubleValue;
    std::vector<ConfigValue> arrayValue;
    std::map<std::string, ConfigValue> objectValue;
};

// Feature flag
struct FeatureFlag {
    std::string name;
    bool enabled;
    std::string description;
    std::chrono::system_clock::time_point createdAt;
    std::map<std::string, std::string> metadata;
};

// Configuration change callback
using ConfigChangeCallback = std::function<void(const std::string& key, const ConfigValue& oldValue, const ConfigValue& newValue)>;

// Configuration manager
class ConfigManager {
private:
    std::map<std::string, ConfigValue> config;
    std::map<std::string, FeatureFlag> featureFlags;
    std::map<std::string, std::vector<ConfigChangeCallback>> callbacks;
    std::mutex configMutex;
    std::string configFilePath;
    std::atomic<bool> hotReloadEnabled;
    std::thread reloadThread;
    FILETIME lastWriteTime;
    
public:
    ConfigManager() : hotReloadEnabled(false) {}
    
    ~ConfigManager() {
        Shutdown();
    }
    
    bool Initialize(const std::string& configPath) {
        configFilePath = configPath;
        
        // Load initial configuration
        if (!configPath.empty()) {
            LoadFromFile(configPath);
        }
        
        // Load environment variables
        LoadFromEnvironment();
        
        // Set defaults
        SetDefaults();
        
        printf("Configuration manager initialized\n");
        printf("  Config file: %s\n", configPath.c_str());
        printf("  Hot reload: %s\n", hotReloadEnabled ? "enabled" : "disabled");
        
        return true;
    }
    
    // Set default configuration values
    void SetDefaults() {
        SetString("server.host", "0.0.0.0");
        SetInt("server.port", 8080);
        SetInt("server.threads", 4);
        SetBool("server.ssl.enabled", false);
        
        SetString("model.path", "models/");
        SetInt("model.max_tokens", 2048);
        SetDouble("model.temperature", 0.7);
        SetDouble("model.top_p", 0.9);
        
        SetString("logging.level", "info");
        SetString("logging.format", "json");
        SetString("logging.output", "logs/rawrxd.log");
        
        SetString("metrics.endpoint", "/metrics");
        SetInt("metrics.port", 9090);
        
        SetString("tracing.endpoint", "http://localhost:4317");
        SetDouble("tracing.sampling_rate", 0.1);
        
        SetInt("cache.max_size_mb", 1024);
        SetInt("cache.ttl_seconds", 3600);
        
        SetInt("rate_limit.requests_per_minute", 60);
        SetInt("rate_limit.burst_size", 10);
    }
    
    // Load configuration from file
    bool LoadFromFile(const std::string& path) {
        std::ifstream file(path);
        if (!file.is_open()) {
            printf("Config file not found: %s\n", path.c_str());
            return false;
        }
        
        std::string line;
        while (std::getline(file, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#') continue;
            
            // Parse key=value
            size_t pos = line.find('=');
            if (pos == std::string::npos) continue;
            
            std::string key = Trim(line.substr(0, pos));
            std::string value = Trim(line.substr(pos + 1));
            
            // Remove quotes if present
            if (value.length() >= 2 && value[0] == '"' && value[value.length() - 1] == '"') {
                value = value.substr(1, value.length() - 2);
            }
            
            ParseAndSet(key, value);
        }
        
        // Get file modification time
        WIN32_FILE_ATTRIBUTE_DATA attrData;
        if (GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &attrData)) {
            lastWriteTime = attrData.ftLastWriteTime;
        }
        
        printf("Loaded configuration from %s\n", path.c_str());
        return true;
    }
    
    // Load configuration from environment variables
    void LoadFromEnvironment() {
        // Common environment variables
        const char* envVars[] = {
            "RAWRXD_SERVER_HOST",
            "RAWRXD_SERVER_PORT",
            "RAWRXD_MODEL_PATH",
            "RAWRXD_LOG_LEVEL",
            "RAWRXD_METRICS_PORT",
            "RAWRXD_TRACING_ENDPOINT",
            "RAWRXD_CACHE_SIZE_MB",
            "RAWRXD_RATE_LIMIT_RPM",
            nullptr
        };
        
        for (int i = 0; envVars[i] != nullptr; i++) {
            const char* value = getenv(envVars[i]);
            if (value) {
                std::string key = envVars[i];
                // Convert RAWRXD_SERVER_HOST to server.host
                key = key.substr(7); // Remove RAWRXD_
                std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                std::replace(key.begin(), key.end(), '_', '.');
                
                ParseAndSet(key, value);
                printf("Loaded from env: %s=%s\n", key.c_str(), value);
            }
        }
    }
    
    // Enable hot reload
    void EnableHotReload() {
        hotReloadEnabled = true;
        reloadThread = std::thread(&ConfigManager::ReloadLoop, this);
        printf("Hot reload enabled\n");
    }
    
    // Get string value
    std::string GetString(const std::string& key, const std::string& defaultValue = "") {
        std::lock_guard<std::mutex> lock(configMutex);
        
        auto it = config.find(key);
        if (it != config.end() && it->second.type == CONFIG_STRING) {
            return it->second.stringValue;
        }
        return defaultValue;
    }
    
    // Get int value
    int GetInt(const std::string& key, int defaultValue = 0) {
        std::lock_guard<std::mutex> lock(configMutex);
        
        auto it = config.find(key);
        if (it != config.end() && it->second.type == CONFIG_INT) {
            return it->second.intValue;
        }
        return defaultValue;
    }
    
    // Get bool value
    bool GetBool(const std::string& key, bool defaultValue = false) {
        std::lock_guard<std::mutex> lock(configMutex);
        
        auto it = config.find(key);
        if (it != config.end() && it->second.type == CONFIG_BOOL) {
            return it->second.boolValue;
        }
        return defaultValue;
    }
    
    // Get double value
    double GetDouble(const std::string& key, double defaultValue = 0.0) {
        std::lock_guard<std::mutex> lock(configMutex);
        
        auto it = config.find(key);
        if (it != config.end() && it->second.type == CONFIG_DOUBLE) {
            return it->second.doubleValue;
        }
        return defaultValue;
    }
    
    // Set string value
    void SetString(const std::string& key, const std::string& value) {
        ConfigValue newValue;
        newValue.type = CONFIG_STRING;
        newValue.stringValue = value;
        SetValue(key, newValue);
    }
    
    // Set int value
    void SetInt(const std::string& key, int value) {
        ConfigValue newValue;
        newValue.type = CONFIG_INT;
        newValue.intValue = value;
        SetValue(key, newValue);
    }
    
    // Set bool value
    void SetBool(const std::string& key, bool value) {
        ConfigValue newValue;
        newValue.type = CONFIG_BOOL;
        newValue.boolValue = value;
        SetValue(key, newValue);
    }
    
    // Set double value
    void SetDouble(const std::string& key, double value) {
        ConfigValue newValue;
        newValue.type = CONFIG_DOUBLE;
        newValue.doubleValue = value;
        SetValue(key, newValue);
    }
    
    // Register feature flag
    void RegisterFeatureFlag(const std::string& name, bool defaultEnabled, const std::string& description) {
        std::lock_guard<std::mutex> lock(configMutex);
        
        FeatureFlag flag;
        flag.name = name;
        flag.enabled = defaultEnabled;
        flag.description = description;
        flag.createdAt = std::chrono::system_clock::now();
        
        featureFlags[name] = flag;
    }
    
    // Check if feature is enabled
    bool IsFeatureEnabled(const std::string& name) {
        std::lock_guard<std::mutex> lock(configMutex);
        
        auto it = featureFlags.find(name);
        if (it != featureFlags.end()) {
            return it->second.enabled;
        }
        return false;
    }
    
    // Enable/disable feature flag
    void SetFeatureEnabled(const std::string& name, bool enabled) {
        std::lock_guard<std::mutex> lock(configMutex);
        
        auto it = featureFlags.find(name);
        if (it != featureFlags.end()) {
            it->second.enabled = enabled;
            printf("Feature flag '%s' %s\n", name.c_str(), enabled ? "enabled" : "disabled");
        }
    }
    
    // Register change callback
    void OnChange(const std::string& key, ConfigChangeCallback callback) {
        std::lock_guard<std::mutex> lock(configMutex);
        callbacks[key].push_back(callback);
    }
    
    // Validate configuration
    bool Validate() {
        std::lock_guard<std::mutex> lock(configMutex);
        
        bool valid = true;
        
        // Validate required fields
        std::vector<std::string> required = {
            "server.host",
            "server.port",
            "model.path"
        };
        
        for (const auto& key : required) {
            if (config.find(key) == config.end()) {
                printf("Missing required config: %s\n", key.c_str());
                valid = false;
            }
        }
        
        // Validate ranges
        int port = GetInt("server.port");
        if (port < 1 || port > 65535) {
            printf("Invalid server.port: %d (must be 1-65535)\n", port);
            valid = false;
        }
        
        double temp = GetDouble("model.temperature");
        if (temp < 0.0 || temp > 2.0) {
            printf("Invalid model.temperature: %.2f (must be 0.0-2.0)\n", temp);
            valid = false;
        }
        
        return valid;
    }
    
    // Save configuration to file
    bool SaveToFile(const std::string& path) {
        std::lock_guard<std::mutex> lock(configMutex);
        
        std::ofstream file(path);
        if (!file.is_open()) {
            return false;
        }
        
        file << "# RawrXD Configuration\n";
        file << "# Generated: " << GetTimestamp() << "\n\n";
        
        for (const auto& pair : config) {
            file << pair.first << "=";
            
            switch (pair.second.type) {
                case CONFIG_STRING:
                    file << "\"" << pair.second.stringValue << "\"";
                    break;
                case CONFIG_INT:
                    file << pair.second.intValue;
                    break;
                case CONFIG_BOOL:
                    file << (pair.second.boolValue ? "true" : "false");
                    break;
                case CONFIG_DOUBLE:
                    file << pair.second.doubleValue;
                    break;
                default:
                    break;
            }
            
            file << "\n";
        }
        
        return true;
    }
    
    // Get all configuration as string
    std::string Dump() {
        std::lock_guard<std::mutex> lock(configMutex);
        
        std::stringstream ss;
        ss << "Configuration:\n";
        
        for (const auto& pair : config) {
            ss << "  " << pair.first << "=";
            
            switch (pair.second.type) {
                case CONFIG_STRING:
                    ss << pair.second.stringValue;
                    break;
                case CONFIG_INT:
                    ss << pair.second.intValue;
                    break;
                case CONFIG_BOOL:
                    ss << (pair.second.boolValue ? "true" : "false");
                    break;
                case CONFIG_DOUBLE:
                    ss << pair.second.doubleValue;
                    break;
                default:
                    break;
            }
            
            ss << "\n";
        }
        
        return ss.str();
    }
    
    void Shutdown() {
        hotReloadEnabled = false;
        
        if (reloadThread.joinable()) {
            reloadThread.join();
        }
    }
    
private:
    void SetValue(const std::string& key, const ConfigValue& newValue) {
        std::lock_guard<std::mutex> lock(configMutex);
        
        ConfigValue oldValue;
        auto it = config.find(key);
        if (it != config.end()) {
            oldValue = it->second;
        }
        
        config[key] = newValue;
        
        // Notify callbacks
        auto cbIt = callbacks.find(key);
        if (cbIt != callbacks.end()) {
            for (auto& callback : cbIt->second) {
                callback(key, oldValue, newValue);
            }
        }
    }
    
    void ParseAndSet(const std::string& key, const std::string& value) {
        // Try to parse as bool
        if (value == "true" || value == "True" || value == "TRUE") {
            SetBool(key, true);
            return;
        }
        if (value == "false" || value == "False" || value == "FALSE") {
            SetBool(key, false);
            return;
        }
        
        // Try to parse as int
        char* end;
        long intVal = strtol(value.c_str(), &end, 10);
        if (*end == '\0') {
            SetInt(key, (int)intVal);
            return;
        }
        
        // Try to parse as double
        double doubleVal = strtod(value.c_str(), &end);
        if (*end == '\0') {
            SetDouble(key, doubleVal);
            return;
        }
        
        // Default to string
        SetString(key, value);
    }
    
    std::string Trim(const std::string& str) {
        size_t start = str.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        
        size_t end = str.find_last_not_of(" \t\r\n");
        return str.substr(start, end - start + 1);
    }
    
    std::string GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        
        char buffer[26];
        ctime_s(buffer, sizeof(buffer), &time);
        buffer[24] = '\0'; // Remove newline
        
        return std::string(buffer);
    }
    
    void ReloadLoop() {
        while (hotReloadEnabled) {
            Sleep(5000); // Check every 5 seconds
            
            if (configFilePath.empty()) continue;
            
            // Check if file has been modified
            WIN32_FILE_ATTRIBUTE_DATA attrData;
            if (GetFileAttributesExA(configFilePath.c_str(), GetFileExInfoStandard, &attrData)) {
                if (CompareFileTime(&lastWriteTime, &attrData.ftLastWriteTime) != 0) {
                    printf("Config file changed, reloading...\n");
                    LoadFromFile(configFilePath);
                    lastWriteTime = attrData.ftLastWriteTime;
                }
            }
        }
    }
};

// Global instance
static ConfigManager g_ConfigManager;

// C API
extern "C" {

bool Config_Init(const char* configPath) {
    return g_ConfigManager.Initialize(configPath);
}

const char* Config_GetString(const char* key, const char* defaultValue) {
    static std::string value;
    value = g_ConfigManager.GetString(key, defaultValue);
    return value.c_str();
}

int Config_GetInt(const char* key, int defaultValue) {
    return g_ConfigManager.GetInt(key, defaultValue);
}

int Config_GetBool(const char* key, int defaultValue) {
    return g_ConfigManager.GetBool(key, defaultValue != 0) ? 1 : 0;
}

double Config_GetDouble(const char* key, double defaultValue) {
    return g_ConfigManager.GetDouble(key, defaultValue);
}

void Config_SetString(const char* key, const char* value) {
    g_ConfigManager.SetString(key, value);
}

void Config_SetInt(const char* key, int value) {
    g_ConfigManager.SetInt(key, value);
}

void Config_SetBool(const char* key, int value) {
    g_ConfigManager.SetBool(key, value != 0);
}

void Config_SetDouble(const char* key, double value) {
    g_ConfigManager.SetDouble(key, value);
}

void Config_EnableHotReload() {
    g_ConfigManager.EnableHotReload();
}

void Config_RegisterFeatureFlag(const char* name, int defaultEnabled, const char* description) {
    g_ConfigManager.RegisterFeatureFlag(name, defaultEnabled != 0, description);
}

int Config_IsFeatureEnabled(const char* name) {
    return g_ConfigManager.IsFeatureEnabled(name) ? 1 : 0;
}

void Config_SetFeatureEnabled(const char* name, int enabled) {
    g_ConfigManager.SetFeatureEnabled(name, enabled != 0);
}

int Config_Validate() {
    return g_ConfigManager.Validate() ? 1 : 0;
}

int Config_Save(const char* path) {
    return g_ConfigManager.SaveToFile(path) ? 1 : 0;
}

const char* Config_Dump() {
    static std::string dump;
    dump = g_ConfigManager.Dump();
    return dump.c_str();
}

void Config_Shutdown() {
    g_ConfigManager.Shutdown();
}

} // extern "C"
