#include "config_manager.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <regex>
#include <filesystem>

namespace RawrXD {
namespace Core {

namespace fs = std::filesystem;

// Implementation class
class ConfigManager::Impl {
public:
    mutable std::mutex mutex_;
    std::map<std::string, ConfigEntry> entries_;
    std::string configFilePath_;
    std::string envPrefix_ = "RAWRXD_";
    std::map<std::string, std::string> envMappings_;
    std::map<int, std::pair<std::regex, ConfigManager::ChangeCallback>> subscribers_;
    int nextSubscriptionId_ = 1;
    std::unique_ptr<ConfigWatcher> fileWatcher_;
    std::vector<std::string> validationErrors_;
    std::chrono::system_clock::time_point lastReload_;
    bool initialized_ = false;

    ConfigValue GetValue(const std::string& path) const {
        auto it = entries_.find(path);
        if (it != entries_.end()) {
            return it->second.value;
        }
        
        // Try to find as section prefix
        std::map<std::string, ConfigValue> section;
        for (const auto& [key, entry] : entries_) {
            if (key.rfind(path + ".", 0) == 0) {
                std::string subPath = key.substr(path.length() + 1);
                section[subPath] = entry.value;
            }
        }
        
        if (!section.empty()) {
            return ConfigValue(section);
        }
        
        return nullptr;
    }

    void SetValue(const std::string& path, const ConfigValue& value, 
                  ConfigSource source, const std::string& description) {
        ConfigChangeEvent event;
        event.path = path;
        event.oldValue = GetValue(path);
        event.newValue = value;
        event.timestamp = std::chrono::system_clock::now();
        
        ConfigEntry entry;
        entry.value = value;
        entry.source = source;
        entry.description = description;
        entry.isSecret = false;
        
        entries_[path] = entry;
        
        // Notify subscribers
        for (const auto& [id, sub] : subscribers_) {
            const auto& pattern = sub.first;
            const auto& callback = sub.second;
            
            if (std::regex_match(path, pattern)) {
                try {
                    callback(event);
                } catch (...) {
                    // Ignore callback exceptions
                }
            }
        }
    }

    std::vector<std::string> GetAllPaths() const {
        std::vector<std::string> paths;
        for (const auto& [key, _] : entries_) {
            paths.push_back(key);
        }
        return paths;
    }

    void ClearValues() {
        entries_.clear();
    }

    bool RemoveValue(const std::string& path) {
        // Remove exact match
        auto it = entries_.find(path);
        if (it != entries_.end()) {
            entries_.erase(it);
            return true;
        }
        
        // Remove all entries with this prefix
        bool removed = false;
        for (auto iter = entries_.begin(); iter != entries_.end();) {
            if (iter->first.rfind(path + ".", 0) == 0) {
                iter = entries_.erase(iter);
                removed = true;
            } else {
                ++iter;
            }
        }
        
        return removed;
    }
};

// ConfigManager implementation
ConfigManager::ConfigManager() : pImpl(std::make_unique<Impl>()) {}

ConfigManager::~ConfigManager() = default;

bool ConfigManager::Initialize(const std::string& configPath) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    if (pImpl->initialized_) {
        return true;
    }
    
    // Set default values
    SetDefaultValues();
    
    // Load from file if provided
    if (!configPath.empty()) {
        if (!LoadFromFile(configPath)) {
            return false;
        }
    }
    
    // Load from environment
    LoadFromEnvironment();
    
    pImpl->initialized_ = true;
    return true;
}

bool ConfigManager::InitializeFromJson(const json& config) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    if (pImpl->initialized_) {
        return true;
    }
    
    SetDefaultValues();
    
    if (!ImportFromJson(config, ConfigSource::File)) {
        return false;
    }
    
    pImpl->initialized_ = true;
    return true;
}

void ConfigManager::Shutdown() {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    StopFileWatcher();
    pImpl->ClearValues();
    pImpl->subscribers_.clear();
    pImpl->initialized_ = false;
}

void ConfigManager::SetDefaultValues() {
    // Server defaults
    pImpl->SetValue("server.host", "127.0.0.1", ConfigSource::Default, "Server bind address");
    pImpl->SetValue("server.port", 8080, ConfigSource::Default, "Server port");
    pImpl->SetValue("server.workers", 4, ConfigSource::Default, "Number of worker threads");
    pImpl->SetValue("server.timeout", 300, ConfigSource::Default, "Request timeout in seconds");
    
    // Inference defaults
    pImpl->SetValue("inference.max_context_length", 8192, ConfigSource::Default, "Maximum context length");
    pImpl->SetValue("inference.batch_size", 1, ConfigSource::Default, "Inference batch size");
    pImpl->SetValue("inference.temperature", 0.7, ConfigSource::Default, "Sampling temperature");
    pImpl->SetValue("inference.top_p", 0.9, ConfigSource::Default, "Nucleus sampling parameter");
    pImpl->SetValue("inference.top_k", 40, ConfigSource::Default, "Top-k sampling parameter");
    pImpl->SetValue("inference.repeat_penalty", 1.1, ConfigSource::Default, "Repetition penalty");
    
    // Hardware defaults
    pImpl->SetValue("hardware.gpu_acceleration", true, ConfigSource::Default, "Enable GPU acceleration");
    pImpl->SetValue("hardware.gpu_layers", 0, ConfigSource::Default, "Number of GPU layers (0 = auto)");
    pImpl->SetValue("hardware.cpu_threads", 0, ConfigSource::Default, "CPU threads (0 = auto)");
    pImpl->SetValue("hardware.use_mmap", true, ConfigSource::Default, "Use memory-mapped files");
    pImpl->SetValue("hardware.use_mlock", false, ConfigSource::Default, "Lock memory pages");
    
    // Logging defaults
    pImpl->SetValue("logging.level", "info", ConfigSource::Default, "Log level");
    pImpl->SetValue("logging.console", true, ConfigSource::Default, "Enable console logging");
    pImpl->SetValue("logging.max_size_mb", 100, ConfigSource::Default, "Max log file size");
    pImpl->SetValue("logging.max_files", 5, ConfigSource::Default, "Max log files to keep");
    
    // Security defaults
    pImpl->SetValue("security.enable_auth", false, ConfigSource::Default, "Enable authentication");
    pImpl->SetValue("security.rate_limit.requests_per_minute", 60, ConfigSource::Default, "Rate limit");
    pImpl->SetValue("security.rate_limit.burst_size", 10, ConfigSource::Default, "Burst size");
    
    // Model defaults
    pImpl->SetValue("models.directory", "./models", ConfigSource::Default, "Model directory");
    pImpl->SetValue("models.cache_size_mb", 4096, ConfigSource::Default, "Model cache size");
    pImpl->SetValue("models.auto_load", false, ConfigSource::Default, "Auto-load models");
}

bool ConfigManager::LoadFromFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    try {
        std::ifstream file(path);
        if (!file.is_open()) {
            return false;
        }
        
        json j;
        file >> j;
        
        pImpl->configFilePath_ = path;
        return ImportFromJson(j, ConfigSource::File);
    } catch (const std::exception& e) {
        pImpl->validationErrors_.push_back(std::string("Failed to load config file: ") + e.what());
        return false;
    }
}

bool ConfigManager::LoadFromEnvironment() {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    bool loaded = false;
    
    // Check mapped environment variables
    for (const auto& [envVar, configPath] : pImpl->envMappings_) {
        const char* value = std::getenv(envVar.c_str());
        if (value) {
            pImpl->SetValue(configPath, ConfigValue(std::string(value)), 
                           ConfigSource::Environment, "From environment variable: " + envVar);
            loaded = true;
        }
    }
    
    // Check prefixed environment variables
    if (!pImpl->envPrefix_.empty()) {
        for (char** env = environ; *env != nullptr; ++env) {
            std::string envStr(*env);
            size_t pos = envStr.find('=');
            if (pos == std::string::npos) continue;
            
            std::string name = envStr.substr(0, pos);
            std::string value = envStr.substr(pos + 1);
            
            if (name.rfind(pImpl->envPrefix_, 0) == 0) {
                std::string configPath = name.substr(pImpl->envPrefix_.length());
                // Convert RAWRXD_SERVER_PORT to server.port
                std::replace(configPath.begin(), configPath.end(), '_', '.');
                std::transform(configPath.begin(), configPath.end(), configPath.begin(), ::tolower);
                
                pImpl->SetValue(configPath, StringToConfigValue(value), 
                               ConfigSource::Environment, "From environment: " + name);
                loaded = true;
            }
        }
    }
    
    return loaded;
}

bool ConfigManager::LoadFromCommandLine(int argc, char** argv) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    bool loaded = false;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        
        // Handle --key=value or --key value
        if (arg.rfind("--", 0) == 0) {
            std::string key = arg.substr(2);
            std::string value;
            
            size_t eqPos = key.find('=');
            if (eqPos != std::string::npos) {
                value = key.substr(eqPos + 1);
                key = key.substr(0, eqPos);
            } else if (i + 1 < argc) {
                value = argv[++i];
            }
            
            // Convert --server-port to server.port
            std::replace(key.begin(), key.end(), '-', '.');
            
            pImpl->SetValue(key, StringToConfigValue(value), 
                           ConfigSource::CommandLine, "From command line");
            loaded = true;
        }
        
        // Handle -c config.json
        if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                LoadFromFile(argv[++i]);
            }
        }
    }
    
    return loaded;
}

bool ConfigManager::SaveToFile(const std::string& path) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    try {
        json j = ExportToJson(false);
        
        std::ofstream file(path);
        if (!file.is_open()) {
            return false;
        }
        
        file << j.dump(2);
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

bool ConfigManager::Has(const std::string& path) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->entries_.find(path) != pImpl->entries_.end();
}

bool ConfigManager::HasValue(const std::string& path) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    auto value = pImpl->GetValue(path);
    return !std::holds_alternative<std::nullptr_t>(value);
}

bool ConfigManager::Remove(const std::string& path) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->RemoveValue(path);
}

void ConfigManager::Clear() {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->ClearValues();
}

std::vector<std::string> ConfigManager::GetKeys(const std::string& path) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    std::vector<std::string> keys;
    std::string prefix = path.empty() ? "" : path + ".";
    
    for (const auto& [key, _] : pImpl->entries_) {
        if (path.empty() || key.rfind(prefix, 0) == 0) {
            std::string relativeKey = path.empty() ? key : key.substr(prefix.length());
            size_t dotPos = relativeKey.find('.');
            if (dotPos != std::string::npos) {
                relativeKey = relativeKey.substr(0, dotPos);
            }
            
            if (std::find(keys.begin(), keys.end(), relativeKey) == keys.end()) {
                keys.push_back(relativeKey);
            }
        }
    }
    
    return keys;
}

std::vector<std::string> ConfigManager::GetPaths() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->GetAllPaths();
}

bool ConfigManager::ValidateAgainstSchema(const std::string& schemaPath) {
    try {
        std::ifstream file(schemaPath);
        if (!file.is_open()) {
            pImpl->validationErrors_.push_back("Cannot open schema file: " + schemaPath);
            return false;
        }
        
        json schema;
        file >> schema;
        
        return ValidateAgainstSchemaJson(schema);
    } catch (const std::exception& e) {
        pImpl->validationErrors_.push_back(std::string("Schema validation error: ") + e.what());
        return false;
    }
}

bool ConfigManager::ValidateAgainstSchemaJson(const json& schema) {
    // Simplified validation - in production, use a proper JSON Schema validator
    pImpl->validationErrors_.clear();
    
    try {
        if (schema.contains("required")) {
            for (const auto& req : schema["required"]) {
                std::string path = req.get<std::string>();
                if (!Has(path)) {
                    pImpl->validationErrors_.push_back("Missing required field: " + path);
                }
            }
        }
        
        return pImpl->validationErrors_.empty();
    } catch (const std::exception& e) {
        pImpl->validationErrors_.push_back(std::string("Validation error: ") + e.what());
        return false;
    }
}

std::vector<std::string> ConfigManager::GetValidationErrors() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->validationErrors_;
}

int ConfigManager::SubscribeToChanges(const std::string& pathPattern, ChangeCallback callback) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    int id = pImpl->nextSubscriptionId_++;
    pImpl->subscribers_[id] = {std::regex(pathPattern), callback};
    return id;
}

void ConfigManager::UnsubscribeFromChanges(int subscriptionId) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->subscribers_.erase(subscriptionId);
}

bool ConfigManager::StartFileWatcher(const std::string& path) {
    // Implementation would use platform-specific file watching
    // For now, just store the path
    pImpl->configFilePath_ = path;
    return true;
}

void ConfigManager::StopFileWatcher() {
    if (pImpl->fileWatcher_) {
        pImpl->fileWatcher_.reset();
    }
}

bool ConfigManager::IsFileWatcherRunning() const {
    return pImpl->fileWatcher_ != nullptr;
}

void ConfigManager::SetEnvironmentPrefix(const std::string& prefix) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->envPrefix_ = prefix;
}

void ConfigManager::RegisterEnvironmentMapping(const std::string& envVar, const std::string& configPath) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->envMappings_[envVar] = configPath;
}

void ConfigManager::MarkAsSecret(const std::string& path) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    auto it = pImpl->entries_.find(path);
    if (it != pImpl->entries_.end()) {
        it->second.isSecret = true;
    }
}

void ConfigManager::UnmarkAsSecret(const std::string& path) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    auto it = pImpl->entries_.find(path);
    if (it != pImpl->entries_.end()) {
        it->second.isSecret = false;
    }
}

bool ConfigManager::IsSecret(const std::string& path) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    auto it = pImpl->entries_.find(path);
    return it != pImpl->entries_.end() && it->second.isSecret;
}

std::string ConfigManager::MaskSecrets(const std::string& text) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    std::string result = text;
    for (const auto& [path, entry] : pImpl->entries_) {
        if (entry.isSecret) {
            std::string secretStr = ConfigValueToString(entry.value);
            if (!secretStr.empty()) {
                size_t pos = 0;
                while ((pos = result.find(secretStr, pos)) != std::string::npos) {
                    result.replace(pos, secretStr.length(), "***SECRET***");
                    pos += 12;
                }
            }
        }
    }
    return result;
}

json ConfigManager::ExportToJson(bool includeSecrets) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    json j;
    for (const auto& [path, entry] : pImpl->entries_) {
        if (!includeSecrets && entry.isSecret) {
            continue;
        }
        
        // Split path by dots and create nested structure
        std::vector<std::string> parts;
        std::stringstream ss(path);
        std::string part;
        while (std::getline(ss, part, '.')) {
            parts.push_back(part);
        }
        
        json* current = &j;
        for (size_t i = 0; i < parts.size() - 1; ++i) {
            if (!current->contains(parts[i])) {
                (*current)[parts[i]] = json::object();
            }
            current = &(*current)[parts[i]];
        }
        
        (*current)[parts.back()] = ConfigValueToJson(entry.value);
    }
    
    return j;
}

bool ConfigManager::ImportFromJson(const json& config, ConfigSource source) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    try {
        ImportJsonRecursive("", config, source);
        return true;
    } catch (const std::exception& e) {
        pImpl->validationErrors_.push_back(std::string("Import error: ") + e.what());
        return false;
    }
}

bool ConfigManager::MergeFromJson(const json& config, ConfigSource source) {
    return ImportFromJson(config, source);
}

void ConfigManager::ImportJsonRecursive(const std::string& prefix, const json& j, ConfigSource source) {
    if (j.is_object()) {
        for (const auto& [key, value] : j.items()) {
            std::string fullPath = prefix.empty() ? key : prefix + "." + key;
            if (value.is_object() && !value.empty() && !value.begin()->is_primitive()) {
                ImportJsonRecursive(fullPath, value, source);
            } else {
                pImpl->SetValue(fullPath, JsonToConfigValue(value), source, "");
            }
        }
    } else {
        pImpl->SetValue(prefix, JsonToConfigValue(j), source, "");
    }
}

bool ConfigManager::Reload() {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    if (pImpl->configFilePath_.empty()) {
        return false;
    }
    
    pImpl->ClearValues();
    SetDefaultValues();
    
    bool success = LoadFromFile(pImpl->configFilePath_);
    if (success) {
        LoadFromEnvironment();
        pImpl->lastReload_ = std::chrono::system_clock::now();
    }
    
    return success;
}

bool ConfigManager::ReloadIfChanged() {
    // Check if file has been modified since last reload
    if (pImpl->configFilePath_.empty()) {
        return false;
    }
    
    try {
        auto lastWrite = fs::last_write_time(pImpl->configFilePath_);
        // Convert to system_clock time for comparison
        // (Implementation depends on C++ version)
        return Reload();
    } catch (...) {
        return false;
    }
}

ConfigManager::Statistics ConfigManager::GetStatistics() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    Statistics stats;
    stats.totalEntries = pImpl->entries_.size();
    stats.secretEntries = std::count_if(pImpl->entries_.begin(), pImpl->entries_.end(),
                                       [](const auto& e) { return e.second.isSecret; });
    stats.fileWatchers = pImpl->fileWatcher_ ? 1 : 0;
    stats.changeSubscribers = pImpl->subscribers_.size();
    stats.lastReload = pImpl->lastReload_;
    
    return stats;
}

// Static helper implementations
ConfigValue ConfigManager::JsonToConfigValue(const json& j) {
    if (j.is_null()) {
        return nullptr;
    } else if (j.is_boolean()) {
        return j.get<bool>();
    } else if (j.is_number_integer()) {
        return j.get<int64_t>();
    } else if (j.is_number_float()) {
        return j.get<double>();
    } else if (j.is_string()) {
        return j.get<std::string>();
    } else if (j.is_array()) {
        std::vector<ConfigValue> arr;
        for (const auto& elem : j) {
            arr.push_back(JsonToConfigValue(elem));
        }
        return arr;
    } else if (j.is_object()) {
        std::map<std::string, ConfigValue> obj;
        for (const auto& [key, value] : j.items()) {
            obj[key] = JsonToConfigValue(value);
        }
        return obj;
    }
    return nullptr;
}

json ConfigManager::ConfigValueToJson(const ConfigValue& value) {
    return std::visit([](auto&& arg) -> json {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, std::nullptr_t>) {
            return nullptr;
        } else if constexpr (std::is_same_v<T, bool>) {
            return arg;
        } else if constexpr (std::is_same_v<T, int64_t>) {
            return arg;
        } else if constexpr (std::is_same_v<T, double>) {
            return arg;
        } else if constexpr (std::is_same_v<T, std::string>) {
            return arg;
        } else if constexpr (std::is_same_v<T, std::vector<ConfigValue>>) {
            json arr = json::array();
            for (const auto& elem : arg) {
                arr.push_back(ConfigValueToJson(elem));
            }
            return arr;
        } else if constexpr (std::is_same_v<T, std::map<std::string, ConfigValue>>) {
            json obj = json::object();
            for (const auto& [key, val] : arg) {
                obj[key] = ConfigValueToJson(val);
            }
            return obj;
        }
        return nullptr;
    }, value);
}

std::string ConfigManager::ConfigValueToString(const ConfigValue& value) {
    return std::visit([](auto&& arg) -> std::string {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, std::nullptr_t>) {
            return "null";
        } else if constexpr (std::is_same_v<T, bool>) {
            return arg ? "true" : "false";
        } else if constexpr (std::is_same_v<T, int64_t>) {
            return std::to_string(arg);
        } else if constexpr (std::is_same_v<T, double>) {
            return std::to_string(arg);
        } else if constexpr (std::is_same_v<T, std::string>) {
            return arg;
        } else {
            return "<complex>";
        }
    }, value);
}

ConfigValue ConfigManager::StringToConfigValue(const std::string& str, const std::string& type) {
    if (type == "auto") {
        // Try to infer type
        if (str == "true" || str == "True" || str == "TRUE") {
            return true;
        } else if (str == "false" || str == "False" || str == "FALSE") {
            return false;
        } else if (str == "null" || str == "None" || str == "nil") {
            return nullptr;
        } else {
            // Try integer
            try {
                size_t pos;
                int64_t val = std::stoll(str, &pos);
                if (pos == str.length()) {
                    return val;
                }
            } catch (...) {}
            
            // Try double
            try {
                size_t pos;
                double val = std::stod(str, &pos);
                if (pos == str.length()) {
                    return val;
                }
            } catch (...) {}
        }
        
        // Default to string
        return str;
    } else if (type == "bool") {
        return str == "true" || str == "1" || str == "yes";
    } else if (type == "int") {
        try {
            return static_cast<int64_t>(std::stoll(str));
        } catch (...) {
            return 0;
        }
    } else if (type == "float" || type == "double") {
        try {
            return std::stod(str);
        } catch (...) {
            return 0.0;
        }
    } else {
        return str;
    }
}

// Template specialization for ConfigValue
template<>
void ConfigManager::Set<ConfigValue>(const std::string& path, const ConfigValue& value,
                                     ConfigSource source, const std::string& description) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->SetValue(path, value, source, description);
}

// Global config instance
static std::unique_ptr<ConfigManager> g_globalConfig;

ConfigManager& GetGlobalConfig() {
    if (!g_globalConfig) {
        g_globalConfig = std::make_unique<ConfigManager>();
        g_globalConfig->Initialize();
    }
    return *g_globalConfig;
}

void SetGlobalConfig(std::unique_ptr<ConfigManager> config) {
    g_globalConfig = std::move(config);
}

void ResetGlobalConfig() {
    g_globalConfig.reset();
}

} // namespace Core
} // namespace RawrXD
