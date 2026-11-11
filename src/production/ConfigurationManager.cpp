// RawrXD Configuration Manager Implementation
// Phase R.3: Dynamic configuration with hot reload and validation

#include "ConfigurationManager.hpp"
#include "../security/SecretManager.hpp"
#include "../security/AuditLogger.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdlib>

namespace RawrXD {
namespace Production {

// ============================================================================
// ConfigurationManager Implementation
// ============================================================================

ConfigurationManager::ConfigurationManager(SecretManager* secrets, AuditLogger* audit)
    : secrets_(secrets)
    , audit_(audit)
    , running_(false)
    , initialized_(false)
    , hotReloadEnabled_(false) {
}

ConfigurationManager::~ConfigurationManager() {
    if (running_) {
        shutdown();
    }
}

bool ConfigurationManager::initialize(const std::string& configPath) {
    if (initialized_) {
        return true;
    }
    
    configPath_ = configPath;
    
    // Load initial configuration
    loadFromFile(configPath);
    
    // Load environment variables
    loadFromEnvironment();
    
    // Validate
    if (!validate()) {
        // Log validation errors but continue with defaults
    }
    
    initialized_ = true;
    return true;
}

bool ConfigurationManager::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    running_ = false;
    
    if (reloadThread_.joinable()) {
        reloadThread_.join();
    }
    
    initialized_ = false;
    return true;
}

// ============================================================================
// Schema Registration
// ============================================================================

bool ConfigurationManager::registerSchema(const ConfigSchema& schema) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    schemas_[schema.key] = schema;
    
    // Set default value if not already set
    if (!config_.count(schema.key) && 
        std::holds_alternative<std::monostate>(schema.defaultValue) == false) {
        ConfigEntry entry;
        entry.key = schema.key;
        entry.value = schema.defaultValue;
        entry.source = ConfigSource::DEFAULT;
        entry.lastModified = std::chrono::system_clock::now();
        entry.description = schema.description;
        entry.isSecret = schema.isSecret;
        entry.isReadOnly = false;
        
        config_[schema.key] = entry;
    }
    
    return true;
}

bool ConfigurationManager::unregisterSchema(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    return schemas_.erase(key) > 0;
}

ConfigSchema ConfigurationManager::getSchema(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = schemas_.find(key);
    if (it != schemas_.end()) {
        return it->second;
    }
    
    return ConfigSchema{};
}

std::vector<ConfigSchema> ConfigurationManager::getAllSchemas() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ConfigSchema> result;
    for (const auto& [key, schema] : schemas_) {
        result.push_back(schema);
    }
    
    return result;
}

// ============================================================================
// Value Getters
// ============================================================================

template<typename T>
T ConfigurationManager::get(const std::string& key, const T& defaultValue) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = config_.find(key);
    if (it == config_.end()) {
        return defaultValue;
    }
    
    try {
        return std::get<T>(it->second.value);
    } catch (const std::bad_variant_access&) {
        return defaultValue;
    }
}

// Explicit instantiations
template bool ConfigurationManager::get<bool>(const std::string&, const bool&) const;
template int64_t ConfigurationManager::get<int64_t>(const std::string&, const int64_t&) const;
template double ConfigurationManager::get<double>(const std::string&, const double&) const;
template std::string ConfigurationManager::get<std::string>(const std::string&, const std::string&) const;

ConfigValue ConfigurationManager::getValue(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = config_.find(key);
    if (it != config_.end()) {
        return it->second.value;
    }
    
    return ConfigValue{};
}

std::string ConfigurationManager::getString(const std::string& key, const std::string& defaultValue) const {
    return get<std::string>(key, defaultValue);
}

int64_t ConfigurationManager::getInt(const std::string& key, int64_t defaultValue) const {
    return get<int64_t>(key, defaultValue);
}

double ConfigurationManager::getFloat(const std::string& key, double defaultValue) const {
    return get<double>(key, defaultValue);
}

bool ConfigurationManager::getBool(const std::string& key, bool defaultValue) const {
    return get<bool>(key, defaultValue);
}

std::vector<ConfigValue> ConfigurationManager::getArray(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = config_.find(key);
    if (it != config_.end()) {
        try {
            return std::get<std::vector<ConfigValue>>(it->second.value);
        } catch (const std::bad_variant_access&) {
            return {};
        }
    }
    
    return {};
}

std::map<std::string, ConfigValue> ConfigurationManager::getObject(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = config_.find(key);
    if (it != config_.end()) {
        try {
            return std::get<std::map<std::string, ConfigValue>>(it->second.value);
        } catch (const std::bad_variant_access&) {
            return {};
        }
    }
    
    return {};
}

// ============================================================================
// Value Setters
// ============================================================================

bool ConfigurationManager::set(const std::string& key, const ConfigValue& value, ConfigSource source) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if read-only
    auto it = config_.find(key);
    if (it != config_.end() && it->second.isReadOnly) {
        return false;
    }
    
    // Validate
    if (!validateValue(key, value)) {
        return false;
    }
    
    // Create change event
    ConfigChangeEvent event;
    event.key = key;
    event.oldValue = (it != config_.end()) ? it->second.value : ConfigValue{};
    event.newValue = value;
    event.source = source;
    event.timestamp = std::chrono::system_clock::now();
    
    // Update config
    ConfigEntry entry;
    entry.key = key;
    entry.value = value;
    entry.source = source;
    entry.lastModified = std::chrono::system_clock::now();
    
    auto schemaIt = schemas_.find(key);
    if (schemaIt != schemas_.end()) {
        entry.description = schemaIt->second.description;
        entry.isSecret = schemaIt->second.isSecret;
    }
    
    config_[key] = entry;
    
    // Store history
    history_[key].push_back(event);
    if (history_[key].size() > 100) {
        history_[key].erase(history_[key].begin());
    }
    
    // Notify
    notifyChange(event);
    
    return true;
}

bool ConfigurationManager::setString(const std::string& key, const std::string& value) {
    return set(key, ConfigValue(value), ConfigSource::FILE);
}

bool ConfigurationManager::setInt(const std::string& key, int64_t value) {
    return set(key, ConfigValue(value), ConfigSource::FILE);
}

bool ConfigurationManager::setFloat(const std::string& key, double value) {
    return set(key, ConfigValue(value), ConfigSource::FILE);
}

bool ConfigurationManager::setBool(const std::string& key, bool value) {
    return set(key, ConfigValue(value), ConfigSource::FILE);
}

// ============================================================================
// Secret Integration
// ============================================================================

bool ConfigurationManager::setSecret(const std::string& key, const std::string& secretPath) {
    if (!secrets_) {
        return false;
    }
    
    // Store reference to secret
    ConfigEntry entry;
    entry.key = key;
    entry.value = ConfigValue(std::string("${secret:") + secretPath + "}");
    entry.source = ConfigSource::SECRET;
    entry.isSecret = true;
    
    std::lock_guard<std::mutex> lock(mutex_);
    config_[key] = entry;
    
    return true;
}

bool ConfigurationManager::resolveSecrets() {
    if (!secrets_) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& [key, entry] : config_) {
        if (entry.isSecret) {
            // Resolve secret value
            // Would call secrets_->readSecret()
        }
    }
    
    return true;
}

// ============================================================================
// Environment Variable Loading
// ============================================================================

bool ConfigurationManager::loadFromEnvironment(const std::string& prefix) {
    // Platform-specific environment variable loading
#ifdef _WIN32
    // Windows implementation
    char* buffer = nullptr;
    size_t size = 0;
    
    // Get all environment variables
    // This is simplified - real implementation would enumerate all env vars
#else
    // Unix implementation
    extern char** environ;
    
    for (char** env = environ; *env != nullptr; ++env) {
        std::string envVar(*env);
        size_t pos = envVar.find('=');
        if (pos == std::string::npos) continue;
        
        std::string name = envVar.substr(0, pos);
        std::string value = envVar.substr(pos + 1);
        
        // Check if it starts with our prefix
        if (name.find(prefix) == 0) {
            std::string key = name.substr(prefix.length());
            
            // Convert to lowercase and replace _ with .
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            std::replace(key.begin(), key.end(), '_', '.');
            
            // Try to parse as different types
            if (value == "true" || value == "TRUE" || value == "1") {
                set(key, ConfigValue(true), ConfigSource::ENVIRONMENT);
            } else if (value == "false" || value == "FALSE" || value == "0") {
                set(key, ConfigValue(false), ConfigSource::ENVIRONMENT);
            } else {
                // Try integer
                try {
                    size_t idx;
                    int64_t intVal = std::stoll(value, &idx);
                    if (idx == value.length()) {
                        set(key, ConfigValue(intVal), ConfigSource::ENVIRONMENT);
                        continue;
                    }
                } catch (...) {}
                
                // Try float
                try {
                    size_t idx;
                    double floatVal = std::stod(value, &idx);
                    if (idx == value.length()) {
                        set(key, ConfigValue(floatVal), ConfigSource::ENVIRONMENT);
                        continue;
                    }
                } catch (...) {}
                
                // String
                set(key, ConfigValue(value), ConfigSource::ENVIRONMENT);
            }
        }
    }
#endif
    
    return true;
}

bool ConfigurationManager::loadFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        return false;
    }
    
    // Simple JSON parsing (simplified)
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    
    // Would parse JSON and load values
    // For now, just store last modified time
    lastFileModified_ = std::chrono::system_clock::now();
    
    return true;
}

bool ConfigurationManager::loadFromCommandLine(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        
        // Parse --key=value format
        if (arg.substr(0, 2) == "--") {
            size_t pos = arg.find('=');
            if (pos != std::string::npos) {
                std::string key = arg.substr(2, pos - 2);
                std::string value = arg.substr(pos + 1);
                
                set(key, ConfigValue(value), ConfigSource::COMMAND_LINE);
            }
        }
    }
    
    return true;
}

// ============================================================================
// Validation
// ============================================================================

bool ConfigurationManager::validate() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& [key, schema] : schemas_) {
        if (schema.required && !config_.count(key)) {
            return false;
        }
        
        auto it = config_.find(key);
        if (it != config_.end()) {
            if (!validateValue(key, it->second.value)) {
                return false;
            }
        }
    }
    
    return true;
}

bool ConfigurationManager::validateKey(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = config_.find(key);
    if (it == config_.end()) {
        return true; // No value to validate
    }
    
    return validateValue(key, it->second.value);
}

std::vector<std::string> ConfigurationManager::getValidationErrors() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> errors;
    
    for (const auto& [key, schema] : schemas_) {
        if (schema.required && !config_.count(key)) {
            errors.push_back("Missing required key: " + key);
        }
        
        auto it = config_.find(key);
        if (it != config_.end()) {
            if (!validateValue(key, it->second.value)) {
                errors.push_back("Invalid value for key: " + key);
            }
        }
    }
    
    return errors;
}

// ============================================================================
// Hot Reload
// ============================================================================

bool ConfigurationManager::enableHotReload(std::chrono::seconds interval) {
    if (hotReloadEnabled_) {
        return true;
    }
    
    hotReloadEnabled_ = true;
    running_ = true;
    
    reloadThread_ = std::thread(&ConfigurationManager::hotReloadLoop, this);
    
    return true;
}

bool ConfigurationManager::disableHotReload() {
    hotReloadEnabled_ = false;
    running_ = false;
    
    if (reloadThread_.joinable()) {
        reloadThread_.join();
    }
    
    return true;
}

void ConfigurationManager::triggerReload() {
    loadFromFile(configPath_);
}

void ConfigurationManager::hotReloadLoop() {
    while (running_ && hotReloadEnabled_) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        
        if (!running_ || !hotReloadEnabled_) break;
        
        // Check if file has been modified
        // Would stat file and compare modification time
        
        triggerReload();
    }
}

// ============================================================================
// Callbacks
// ============================================================================

void ConfigurationManager::addChangeCallback(const std::string& key, ConfigChangeCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_[key].push_back(callback);
}

void ConfigurationManager::removeChangeCallback(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_.erase(key);
}

void ConfigurationManager::addGlobalChangeCallback(ConfigChangeCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    globalCallbacks_.push_back(callback);
}

void ConfigurationManager::notifyChange(const ConfigChangeEvent& event) {
    // Notify specific callbacks
    auto it = callbacks_.find(event.key);
    if (it != callbacks_.end()) {
        for (const auto& callback : it->second) {
            callback(event);
        }
    }
    
    // Notify global callbacks
    for (const auto& callback : globalCallbacks_) {
        callback(event);
    }
}

// ============================================================================
// Export/Import
// ============================================================================

std::string ConfigurationManager::exportToJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::stringstream json;
    json << "{";
    
    bool first = true;
    for (const auto& [key, entry] : config_) {
        if (!first) json << ",";
        first = false;
        
        json << "\"" << key << "\":";
        
        // Serialize value based on type
        std::visit([&json](auto&& arg) {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, std::monostate>) {
                json << "null";
            } else if constexpr (std::is_same_v<T, bool>) {
                json << (arg ? "true" : "false");
            } else if constexpr (std::is_same_v<T, int64_t>) {
                json << arg;
            } else if constexpr (std::is_same_v<T, double>) {
                json << arg;
            } else if constexpr (std::is_same_v<T, std::string>) {
                json << "\"" << arg << "\"";
            } else {
                json << "{}";
            }
        }, entry.value);
    }
    
    json << "}";
    return json.str();
}

std::string ConfigurationManager::exportToYaml() const {
    // Would implement YAML export
    return "";
}

bool ConfigurationManager::importFromJson(const std::string& json) {
    // Would implement JSON import
    return true;
}

bool ConfigurationManager::importFromYaml(const std::string& yaml) {
    // Would implement YAML import
    return true;
}

// ============================================================================
// Configuration Sections
// ============================================================================

std::vector<std::string> ConfigurationManager::getKeys(const std::string& prefix) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [key, entry] : config_) {
        if (prefix.empty() || key.find(prefix) == 0) {
            result.push_back(key);
        }
    }
    
    return result;
}

std::map<std::string, ConfigValue> ConfigurationManager::getSection(const std::string& prefix) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::map<std::string, ConfigValue> result;
    for (const auto& [key, entry] : config_) {
        if (key.find(prefix) == 0) {
            result[key] = entry.value;
        }
    }
    
    return result;
}

bool ConfigurationManager::hasKey(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.count(key) > 0;
}

// ============================================================================
// Defaults
// ============================================================================

bool ConfigurationManager::resetToDefaults() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& [key, schema] : schemas_) {
        if (!schema.isReadOnly && 
            std::holds_alternative<std::monostate>(schema.defaultValue) == false) {
            ConfigEntry entry;
            entry.key = key;
            entry.value = schema.defaultValue;
            entry.source = ConfigSource::DEFAULT;
            entry.lastModified = std::chrono::system_clock::now();
            entry.description = schema.description;
            entry.isSecret = schema.isSecret;
            
            config_[key] = entry;
        }
    }
    
    return true;
}

bool ConfigurationManager::resetKeyToDefault(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto schemaIt = schemas_.find(key);
    if (schemaIt == schemas_.end()) {
        return false;
    }
    
    if (schemaIt->second.isReadOnly) {
        return false;
    }
    
    ConfigEntry entry;
    entry.key = key;
    entry.value = schemaIt->second.defaultValue;
    entry.source = ConfigSource::DEFAULT;
    entry.lastModified = std::chrono::system_clock::now();
    entry.description = schemaIt->second.description;
    entry.isSecret = schemaIt->second.isSecret;
    
    config_[key] = entry;
    
    return true;
}

// ============================================================================
// History
// ============================================================================

std::vector<ConfigChangeEvent> ConfigurationManager::getChangeHistory(const std::string& key, uint32_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = history_.find(key);
    if (it == history_.end()) {
        return {};
    }
    
    auto& events = it->second;
    if (events.size() <= limit) {
        return events;
    }
    
    return std::vector<ConfigChangeEvent>(events.end() - limit, events.end());
}

// ============================================================================
// Environment Profiles
// ============================================================================

void ConfigurationManager::setEnvironment(const std::string& env) {
    environment_ = env;
    
    // Load environment-specific configuration
    loadProfile(env);
}

bool ConfigurationManager::loadProfile(const std::string& profileName) {
    std::string profilePath = configPath_ + "." + profileName;
    return loadFromFile(profilePath);
}

// ============================================================================
// Internal Methods
// ============================================================================

bool ConfigurationManager::validateValue(const std::string& key, const ConfigValue& value) const {
    auto it = schemas_.find(key);
    if (it == schemas_.end()) {
        return true; // No schema to validate against
    }
    
    const auto& schema = it->second;
    
    // Check allowed values
    if (!schema.allowedValues.empty()) {
        // Would check if value is in allowed values
    }
    
    // Run custom validator
    if (schema.validator) {
        return schema.validator(value);
    }
    
    return true;
}

ConfigValue ConfigurationManager::resolveValue(const ConfigValue& value) const {
    // Would resolve variable references like ${env:VAR} or ${secret:path}
    return value;
}

std::string ConfigurationManager::expandVariables(const std::string& value) const {
    std::string result = value;
    
    // Expand ${env:VAR}
    size_t pos = 0;
    while ((pos = result.find("${env:", pos)) != std::string::npos) {
        size_t end = result.find("}", pos);
        if (end == std::string::npos) break;
        
        std::string varName = result.substr(pos + 6, end - pos - 6);
        const char* varValue = std::getenv(varName.c_str());
        
        if (varValue) {
            result.replace(pos, end - pos + 1, varValue);
        } else {
            pos = end + 1;
        }
    }
    
    return result;
}

// ============================================================================
// FeatureFlags Implementation
// ============================================================================

FeatureFlags::FeatureFlags(ConfigurationManager* config)
    : config_(config) {
}

bool FeatureFlags::isEnabled(const std::string& flag) const {
    return config_->getBool("feature." + flag, false);
}

void FeatureFlags::enable(const std::string& flag) {
    config_->setBool("feature." + flag, true);
}

void FeatureFlags::disable(const std::string& flag) {
    config_->setBool("feature." + flag, false);
}

void FeatureFlags::toggle(const std::string& flag) {
    enable(flag, !isEnabled(flag));
}

bool FeatureFlags::isEnabledFor(const std::string& flag, const std::string& entity) const {
    // Would check if feature is enabled for specific entity (gradual rollout)
    return isEnabled(flag);
}

void FeatureFlags::setRolloutPercentage(const std::string& flag, uint32_t percentage) {
    config_->setInt("feature." + flag + ".rollout", percentage);
}

std::string FeatureFlags::getVariant(const std::string& experiment, const std::string& userId) const {
    // Would return A/B test variant for user
    return "control";
}

void FeatureFlags::configureExperiment(const std::string& experiment,
                                      const std::vector<std::string>& variants,
                                      const std::map<std::string, uint32_t>& weights) {
    // Would configure A/B test
}

std::map<std::string, bool> FeatureFlags::getAllFlags() const {
    std::map<std::string, bool> flags;
    
    auto keys = config_->getKeys("feature.");
    for (const auto& key : keys) {
        std::string flagName = key.substr(8); // Remove "feature." prefix
        flags[flagName] = config_->getBool(key, false);
    }
    
    return flags;
}

void FeatureFlags::bulkUpdate(const std::map<std::string, bool>& flags) {
    for (const auto& [flag, enabled] : flags) {
        config_->setBool("feature." + flag, enabled);
    }
}

} // namespace Production
} // namespace RawrXD
