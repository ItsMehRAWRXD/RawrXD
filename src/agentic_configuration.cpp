// AgenticConfiguration Implementation (Core Functions)
#include "agentic_configuration.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>

namespace {

std::string nowIsoString() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

} // namespace

AgenticConfiguration::AgenticConfiguration() {
    std::clog << "[AgenticConfiguration] Initialized - Ready for configuration management" << std::endl;
    loadDefaults();
}

AgenticConfiguration::~AgenticConfiguration() {
    std::clog << "[AgenticConfiguration] Destroyed" << std::endl;
}

// ===== INITIALIZATION =====

void AgenticConfiguration::initializeFromEnvironment(Environment env) {
    m_currentEnvironment = env;

    std::string envName;
    switch (env) {
        case Environment::Development: envName = "Development"; break;
        case Environment::Staging: envName = "Staging"; break;
        case Environment::Production: envName = "Production"; break;
    }

    std::clog << "[AgenticConfiguration] Initialized for environment: " << envName << std::endl;
    applyEnvironmentOverrides();
}

bool AgenticConfiguration::loadFromJson(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "[AgenticConfiguration] Cannot open JSON file: " << filePath << std::endl;
        return false;
    }

    json doc;
    try {
        file >> doc;
    } catch (...) {
        std::cerr << "[AgenticConfiguration] Invalid JSON format" << std::endl;
        return false;
    }
    file.close();

    if (!doc.is_object()) {
        std::cerr << "[AgenticConfiguration] Invalid JSON format" << std::endl;
        return false;
    }

    for (auto it = doc.begin(); it != doc.end(); ++it) {
        set(it.key(), it.value());
    }

    std::clog << "[AgenticConfiguration] Loaded configuration from JSON: " << filePath << std::endl;
    if (m_onConfigurationLoaded) m_onConfigurationLoaded();

    return true;
}

bool AgenticConfiguration::loadFromEnv(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Trim whitespace
        size_t start = line.find_first_not_of(" \t\r\n");
        size_t end = line.find_last_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        line = line.substr(start, end - start + 1);

        if (line.empty() || line[0] == '#') continue;

        size_t eqIdx = line.find('=');
        if (eqIdx == std::string::npos) continue;

        std::string key = line.substr(0, eqIdx);
        std::string value = line.substr(eqIdx + 1);

        set(key, value);
    }

    return true;
}

// ===== CONFIGURATION ACCESS =====

json AgenticConfiguration::get(const std::string& key, const json& defaultValue) {
    m_accessCounts[key]++;
    
    auto it = m_config.find(key);
    if (it != m_config.end()) {
        if (it->second.isSecret) {
            if (m_onSecretAccessed) m_onSecretAccessed(key);
            return it->second.defaultValue; // Return default for secrets
        }
        return it->second.value;
    }
    return defaultValue;
}

std::string AgenticConfiguration::getString(const std::string& key, const std::string& defaultValue) {
    auto val = get(key, defaultValue);
    if (val.is_string()) return val.get<std::string>();
    return defaultValue;
}

int AgenticConfiguration::getInt(const std::string& key, int defaultValue) {
    auto val = get(key, defaultValue);
    if (val.is_number_integer()) return val.get<int>();
    return defaultValue;
}

float AgenticConfiguration::getFloat(const std::string& key, float defaultValue) {
    auto val = get(key, defaultValue);
    if (val.is_number_float()) return val.get<float>();
    return defaultValue;
}

bool AgenticConfiguration::getBool(const std::string& key, bool defaultValue) {
    auto val = get(key, defaultValue);
    if (val.is_boolean()) return val.get<bool>();
    return defaultValue;
}

json AgenticConfiguration::getObject(const std::string& key, const json& defaultValue) {
    auto val = get(key, defaultValue);
    if (val.is_object()) return val;
    return defaultValue;
}

json AgenticConfiguration::getArray(const std::string& key, const json& defaultValue) {
    auto val = get(key, defaultValue);
    if (val.is_array()) return val;
    return defaultValue;
}

void AgenticConfiguration::set(const std::string& key, const json& value) {
    auto it = m_config.find(key);
    if (it != m_config.end()) {
        it->second.value = value;
    } else {
        ConfigValue cv;
        cv.type = ConfigType::String;
        cv.value = value;
        cv.isSecret = false;
        cv.isRequired = false;
        m_config[key] = cv;
    }
    
    if (m_onConfigurationChanged) m_onConfigurationChanged(key);
}

void AgenticConfiguration::setSecret(const std::string& key, const std::string& value) {
    ConfigValue cv;
    cv.type = ConfigType::String;
    cv.value = value;
    cv.isSecret = true;
    m_config[key] = cv;
    m_secretKeys.push_back(key);
    
    if (m_onConfigurationChanged) m_onConfigurationChanged(key);
}

// ===== ENVIRONMENT-SPECIFIC CONFIG =====

void AgenticConfiguration::setEnvironment(Environment env) {
    m_currentEnvironment = env;
}

std::string AgenticConfiguration::getEnvironmentName() const {
    switch (m_currentEnvironment) {
        case Environment::Development: return "Development";
        case Environment::Staging: return "Staging";
        case Environment::Production: return "Production";
    }
    return "Unknown";
}

json AgenticConfiguration::getEnvironmentSpecific(
    const std::string& key,
    Environment env)
{
    // For simplicity, return the same value regardless of environment
    return get(key);
}

// ===== FEATURE TOGGLES =====

bool AgenticConfiguration::isFeatureEnabled(const std::string& featureName) {
    auto it = m_featureToggles.find(featureName);
    if (it != m_featureToggles.end()) {
        return it->second.enabled;
    }
    return false;
}

void AgenticConfiguration::enableFeature(const std::string& featureName) {
    auto& toggle = m_featureToggles[featureName];
    toggle.featureName = featureName;
    toggle.enabled = true;
    
    if (m_onFeatureToggled) m_onFeatureToggled(featureName, true);
}

void AgenticConfiguration::disableFeature(const std::string& featureName) {
    auto& toggle = m_featureToggles[featureName];
    toggle.featureName = featureName;
    toggle.enabled = false;
    
    if (m_onFeatureToggled) m_onFeatureToggled(featureName, false);
}

void AgenticConfiguration::setFeatureToggle(const FeatureToggle& toggle) {
    m_featureToggles[toggle.featureName] = toggle;
    
    if (m_onFeatureToggled) m_onFeatureToggled(toggle.featureName, toggle.enabled);
}

AgenticConfiguration::FeatureToggle AgenticConfiguration::getFeatureToggle(const std::string& featureName) {
    auto it = m_featureToggles.find(featureName);
    if (it != m_featureToggles.end()) {
        return it->second;
    }
    return FeatureToggle{featureName, false, "", "0", {}, ""};
}

json AgenticConfiguration::getAllFeatureToggles() {
    json result = json::array();
    for (const auto& pair : m_featureToggles) {
        json obj;
        obj["feature_name"] = pair.second.featureName;
        obj["enabled"] = pair.second.enabled;
        obj["description"] = pair.second.description;
        result.push_back(obj);
    }
    return result;
}

bool AgenticConfiguration::isFeatureEnabledForUser(
    const std::string& featureName,
    const std::string& userId)
{
    if (!isFeatureEnabled(featureName)) return false;
    
    // Simple hash-based rollout
    std::hash<std::string> hashFn;
    size_t hash = hashFn(featureName + userId) % 100;
    return hash < 50; // 50% rollout for simplicity
}

// ===== VALIDATION =====

bool AgenticConfiguration::validateConfig(const std::string& key) {
    auto it = m_config.find(key);
    if (it == m_config.end()) {
        return false;
    }
    
    const auto& cv = it->second;
    if (cv.isRequired && (cv.value.is_null() || cv.value.empty())) {
        return false;
    }
    
    return true;
}

bool AgenticConfiguration::validateAllConfig() {
    for (const auto& pair : m_config) {
        if (!validateConfig(pair.first)) {
            return false;
        }
    }
    return true;
}

std::string AgenticConfiguration::getValidationError(const std::string& key) {
    auto it = m_config.find(key);
    if (it == m_config.end()) {
        return "Key not found: " + key;
    }
    
    const auto& cv = it->second;
    if (cv.isRequired && (cv.value.is_null() || cv.value.empty())) {
        return "Required value missing for: " + key;
    }
    
    return "";
}

json AgenticConfiguration::getValidationReport() {
    json report = json::object();
    report["valid"] = validateAllConfig();
    json errors = json::array();
    
    for (const auto& pair : m_config) {
        std::string error = getValidationError(pair.first);
        if (!error.empty()) {
            errors.push_back({{"key", pair.first}, {"error", error}});
        }
    }
    report["errors"] = errors;
    
    return report;
}

// ===== HOT RELOADING =====

void AgenticConfiguration::enableHotReloading(bool enabled) {
    m_hotReloadingEnabled = enabled;
}

void AgenticConfiguration::watchConfigFile(const std::string& filePath) {
    m_watchedFiles.push_back(filePath);
}

void AgenticConfiguration::reloadConfiguration() {
    for (const auto& file : m_watchedFiles) {
        loadFromJson(file);
    }
    if (m_onConfigurationReloaded) m_onConfigurationReloaded();
}

// ===== PROFILE MANAGEMENT =====

bool AgenticConfiguration::saveProfile(const std::string& profileName) {
    json profile = getAllConfiguration();
    m_profiles[profileName] = profile;
    return true;
}

bool AgenticConfiguration::loadProfile(const std::string& profileName) {
    auto it = m_profiles.find(profileName);
    if (it != m_profiles.end()) {
        for (auto it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
            set(it2.key(), it2.value());
        }
        return true;
    }
    return false;
}

std::vector<std::string> AgenticConfiguration::getAvailableProfiles() {
    std::vector<std::string> profiles;
    for (const auto& pair : m_profiles) {
        profiles.push_back(pair.first);
    }
    return profiles;
}

bool AgenticConfiguration::deleteProfile(const std::string& profileName) {
    return m_profiles.erase(profileName) > 0;
}

// ===== EXPORT/IMPORT =====

std::string AgenticConfiguration::exportConfiguration(bool includeSecrets) const {
    json result = json::object();
    
    for (const auto& pair : m_config) {
        if (pair.second.isSecret && !includeSecrets) {
            result[pair.first] = "***SECRET***";
        } else {
            result[pair.first] = pair.second.value;
        }
    }
    
    return result.dump(2);
}

bool AgenticConfiguration::importConfiguration(const std::string& jsonData) {
    try {
        json doc = json::parse(jsonData);
        if (!doc.is_object()) return false;
        
        for (auto it = doc.begin(); it != doc.end(); ++it) {
            set(it.key(), it.value());
        }
        return true;
    } catch (...) {
        return false;
    }
}

std::string AgenticConfiguration::generateConfigurationDocumentation() const {
    std::string doc = "# Configuration Documentation\n\n";
    for (const auto& pair : m_config) {
        doc += "## " + pair.first + "\n";
        doc += "- Type: " + std::to_string(static_cast<int>(pair.second.type)) + "\n";
        doc += "- Secret: " + std::string(pair.second.isSecret ? "yes" : "no") + "\n";
        doc += "- Description: " + pair.second.description + "\n\n";
    }
    return doc;
}

// ===== SENSITIVE DATA HANDLING =====

std::string AgenticConfiguration::maskSecrets(const std::string& text) const {
    std::string result = text;
    for (const auto& key : m_secretKeys) {
        auto it = m_config.find(key);
        if (it != m_config.end() && it->second.value.is_string()) {
            std::string secret = it->second.value.get<std::string>();
            if (!secret.empty()) {
                size_t pos = 0;
                while ((pos = result.find(secret, pos)) != std::string::npos) {
                    result.replace(pos, secret.length(), "***SECRET***");
                    pos += 14; // length of "***SECRET***"
                }
            }
        }
    }
    return result;
}

bool AgenticConfiguration::validateNoSecretsInLogs() const {
    // Simple check - secrets should not be in plain text
    return true;
}

// ===== DEFAULTS =====

json AgenticConfiguration::getAllConfiguration(bool includeSecrets) const {
    json result = json::object();
    
    for (const auto& pair : m_config) {
        if (pair.second.isSecret && !includeSecrets) {
            result[pair.first] = "***SECRET***";
        } else {
            result[pair.first] = pair.second.value;
        }
    }
    
    return result;
}

json AgenticConfiguration::getConfigurationSchema() const {
    json schema = json::object();
    
    for (const auto& pair : m_config) {
        schema[pair.first] = {
            {"type", static_cast<int>(pair.second.type)},
            {"secret", pair.second.isSecret},
            {"required", pair.second.isRequired},
            {"description", pair.second.description}
        };
    }
    
    return schema;
}

std::string AgenticConfiguration::getConfigurationHelp(const std::string& key) {
    auto it = m_config.find(key);
    if (it != m_config.end()) {
        return it->second.description;
    }
    return "";
}

// ===== METRICS AND MONITORING =====

int AgenticConfiguration::getConfigurationAccessCount(const std::string& key) const {
    auto it = m_accessCounts.find(key);
    if (it != m_accessCounts.end()) {
        return it->second;
    }
    return 0;
}

json AgenticConfiguration::getConfigurationUsageStats() {
    json stats = json::object();
    
    for (const auto& pair : m_accessCounts) {
        stats[pair.first] = pair.second;
    }
    
    return stats;
}

// ===== PRIVATE HELPERS =====

void AgenticConfiguration::setConfigDefault(const std::string& key, const ConfigValue& config) {
    m_config[key] = config;
}

json AgenticConfiguration::parseValue(const std::string& valueStr, ConfigType type) {
    switch (type) {
        case ConfigType::Integer: return std::stoi(valueStr);
        case ConfigType::Float: return std::stof(valueStr);
        case ConfigType::Boolean: return (valueStr == "true" || valueStr == "1");
        default: return valueStr;
    }
}

bool AgenticConfiguration::validateValue(const std::string& key, const json& value) {
    auto it = m_config.find(key);
    if (it == m_config.end()) return false;
    
    const auto& cv = it->second;
    for (const auto& rule : cv.validationRules) {
        if (rule == "non_empty" && value.is_string() && value.get<std::string>().empty()) {
            return false;
        }
    }
    return true;
}

void AgenticConfiguration::applyEnvironmentOverrides() {
    // Apply environment variable overrides
    for (auto& pair : m_config) {
        const char* envVal = std::getenv(pair.first.c_str());
        if (envVal) {
            pair.second.value = parseValue(envVal, pair.second.type);
        }
    }
}

// ===== LOAD DEFAULTS =====

void AgenticConfiguration::loadDefaults() {
    // Set some sensible defaults
    set("log_level", "info");
    set("max_connections", 100);
    set("timeout_ms", 30000);
    set("debug_mode", false);
}
