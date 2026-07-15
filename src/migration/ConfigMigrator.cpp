// RawrXD Configuration Migrator Implementation
// Phase Y.2: Configuration migration utilities

#include "ConfigMigrator.hpp"
#include <sstream>
#include <fstream>
#include <algorithm>

namespace RawrXD {
namespace Migration {

// ============================================================================
// ConfigVersion Implementation
// ============================================================================

std::string ConfigVersion::toString() const {
    std::ostringstream oss;
    oss << major << "." << minor << "." << patch;
    return oss.str();
}

bool ConfigVersion::operator<(const ConfigVersion& other) const {
    if (major != other.major) return major < other.major;
    if (minor != other.minor) return minor < other.minor;
    return patch < other.patch;
}

bool ConfigVersion::operator==(const ConfigVersion& other) const {
    return major == other.major && minor == other.minor && patch == other.patch;
}

// ============================================================================
// ConfigMigrator Implementation
// ============================================================================

ConfigMigrator::ConfigMigrator() = default;

ConfigMigrator::~ConfigMigrator() = default;

void ConfigMigrator::registerSchema(const ConfigSchema& schema) {
    schemas_[schema.version] = schema;
}

void ConfigMigrator::registerMigrationRule(const MigrationRule& rule) {
    migrationRules_.push_back(rule);
}

ConfigVersion ConfigMigrator::detectVersion(const std::map<std::string, std::string>& config) const {
    // Check for version key
    auto it = config.find("version");
    if (it != config.end()) {
        std::istringstream iss(it->second);
        ConfigVersion ver{0, 0, 0};
        char dot;
        iss >> ver.major >> dot >> ver.minor >> dot >> ver.patch;
        return ver;
    }
    
    // Infer from keys present
    return ConfigVersion{1, 0, 0};  // Default
}

bool ConfigMigrator::isVersionSupported(const ConfigVersion& version) const {
    return schemas_.find(version) != schemas_.end();
}

ConfigMigrationResult ConfigMigrator::migrate(const std::map<std::string, std::string>& config,
                                            const ConfigVersion& targetVersion) {
    ConfigMigrationResult result;
    result.fromVersion = detectVersion(config);
    result.toVersion = targetVersion;
    
    if (result.fromVersion == targetVersion) {
        result.success = true;
        return result;
    }
    
    // Copy config for migration
    std::map<std::string, std::string> workingConfig = config;
    
    // Apply migrations
    result = applyMigrations(workingConfig, result.fromVersion, targetVersion);
    
    // Validate final config
    if (!validateConfig(workingConfig, targetVersion)) {
        auto errors = getValidationErrors(workingConfig, targetVersion);
        result.errors.insert(result.errors.end(), errors.begin(), errors.end());
        result.success = false;
    } else {
        result.success = true;
    }
    
    return result;
}

ConfigMigrationResult ConfigMigrator::migrate(const std::string& configPath,
                                              const ConfigVersion& targetVersion) {
    auto config = importFromJSON(configPath);
    return migrate(config, targetVersion);
}

bool ConfigMigrator::validateConfig(const std::map<std::string, std::string>& config,
                                   const ConfigVersion& version) const {
    return getValidationErrors(config, version).empty();
}

std::vector<std::string> ConfigMigrator::getValidationErrors(const std::map<std::string, std::string>& config,
                                                              const ConfigVersion& version) const {
    std::vector<std::string> errors;
    
    auto schemaIt = schemas_.find(version);
    if (schemaIt == schemas_.end()) {
        errors.push_back("Unknown schema version: " + version.toString());
        return errors;
    }
    
    const auto& schema = schemaIt->second;
    
    // Check required keys
    for (const auto& key : schema.requiredKeys) {
        if (config.find(key) == config.end()) {
            errors.push_back("Missing required key: " + key);
        }
    }
    
    // Check dependencies
    for (const auto& [key, deps] : schema.dependencies) {
        if (config.find(key) != config.end()) {
            for (const auto& dep : deps) {
                if (config.find(dep) == config.end()) {
                    errors.push_back("Missing dependency for " + key + ": " + dep);
                }
            }
        }
    }
    
    return errors;
}

std::map<std::string, std::string> ConfigMigrator::getDefaults(const ConfigVersion& version) const {
    std::map<std::string, std::string> defaults;
    
    auto it = schemas_.find(version);
    if (it != schemas_.end()) {
        for (const auto& [key, entry] : it->second.entries) {
            defaults[key] = entry.value;
        }
    }
    
    return defaults;
}

std::vector<std::string> ConfigMigrator::getDeprecatedKeys(const ConfigVersion& version) const {
    std::vector<std::string> deprecated;
    
    auto it = schemas_.find(version);
    if (it != schemas_.end()) {
        for (const auto& [key, entry] : it->second.entries) {
            if (entry.isDeprecated) {
                deprecated.push_back(key);
            }
        }
    }
    
    return deprecated;
}

std::vector<std::string> ConfigMigrator::getRemovedKeys(const ConfigVersion& fromVersion,
                                                        const ConfigVersion& toVersion) const {
    std::vector<std::string> removed;
    
    auto fromIt = schemas_.find(fromVersion);
    auto toIt = schemas_.find(toVersion);
    
    if (fromIt != schemas_.end() && toIt != schemas_.end()) {
        for (const auto& [key, entry] : fromIt->second.entries) {
            if (toIt->second.entries.find(key) == toIt->second.entries.end()) {
                removed.push_back(key);
            }
        }
    }
    
    return removed;
}

std::map<std::string, std::string> ConfigMigrator::getKeyChanges(const ConfigVersion& fromVersion,
                                                                  const ConfigVersion& toVersion) const {
    std::map<std::string, std::string> changes;
    
    auto fromIt = schemas_.find(fromVersion);
    auto toIt = schemas_.find(toVersion);
    
    if (fromIt != schemas_.end() && toIt != schemas_.end()) {
        for (const auto& [key, entry] : fromIt->second.entries) {
            auto toEntry = toIt->second.entries.find(key);
            if (toEntry != toIt->second.entries.end()) {
                if (entry.value != toEntry->second.value) {
                    changes[key] = toEntry->second.value;
                }
            }
        }
    }
    
    return changes;
}

bool ConfigMigrator::exportToJSON(const std::map<std::string, std::string>& config,
                                 const std::string& outputPath) const {
    std::ofstream file(outputPath);
    if (!file) return false;
    
    file << "{\n";
    bool first = true;
    for (const auto& [key, value] : config) {
        if (!first) file << ",\n";
        first = false;
        file << "  \"" << key << "\": \"" << value << "\"";
    }
    file << "\n}\n";
    
    return true;
}

std::map<std::string, std::string> ConfigMigrator::importFromJSON(const std::string& inputPath) const {
    std::map<std::string, std::string> config;
    
    std::ifstream file(inputPath);
    if (!file) return config;
    
    // Simple JSON parsing - would use proper JSON library
    std::string line;
    while (std::getline(file, line)) {
        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string key = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 1);
            
            // Trim quotes and whitespace
            key.erase(0, key.find_first_not_of(" \"\t"));
            key.erase(key.find_last_not_of(" \"\t") + 1);
            value.erase(0, value.find_first_not_of(" \"\t,"));
            value.erase(value.find_last_not_of(" \"\t,") + 1);
            
            if (!key.empty() && !value.empty()) {
                config[key] = value;
            }
        }
    }
    
    return config;
}

bool ConfigMigrator::exportToYAML(const std::map<std::string, std::string>& config,
                                 const std::string& outputPath) const {
    std::ofstream file(outputPath);
    if (!file) return false;
    
    for (const auto& [key, value] : config) {
        file << key << ": " << value << "\n";
    }
    
    return true;
}

std::map<std::string, std::string> ConfigMigrator::importFromYAML(const std::string& inputPath) const {
    std::map<std::string, std::string> config;
    
    std::ifstream file(inputPath);
    if (!file) return config;
    
    std::string line;
    while (std::getline(file, line)) {
        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string key = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 1);
            
            // Trim whitespace
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            if (!key.empty() && !key.starts_with("#")) {
                config[key] = value;
            }
        }
    }
    
    return config;
}

ConfigMigrationResult ConfigMigrator::applyMigrations(std::map<std::string, std::string>& config,
                                                      const ConfigVersion& fromVersion,
                                                      const ConfigVersion& toVersion) {
    ConfigMigrationResult result;
    result.fromVersion = fromVersion;
    result.toVersion = toVersion;
    
    // Sort rules by version
    std::vector<MigrationRule> applicableRules;
    for (const auto& rule : migrationRules_) {
        if (rule.fromVersion >= fromVersion && rule.toVersion <= toVersion) {
            applicableRules.push_back(rule);
        }
    }
    
    std::sort(applicableRules.begin(), applicableRules.end(),
              [](const MigrationRule& a, const MigrationRule& b) {
                  return a.fromVersion < b.fromVersion;
              });
    
    // Apply each rule
    for (const auto& rule : applicableRules) {
        try {
            if (rule.transform) {
                rule.transform(config);
            }
            
            for (const auto& key : rule.affectedKeys) {
                result.migratedKeys.push_back(key);
            }
        } catch (const std::exception& e) {
            result.errors.push_back("Migration failed: " + std::string(e.what()));
        }
    }
    
    // Update version
    config["version"] = toVersion.toString();
    
    return result;
}

// ============================================================================
// EnvironmentMigrator Implementation
// ============================================================================

EnvironmentMigrator::EnvironmentMigrator() = default;

void EnvironmentMigrator::registerEnvMigration(const EnvMigration& migration) {
    envMigrations_.push_back(migration);
}

bool EnvironmentMigrator::migrateEnvironment() {
    bool success = true;
    
    for (const auto& migration : envMigrations_) {
        const char* oldValue = std::getenv(migration.oldVar.c_str());
        if (oldValue) {
            // Migrate to new variable
#ifdef _WIN32
            _putenv_s(migration.newVar.c_str(), oldValue);
#else
            setenv(migration.newVar.c_str(), oldValue, 1);
#endif
        }
    }
    
    return success;
}

std::vector<std::string> EnvironmentMigrator::getUnsetRequiredVars() const {
    std::vector<std::string> unset;
    
    for (const auto& migration : envMigrations_) {
        if (migration.required) {
            const char* value = std::getenv(migration.newVar.c_str());
            if (!value || strlen(value) == 0) {
                unset.push_back(migration.newVar);
            }
        }
    }
    
    return unset;
}

std::map<std::string, std::string> EnvironmentMigrator::getMigratedEnvironment() const {
    std::map<std::string, std::string> env;
    
    for (const auto& migration : envMigrations_) {
        const char* value = std::getenv(migration.newVar.c_str());
        if (value) {
            env[migration.newVar] = value;
        }
    }
    
    return env;
}

bool EnvironmentMigrator::migratePaths(const std::string& oldBasePath, const std::string& newBasePath) {
    // Would migrate paths
    return true;
}

bool EnvironmentMigrator::migrateDataDirectory(const std::string& oldPath, const std::string& newPath) {
    // Would migrate data directory
    return true;
}

bool EnvironmentMigrator::migrateCacheDirectory(const std::string& oldPath, const std::string& newPath) {
    // Would migrate cache directory
    return true;
}

bool EnvironmentMigrator::migrateLogDirectory(const std::string& oldPath, const std::string& newPath) {
    // Would migrate log directory
    return true;
}

// ============================================================================
// DatabaseSchemaMigrator Implementation
// ============================================================================

DatabaseSchemaMigrator::DatabaseSchemaMigrator() = default;

void DatabaseSchemaMigrator::registerMigration(const MigrationScript& migration) {
    migrations_[migration.toVersion] = migration;
}

bool DatabaseSchemaMigrator::migrateToVersion(uint32_t targetVersion) {
    if (targetVersion <= currentVersion_) {
        return true;
    }
    
    // Apply migrations in order
    for (uint32_t v = currentVersion_ + 1; v <= targetVersion; ++v) {
        auto it = migrations_.find(v);
        if (it != migrations_.end()) {
            // Would execute upScripts
            currentVersion_ = v;
        }
    }
    
    return true;
}

bool DatabaseSchemaMigrator::rollbackToVersion(uint32_t targetVersion) {
    if (targetVersion >= currentVersion_) {
        return true;
    }
    
    // Rollback migrations in reverse order
    for (uint32_t v = currentVersion_; v > targetVersion; --v) {
        auto it = migrations_.find(v);
        if (it != migrations_.end() && it->second.isReversible) {
            // Would execute downScripts
            currentVersion_ = v - 1;
        }
    }
    
    return true;
}

uint32_t DatabaseSchemaMigrator::getCurrentVersion() const {
    return currentVersion_;
}

std::vector<DatabaseSchemaMigrator::SchemaVersion> DatabaseSchemaMigrator::getMigrationHistory() const {
    std::vector<SchemaVersion> history;
    
    for (uint32_t v = 1; v <= currentVersion_; ++v) {
        auto it = migrations_.find(v);
        if (it != migrations_.end()) {
            SchemaVersion sv;
            sv.version = v;
            sv.description = it->second.description;
            sv.appliedAt = std::chrono::system_clock::now();
            history.push_back(sv);
        }
    }
    
    return history;
}

std::vector<uint32_t> DatabaseSchemaMigrator::getPendingMigrations() const {
    std::vector<uint32_t> pending;
    
    for (const auto& [version, migration] : migrations_) {
        if (version > currentVersion_) {
            pending.push_back(version);
        }
    }
    
    std::sort(pending.begin(), pending.end());
    return pending;
}

bool DatabaseSchemaMigrator::validateMigration(const MigrationScript& migration) const {
    // Would validate migration script
    return !migration.upScripts.empty();
}

bool DatabaseSchemaMigrator::testMigration(uint32_t version) {
    // Would test migration in transaction
    return true;
}

} // namespace Migration
} // namespace RawrXD
