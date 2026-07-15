// RawrXD Configuration Migrator
// Phase Y.2: Configuration migration utilities
// Handles migration of settings between versions and formats

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Migration {

// Configuration version
struct ConfigVersion {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    
    std::string toString() const;
    bool operator<(const ConfigVersion& other) const;
    bool operator==(const ConfigVersion& other) const;
};

// Configuration entry
struct ConfigEntry {
    std::string key;
    std::string value;
    std::string type;  // "string", "int", "float", "bool", "array", "object"
    std::string description;
    bool isDeprecated{false};
    std::string replacementKey;
    ConfigVersion deprecatedIn;
    ConfigVersion removedIn;
};

// Migration rule
struct MigrationRule {
    ConfigVersion fromVersion;
    ConfigVersion toVersion;
    std::function<void(std::map<std::string, std::string>&)> transform;
    std::vector<std::string> affectedKeys;
    std::string description;
};

// Configuration schema
struct ConfigSchema {
    ConfigVersion version;
    std::map<std::string, ConfigEntry> entries;
    std::vector<std::string> requiredKeys;
    std::map<std::string, std::vector<std::string>> dependencies;
};

// Migration result
struct ConfigMigrationResult {
    bool success;
    ConfigVersion fromVersion;
    ConfigVersion toVersion;
    std::vector<std::string> migratedKeys;
    std::vector<std::string> deprecatedKeys;
    std::vector<std::string> removedKeys;
    std::vector<std::string> addedKeys;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

// Configuration migrator
class ConfigMigrator {
public:
    ConfigMigrator();
    ~ConfigMigrator();
    
    // Schema management
    void registerSchema(const ConfigSchema& schema);
    void registerMigrationRule(const MigrationRule& rule);
    
    // Version detection
    ConfigVersion detectVersion(const std::map<std::string, std::string>& config) const;
    bool isVersionSupported(const ConfigVersion& version) const;
    
    // Migration
    ConfigMigrationResult migrate(const std::map<std::string, std::string>& config,
                                  const ConfigVersion& targetVersion);
    ConfigMigrationResult migrate(const std::string& configPath,
                                  const ConfigVersion& targetVersion);
    
    // Validation
    bool validateConfig(const std::map<std::string, std::string>& config,
                       const ConfigVersion& version) const;
    std::vector<std::string> getValidationErrors(const std::map<std::string, std::string>& config,
                                                  const ConfigVersion& version) const;
    
    // Utilities
    std::map<std::string, std::string> getDefaults(const ConfigVersion& version) const;
    std::vector<std::string> getDeprecatedKeys(const ConfigVersion& version) const;
    std::vector<std::string> getRemovedKeys(const ConfigVersion& fromVersion,
                                            const ConfigVersion& toVersion) const;
    std::map<std::string, std::string> getKeyChanges(const ConfigVersion& fromVersion,
                                                     const ConfigVersion& toVersion) const;
    
    // Import/Export
    bool exportToJSON(const std::map<std::string, std::string>& config,
                     const std::string& outputPath) const;
    std::map<std::string, std::string> importFromJSON(const std::string& inputPath) const;
    bool exportToYAML(const std::map<std::string, std::string>& config,
                     const std::string& outputPath) const;
    std::map<std::string, std::string> importFromYAML(const std::string& inputPath) const;

private:
    std::map<ConfigVersion, ConfigSchema> schemas_;
    std::vector<MigrationRule> migrationRules_;
    
    ConfigMigrationResult applyMigrations(std::map<std::string, std::string>& config,
                                          const ConfigVersion& fromVersion,
                                          const ConfigVersion& toVersion);
};

// Environment migrator
class EnvironmentMigrator {
public:
    EnvironmentMigrator();
    
    // Environment variable migration
    struct EnvMigration {
        std::string oldVar;
        std::string newVar;
        std::string defaultValue;
        bool required;
        std::string description;
    };
    
    void registerEnvMigration(const EnvMigration& migration);
    bool migrateEnvironment();
    std::vector<std::string> getUnsetRequiredVars() const;
    std::map<std::string, std::string> getMigratedEnvironment() const;
    
    // Path migration
    bool migratePaths(const std::string& oldBasePath, const std::string& newBasePath);
    bool migrateDataDirectory(const std::string& oldPath, const std::string& newPath);
    bool migrateCacheDirectory(const std::string& oldPath, const std::string& newPath);
    bool migrateLogDirectory(const std::string& oldPath, const std::string& newPath);

private:
    std::vector<EnvMigration> envMigrations_;
};

// Database schema migrator
class DatabaseSchemaMigrator {
public:
    DatabaseSchemaMigrator();
    
    // Schema version
    struct SchemaVersion {
        uint32_t version;
        std::string description;
        std::chrono::system_clock::time_point appliedAt;
    };
    
    // Migration script
    struct MigrationScript {
        uint32_t fromVersion;
        uint32_t toVersion;
        std::string description;
        std::vector<std::string> upScripts;
        std::vector<std::string> downScripts;
        bool isReversible;
    };
    
    void registerMigration(const MigrationScript& migration);
    bool migrateToVersion(uint32_t targetVersion);
    bool rollbackToVersion(uint32_t targetVersion);
    
    uint32_t getCurrentVersion() const;
    std::vector<SchemaVersion> getMigrationHistory() const;
    std::vector<uint32_t> getPendingMigrations() const;
    
    bool validateMigration(const MigrationScript& migration) const;
    bool testMigration(uint32_t version);

private:
    std::map<uint32_t, MigrationScript> migrations_;
    uint32_t currentVersion_{0};
};

} // namespace Migration
} // namespace RawrXD
