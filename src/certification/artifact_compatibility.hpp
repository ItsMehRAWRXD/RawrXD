// VAL-079: Artifact Compatibility
// Schema evolution and backward compatibility guarantees

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <optional>

namespace RawrXD {
namespace Certification {

// ============================================================================
// Schema Version Management
// ============================================================================

struct SchemaVersion {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    
    std::string ToString() const {
        return std::to_string(major) + "." + 
               std::to_string(minor) + "." + 
               std::to_string(patch);
    }
    
    static std::optional<SchemaVersion> FromString(const std::string& str);
    
    bool operator==(const SchemaVersion& other) const {
        return major == other.major && 
               minor == other.minor && 
               patch == other.patch;
    }
    
    bool operator<(const SchemaVersion& other) const {
        if (major != other.major) return major < other.major;
        if (minor != other.minor) return minor < other.minor;
        return patch < other.patch;
    }
    
    bool IsCompatibleWith(const SchemaVersion& other) const;
};

// ============================================================================
// Manifest Compatibility
// ============================================================================

struct ManifestCompatibility {
    SchemaVersion source_version;
    SchemaVersion target_version;
    bool readable;
    bool writable;
    bool lossless;
    std::vector<std::string> warnings;
    std::vector<std::string> required_migrations;
    
    bool IsCompatible() const { return readable && lossless; }
    std::string Serialize() const;
};

class ManifestCompatibilityChecker {
public:
    ManifestCompatibilityChecker();
    ~ManifestCompatibilityChecker();
    
    // Check compatibility between versions
    ManifestCompatibility CheckCompatibility(
        const SchemaVersion& from,
        const SchemaVersion& to
    ) const;
    
    // Verify old manifests remain readable
    bool VerifyBackwardCompatibility(
        const std::string& legacy_manifest_path
    ) const;
    
    // Verify schema migrations are deterministic
    bool VerifyMigrationDeterminism(
        const std::string& manifest_v1,
        const std::string& manifest_v2
    ) const;
    
    // Get supported version range
    struct VersionRange {
        SchemaVersion minimum;
        SchemaVersion maximum;
        std::vector<SchemaVersion> supported;
    };
    VersionRange GetSupportedVersions() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Runtime Version Identification
// ============================================================================

struct RuntimeVersionIdentity {
    std::string version_string;
    SchemaVersion schema_version;
    std::string commit_hash;
    std::string build_timestamp;
    
    // Compatibility flags
    bool can_read_manifests_from;
    SchemaVersion min_readable_manifest;
    SchemaVersion max_readable_manifest;
    
    std::string Serialize() const;
    static std::optional<RuntimeVersionIdentity> Load(const std::string& path);
};

class RuntimeVersionManager {
public:
    RuntimeVersionManager();
    ~RuntimeVersionManager();
    
    // Register runtime version
    void RegisterRuntimeVersion(const RuntimeVersionIdentity& identity);
    
    // Check if runtime can read manifest
    bool CanReadManifest(
        const RuntimeVersionIdentity& runtime,
        const SchemaVersion& manifest_version
    ) const;
    
    // Get compatible runtime versions for manifest
    std::vector<RuntimeVersionIdentity> GetCompatibleRuntimes(
        const SchemaVersion& manifest_version
    ) const;
    
    // Verify previous versions remain identifiable
    bool VerifyVersionIdentifiability() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Schema Migration
// ============================================================================

class SchemaMigrator {
public:
    SchemaMigrator();
    ~SchemaMigrator();
    
    // Migrate manifest from old to new schema
    std::string MigrateManifest(
        const std::string& manifest_json,
        const SchemaVersion& from_version,
        const SchemaVersion& to_version
    ) const;
    
    // Verify migration is deterministic
    bool VerifyDeterminism(
        const std::string& manifest_json,
        const SchemaVersion& from_version,
        const SchemaVersion& to_version
    ) const;
    
    // Get migration path
    std::vector<SchemaVersion> GetMigrationPath(
        const SchemaVersion& from_version,
        const SchemaVersion& to_version
    ) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Compatibility Test Suite
// ============================================================================

struct CompatibilityTestResult {
    std::string test_name;
    bool passed;
    SchemaVersion from_version;
    SchemaVersion to_version;
    std::string error_message;
    
    bool IsSuccess() const { return passed; }
};

class CompatibilityTestSuite {
public:
    CompatibilityTestSuite();
    ~CompatibilityTestSuite();
    
    // Run all compatibility tests
    std::vector<CompatibilityTestResult> RunAllTests();
    
    // Individual tests
    CompatibilityTestResult TestOldManifestReadable();
    CompatibilityTestResult TestPreviousRuntimeIdentifiable();
    CompatibilityTestResult TestSchemaMigrationDeterminism();
    CompatibilityTestResult TestForwardCompatibility();
    CompatibilityTestResult TestBackwardCompatibility();
    
    // Get summary
    struct Summary {
        int total_tests;
        int passed;
        int failed;
        bool all_compatible;
    };
    Summary GetSummary() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// C API
// ============================================================================

extern "C" {

// Schema version
typedef struct Val079SchemaVersion* Val079VersionHandle;

Val079VersionHandle val079_version_create(int major, int minor, int patch);
int val079_version_compare(Val079VersionHandle a, Val079VersionHandle b);
int val079_version_is_compatible(Val079VersionHandle a, Val079VersionHandle b);
void val079_version_destroy(Val079VersionHandle handle);

// Compatibility checker
typedef struct Val079CompatibilityChecker* Val079CheckerHandle;

Val079CheckerHandle val079_checker_create();
int val079_check_manifest_compatibility(
    Val079CheckerHandle handle,
    const char* manifest_path,
    int from_major, int from_minor, int from_patch,
    int to_major, int to_minor, int to_patch
);
const char* val079_get_compatibility_report(Val079CheckerHandle handle);
void val079_checker_destroy(Val079CheckerHandle handle);

// Migration
typedef struct Val079SchemaMigrator* Val079MigratorHandle;

Val079MigratorHandle val079_migrator_create();
const char* val079_migrate_manifest(
    Val079MigratorHandle handle,
    const char* manifest_json,
    int from_major, int from_minor, int from_patch,
    int to_major, int to_minor, int to_patch
);
void val079_migrator_destroy(Val079MigratorHandle handle);

} // extern "C"

} // namespace Certification
} // namespace RawrXD
