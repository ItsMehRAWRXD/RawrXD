// VAL-079: Artifact Compatibility Implementation
// Schema evolution and backward compatibility

#include "artifact_compatibility.hpp"
#include <sstream>
#include <fstream>
#include <algorithm>

namespace RawrXD {
namespace Certification {

// ============================================================================
// SchemaVersion Implementation
// ============================================================================

bool SchemaVersion::IsCompatibleWith(const SchemaVersion& other) const {
    // Major version must match for compatibility
    if (major != other.major) return false;
    
    // This version must be >= other version
    if (minor < other.minor) return false;
    if (minor == other.minor && patch < other.patch) return false;
    
    return true;
}

bool SchemaVersion::IsNewerThan(const SchemaVersion& other) const {
    if (major > other.major) return true;
    if (major < other.major) return false;
    if (minor > other.minor) return true;
    if (minor < other.minor) return false;
    return patch > other.patch;
}

std::string SchemaVersion::ToString() const {
    std::stringstream ss;
    ss << major << "." << minor << "." << patch;
    if (!prerelease.empty()) {
        ss << "-" << prerelease;
    }
    if (!build.empty()) {
        ss << "+" << build;
    }
    return ss.str();
}

SchemaVersion SchemaVersion::FromString(const std::string& version_str) {
    SchemaVersion version;
    std::stringstream ss(version_str);
    char dot;
    ss >> version.major >> dot >> version.minor >> dot >> version.patch;
    return version;
}

// ============================================================================
// CompatibilityMatrix Implementation
// ============================================================================

CompatibilityMatrix::CompatibilityMatrix() {
    // Initialize with default compatibility rules
    AddRule({1, 0, 0}, {1, 0, 0}, CompatibilityLevel::FULL);
    AddRule({1, 0, 0}, {1, 1, 0}, CompatibilityLevel::BACKWARD);
    AddRule({1, 1, 0}, {1, 0, 0}, CompatibilityLevel::FORWARD);
}

void CompatibilityMatrix::AddRule(const SchemaVersion& from, 
                                   const SchemaVersion& to, 
                                   CompatibilityLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_[{from.ToString(), to.ToString()}] = level;
}

CompatibilityLevel CompatibilityMatrix::CheckCompatibility(
    const SchemaVersion& reader, 
    const SchemaVersion& writer
) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto key = std::make_pair(reader.ToString(), writer.ToString());
    auto it = rules_.find(key);
    if (it != rules_.end()) {
        return it->second;
    }
    
    // Default: check if versions are compatible
    if (reader.IsCompatibleWith(writer) && writer.IsCompatibleWith(reader)) {
        return CompatibilityLevel::FULL;
    } else if (reader.IsCompatibleWith(writer)) {
        return CompatibilityLevel::BACKWARD;
    } else if (writer.IsCompatibleWith(reader)) {
        return CompatibilityLevel::FORWARD;
    }
    
    return CompatibilityLevel::NONE;
}

bool CompatibilityMatrix::IsCompatible(const SchemaVersion& reader, 
                                        const SchemaVersion& writer) const {
    auto level = CheckCompatibility(reader, writer);
    return level != CompatibilityLevel::NONE;
}

// ============================================================================
// MigrationStep Implementation
// ============================================================================

bool MigrationStep::Execute(std::any& data) const {
    if (transform) {
        return transform(data);
    }
    return true;
}

// ============================================================================
// SchemaMigrator Implementation
// ============================================================================

class SchemaMigrator::Impl {
public:
    std::unordered_map<std::string, std::vector<MigrationStep>> migrations_;
    std::mutex mutex_;
};

SchemaMigrator::SchemaMigrator() : impl_(std::make_unique<Impl>()) {}
SchemaMigrator::~SchemaMigrator() = default;

SchemaMigrator& SchemaMigrator::Instance() {
    static SchemaMigrator instance;
    return instance;
}

void SchemaMigrator::RegisterMigration(const SchemaVersion& from, 
                                        const SchemaVersion& to,
                                        MigrationStep step) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::string key = from.ToString() + "->" + to.ToString();
    impl_->migrations_[key].push_back(step);
}

bool SchemaMigrator::Migrate(std::any& data, 
                              const SchemaVersion& from, 
                              const SchemaVersion& to) {
    if (from.ToString() == to.ToString()) {
        return true; // Nothing to do
    }
    
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::string key = from.ToString() + "->" + to.ToString();
    
    auto it = impl_->migrations_.find(key);
    if (it == impl_->migrations_.end()) {
        return false; // No migration path
    }
    
    for (const auto& step : it->second) {
        if (!step.Execute(data)) {
            return false;
        }
    }
    
    return true;
}

bool SchemaMigrator::CanMigrate(const SchemaVersion& from, 
                                 const SchemaVersion& to) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::string key = from.ToString() + "->" + to.ToString();
    return impl_->migrations_.find(key) != impl_->migrations_.end();
}

// ============================================================================
// VersionedArtifact Implementation
// ============================================================================

VersionedArtifact::VersionedArtifact(const std::string& path, 
                                      const SchemaVersion& version)
    : path_(path), version_(version) {}

bool VersionedArtifact::Load() {
    std::ifstream file(path_);
    if (!file) return false;
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    raw_data_ = buffer.str();
    
    return true;
}

bool VersionedArtifact::Save() const {
    std::ofstream file(path_);
    if (!file) return false;
    file << raw_data_;
    return true;
}

bool VersionedArtifact::MigrateTo(const SchemaVersion& target_version) {
    if (version_.ToString() == target_version.ToString()) {
        return true;
    }
    
    std::any data = raw_data_;
    if (SchemaMigrator::Instance().Migrate(data, version_, target_version)) {
        raw_data_ = std::any_cast<std::string>(data);
        version_ = target_version;
        return true;
    }
    
    return false;
}

// ============================================================================
// CompatibilityChecker Implementation
// ============================================================================

class CompatibilityChecker::Impl {
public:
    CompatibilityMatrix matrix_;
};

CompatibilityChecker::CompatibilityChecker() : impl_(std::make_unique<Impl>()) {}
CompatibilityChecker::~CompatibilityChecker() = default;

CompatibilityChecker& CompatibilityChecker::Instance() {
    static CompatibilityChecker instance;
    return instance;
}

CompatibilityReport CompatibilityChecker::CheckCompatibility(
    const VersionedArtifact& artifact,
    const SchemaVersion& target_version
) {
    CompatibilityReport report;
    report.artifact_version = artifact.GetVersion();
    report.target_version = target_version;
    
    auto level = impl_->matrix_.CheckCompatibility(
        artifact.GetVersion(), target_version);
    
    report.compatible = (level != CompatibilityLevel::NONE);
    report.level = level;
    
    if (!report.compatible) {
        report.issues.push_back("Versions are incompatible");
    }
    
    // Check if migration is possible
    if (!report.compatible) {
        if (SchemaMigrator::Instance().CanMigrate(
                artifact.GetVersion(), target_version)) {
            report.can_migrate = true;
            report.migration_path = artifact.GetVersion().ToString() + " -> " + 
                                   target_version.ToString();
        }
    }
    
    return report;
}

CompatibilityReport CompatibilityChecker::CheckFileCompatibility(
    const std::string& path,
    const SchemaVersion& expected_version
) {
    // Detect version from file
    SchemaVersion detected_version = DetectVersion(path);
    
    VersionedArtifact artifact(path, detected_version);
    return CheckCompatibility(artifact, expected_version);
}

SchemaVersion CompatibilityChecker::DetectVersion(const std::string& path) {
    std::ifstream file(path);
    if (!file) return SchemaVersion{0, 0, 0};
    
    // Try to read version from file header
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("version") != std::string::npos) {
            // Simple version extraction
            size_t pos = line.find('"');
            if (pos != std::string::npos) {
                size_t end = line.find('"', pos + 1);
                if (end != std::string::npos) {
                    return SchemaVersion::FromString(line.substr(pos + 1, end - pos - 1));
                }
            }
        }
    }
    
    return SchemaVersion{0, 0, 0};
}

std::string CompatibilityChecker::GenerateReport(const CompatibilityReport& report) const {
    std::stringstream ss;
    ss << "Compatibility Report\n";
    ss << "===================\n";
    ss << "Artifact version: " << report.artifact_version.ToString() << "\n";
    ss << "Target version: " << report.target_version.ToString() << "\n";
    ss << "Compatible: " << (report.compatible ? "YES" : "NO") << "\n";
    ss << "Level: " << static_cast<int>(report.level) << "\n";
    
    if (report.can_migrate) {
        ss << "Migration possible: YES\n";
        ss << "Migration path: " << report.migration_path << "\n";
    }
    
    if (!report.issues.empty()) {
        ss << "\nIssues:\n";
        for (const auto& issue : report.issues) {
            ss << "  - " << issue << "\n";
        }
    }
    
    return ss.str();
}

// ============================================================================
// BackwardCompatibilityLayer Implementation
// ============================================================================

class BackwardCompatibilityLayer::Impl {
public:
    std::unordered_map<std::string, std::function<std::any(const std::any&)>> adapters_;
    std::mutex mutex_;
};

BackwardCompatibilityLayer::BackwardCompatibilityLayer() : impl_(std::make_unique<Impl>()) {}
BackwardCompatibilityLayer::~BackwardCompatibilityLayer() = default;

BackwardCompatibilityLayer& BackwardCompatibilityLayer::Instance() {
    static BackwardCompatibilityLayer instance;
    return instance;
}

void BackwardCompatibilityLayer::RegisterAdapter(
    const SchemaVersion& version,
    std::function<std::any(const std::any&)> adapter
) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->adapters_[version.ToString()] = adapter;
}

std::any BackwardCompatibilityLayer::Adapt(const std::any& data, 
                                            const SchemaVersion& from_version) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->adapters_.find(from_version.ToString());
    if (it != impl_->adapters_.end()) {
        return it->second(data);
    }
    return data;
}

bool BackwardCompatibilityLayer::CanAdapt(const SchemaVersion& version) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->adapters_.find(version.ToString()) != impl_->adapters_.end();
}

} // namespace Certification
} // namespace RawrXD
