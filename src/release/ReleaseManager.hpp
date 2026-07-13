// RawrXD Release Manager
// Phase U.2: Release management and versioning
// Handles release lifecycle from build to deployment

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>

namespace RawrXD {
namespace Release {

// Release version
struct Version {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    std::string prerelease;  // e.g., "alpha", "beta", "rc1"
    std::string build;       // Build metadata
    
    std::string toString() const;
    bool isPrerelease() const { return !prerelease.empty(); }
    bool operator<(const Version& other) const;
    bool operator==(const Version& other) const;
};

// Release artifact
struct ReleaseArtifact {
    std::string name;
    std::string type;  // "binary", "docker", "package", "source"
    std::string path;
    std::string checksum;
    std::string signature;
    uint64_t size;
    std::chrono::system_clock::time_point createdAt;
    std::map<std::string, std::string> metadata;
};

// Release information
struct ReleaseInfo {
    Version version;
    std::string name;
    std::string description;
    std::vector<std::string> changelog;
    std::vector<ReleaseArtifact> artifacts;
    std::chrono::system_clock::time_point releasedAt;
    std::string releasedBy;
    bool isDraft{false};
    bool isPrerelease{false};
    std::map<std::string, std::string> tags;
};

// Release stage
enum class ReleaseStage {
    DEVELOPMENT,    // Active development
    ALPHA,          // Internal testing
    BETA,           // External testing
    RC,             // Release candidate
    GA,             // General availability
    MAINTENANCE,    // Maintenance mode
    DEPRECATED      // Deprecated
};

// Deployment target
struct DeploymentTarget {
    std::string name;
    std::string environment;  // "development", "staging", "production"
    std::string region;
    std::vector<std::string> hosts;
    std::map<std::string, std::string> config;
};

// Release manager
class ReleaseManager {
public:
    ReleaseManager();
    ~ReleaseManager();
    
    // Version management
    Version getCurrentVersion() const;
    Version parseVersion(const std::string& versionStr) const;
    bool isValidVersion(const std::string& versionStr) const;
    std::string incrementVersion(const Version& version, const std::string& component) const;
    
    // Release creation
    bool createRelease(const ReleaseInfo& release);
    bool updateRelease(const Version& version, const ReleaseInfo& release);
    bool deleteRelease(const Version& version);
    ReleaseInfo getRelease(const Version& version) const;
    std::vector<ReleaseInfo> listReleases() const;
    std::vector<ReleaseInfo> listReleasesByStage(ReleaseStage stage) const;
    
    // Artifact management
    bool addArtifact(const Version& version, const ReleaseArtifact& artifact);
    bool removeArtifact(const Version& version, const std::string& artifactName);
    ReleaseArtifact getArtifact(const Version& version, const std::string& artifactName) const;
    
    // Release lifecycle
    bool promoteRelease(const Version& version, ReleaseStage newStage);
    bool publishRelease(const Version& version);
    bool unpublishRelease(const Version& version);
    bool deprecateRelease(const Version& version);
    
    // Deployment
    bool deployToTarget(const Version& version, const DeploymentTarget& target);
    bool rollbackDeployment(const Version& version, const DeploymentTarget& target);
    std::vector<DeploymentTarget> getDeploymentTargets() const;
    
    // Validation
    bool validateRelease(const Version& version);
    bool verifyArtifacts(const Version& version);
    bool runReleaseTests(const Version& version);
    
    // Changelog
    void addChangelogEntry(const Version& version, const std::string& entry);
    std::vector<std::string> getChangelog(const Version& version) const;
    std::string generateChangelogMarkdown(const Version& version) const;
    
    // Statistics
    struct ReleaseStats {
        uint32_t totalReleases;
        uint32_t draftReleases;
        uint32_t publishedReleases;
        uint32_t deprecatedReleases;
        std::map<ReleaseStage, uint32_t> byStage;
        std::map<std::string, uint32_t> byMonth;
    };
    ReleaseStats getStats() const;
    
    // Callbacks
    using ReleaseCallback = std::function<void(const Version&, const std::string& action)>;
    void setReleaseCallback(ReleaseCallback callback);

private:
    void notifyReleaseEvent(const Version& version, const std::string& action);
    std::string generateReleaseNotes(const ReleaseInfo& release) const;
    
    mutable std::mutex mutex_;
    std::map<std::string, ReleaseInfo> releases_;
    ReleaseCallback releaseCallback_;
};

// Version manager
class VersionManager {
public:
    VersionManager();
    
    // Semantic versioning
    static Version parse(const std::string& versionStr);
    static std::string toString(const Version& version);
    static bool isCompatible(const Version& required, const Version& actual);
    static int compare(const Version& a, const Version& b);
    
    // Version constraints
    static bool satisfies(const Version& version, const std::string& constraint);
    static std::vector<Version> filterByConstraint(const std::vector<Version>& versions, 
                                                     const std::string& constraint);
    
    // Version resolution
    static std::optional<Version> resolveLatest(const std::vector<Version>& versions);
    static std::optional<Version> resolveLatestStable(const std::vector<Version>& versions);
    static std::optional<Version> resolveCompatible(const std::vector<Version>& versions, 
                                                      const Version& required);
};

// Build information
struct BuildInfo {
    std::string version;
    std::string commitHash;
    std::string branch;
    std::string buildNumber;
    std::chrono::system_clock::time_point buildTime;
    std::string builder;
    std::map<std::string, std::string> metadata;
};

// Build manager
class BuildManager {
public:
    BuildManager();
    
    // Build information
    BuildInfo getBuildInfo() const;
    void setBuildInfo(const BuildInfo& info);
    
    // Build metadata
    std::string getBuildIdentifier() const;
    std::string getBuildDate() const;
    bool isDevelopmentBuild() const;
    bool isReleaseBuild() const;
    
    // Feature flags from build
    std::vector<std::string> getEnabledFeatures() const;
    bool isFeatureEnabled(const std::string& feature) const;
};

} // namespace Release
} // namespace RawrXD
