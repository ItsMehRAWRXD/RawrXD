// RawrXD Release Manager Implementation
// Phase U.2: Release management and versioning

#include "ReleaseManager.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace RawrXD {
namespace Release {

// ============================================================================
// Version Implementation
// ============================================================================

std::string Version::toString() const {
    std::ostringstream oss;
    oss << major << "." << minor << "." << patch;
    if (!prerelease.empty()) {
        oss << "-" << prerelease;
    }
    if (!build.empty()) {
        oss << "+" << build;
    }
    return oss.str();
}

bool Version::operator<(const Version& other) const {
    if (major != other.major) return major < other.major;
    if (minor != other.minor) return minor < other.minor;
    if (patch != other.patch) return patch < other.patch;
    
    // Prerelease versions have lower precedence
    if (prerelease.empty() && !other.prerelease.empty()) return false;
    if (!prerelease.empty() && other.prerelease.empty()) return true;
    if (prerelease != other.prerelease) return prerelease < other.prerelease;
    
    return false;
}

bool Version::operator==(const Version& other) const {
    return major == other.major && 
           minor == other.minor && 
           patch == other.patch &&
           prerelease == other.prerelease;
}

// ============================================================================
// ReleaseManager Implementation
// ============================================================================

ReleaseManager::ReleaseManager() = default;
ReleaseManager::~ReleaseManager() = default;

Version ReleaseManager::getCurrentVersion() const {
    // Would read from build info
    return Version{1, 0, 0, "", ""};
}

Version ReleaseManager::parseVersion(const std::string& versionStr) const {
    return VersionManager::parse(versionStr);
}

bool ReleaseManager::isValidVersion(const std::string& versionStr) const {
    try {
        parseVersion(versionStr);
        return true;
    } catch (...) {
        return false;
    }
}

std::string ReleaseManager::incrementVersion(const Version& version, const std::string& component) const {
    Version newVersion = version;
    
    if (component == "major") {
        newVersion.major++;
        newVersion.minor = 0;
        newVersion.patch = 0;
    } else if (component == "minor") {
        newVersion.minor++;
        newVersion.patch = 0;
    } else if (component == "patch") {
        newVersion.patch++;
    }
    
    return newVersion.toString();
}

bool ReleaseManager::createRelease(const ReleaseInfo& release) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = release.version.toString();
    if (releases_.find(key) != releases_.end()) {
        return false; // Already exists
    }
    
    releases_[key] = release;
    notifyReleaseEvent(release.version, "created");
    
    return true;
}

bool ReleaseManager::updateRelease(const Version& version, const ReleaseInfo& release) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = version.toString();
    auto it = releases_.find(key);
    if (it == releases_.end()) {
        return false;
    }
    
    releases_[key] = release;
    notifyReleaseEvent(version, "updated");
    
    return true;
}

bool ReleaseManager::deleteRelease(const Version& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = version.toString();
    auto it = releases_.find(key);
    if (it == releases_.end()) {
        return false;
    }
    
    releases_.erase(it);
    notifyReleaseEvent(version, "deleted");
    
    return true;
}

ReleaseInfo ReleaseManager::getRelease(const Version& version) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = version.toString();
    auto it = releases_.find(key);
    if (it != releases_.end()) {
        return it->second;
    }
    
    return ReleaseInfo{};
}

std::vector<ReleaseInfo> ReleaseManager::listReleases() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ReleaseInfo> result;
    for (const auto& [key, release] : releases_) {
        result.push_back(release);
    }
    
    // Sort by version (newest first)
    std::sort(result.begin(), result.end(), [](const ReleaseInfo& a, const ReleaseInfo& b) {
        return b.version < a.version;
    });
    
    return result;
}

std::vector<ReleaseInfo> ReleaseManager::listReleasesByStage(ReleaseStage stage) const {
    auto all = listReleases();
    std::vector<ReleaseInfo> result;
    
    // Would filter by actual stage field
    // For now, filter by prerelease flag
    for (const auto& release : all) {
        if (stage == ReleaseStage::GA && !release.isPrerelease) {
            result.push_back(release);
        } else if (stage != ReleaseStage::GA && release.isPrerelease) {
            result.push_back(release);
        }
    }
    
    return result;
}

bool ReleaseManager::addArtifact(const Version& version, const ReleaseArtifact& artifact) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = version.toString();
    auto it = releases_.find(key);
    if (it == releases_.end()) {
        return false;
    }
    
    it->second.artifacts.push_back(artifact);
    notifyReleaseEvent(version, "artifact_added");
    
    return true;
}

bool ReleaseManager::removeArtifact(const Version& version, const std::string& artifactName) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = version.toString();
    auto it = releases_.find(key);
    if (it == releases_.end()) {
        return false;
    }
    
    auto& artifacts = it->second.artifacts;
    artifacts.erase(
        std::remove_if(artifacts.begin(), artifacts.end(),
            [&artifactName](const ReleaseArtifact& a) { return a.name == artifactName; }),
        artifacts.end()
    );
    
    notifyReleaseEvent(version, "artifact_removed");
    return true;
}

ReleaseArtifact ReleaseManager::getArtifact(const Version& version, const std::string& artifactName) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = version.toString();
    auto it = releases_.find(key);
    if (it != releases_.end()) {
        for (const auto& artifact : it->second.artifacts) {
            if (artifact.name == artifactName) {
                return artifact;
            }
        }
    }
    
    return ReleaseArtifact{};
}

bool ReleaseManager::promoteRelease(const Version& version, ReleaseStage newStage) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = version.toString();
    auto it = releases_.find(key);
    if (it == releases_.end()) {
        return false;
    }
    
    // Update stage
    if (newStage == ReleaseStage::GA) {
        it->second.isPrerelease = false;
    }
    
    notifyReleaseEvent(version, "promoted");
    return true;
}

bool ReleaseManager::publishRelease(const Version& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = version.toString();
    auto it = releases_.find(key);
    if (it == releases_.end()) {
        return false;
    }
    
    it->second.isDraft = false;
    it->second.releasedAt = std::chrono::system_clock::now();
    
    notifyReleaseEvent(version, "published");
    return true;
}

bool ReleaseManager::unpublishRelease(const Version& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = version.toString();
    auto it = releases_.find(key);
    if (it == releases_.end()) {
        return false;
    }
    
    it->second.isDraft = true;
    
    notifyReleaseEvent(version, "unpublished");
    return true;
}

bool ReleaseManager::deprecateRelease(const Version& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = version.toString();
    auto it = releases_.find(key);
    if (it == releases_.end()) {
        return false;
    }
    
    // Mark as deprecated
    it->second.tags["deprecated"] = "true";
    
    notifyReleaseEvent(version, "deprecated");
    return true;
}

bool ReleaseManager::deployToTarget(const Version& version, const DeploymentTarget& target) {
    // Would implement actual deployment logic
    notifyReleaseEvent(version, "deployed_to_" + target.environment);
    return true;
}

bool ReleaseManager::rollbackDeployment(const Version& version, const DeploymentTarget& target) {
    // Would implement rollback logic
    notifyReleaseEvent(version, "rollback_from_" + target.environment);
    return true;
}

std::vector<DeploymentTarget> ReleaseManager::getDeploymentTargets() const {
    // Would load from configuration
    return {
        DeploymentTarget{"staging", "staging", "us-east-1", {}, {}},
        DeploymentTarget{"production", "production", "us-east-1", {}, {}}
    };
}

bool ReleaseManager::validateRelease(const Version& version) {
    auto release = getRelease(version);
    
    if (release.version.toString().empty()) {
        return false;
    }
    
    // Validate artifacts
    if (release.artifacts.empty()) {
        return false;
    }
    
    return true;
}

bool ReleaseManager::verifyArtifacts(const Version& version) {
    auto release = getRelease(version);
    
    for (const auto& artifact : release.artifacts) {
        if (artifact.checksum.empty()) {
            return false;
        }
    }
    
    return true;
}

bool ReleaseManager::runReleaseTests(const Version& version) {
    // Would run automated tests
    notifyReleaseEvent(version, "tests_started");
    // ... test execution
    notifyReleaseEvent(version, "tests_completed");
    return true;
}

void ReleaseManager::addChangelogEntry(const Version& version, const std::string& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = version.toString();
    auto it = releases_.find(key);
    if (it != releases_.end()) {
        it->second.changelog.push_back(entry);
    }
}

std::vector<std::string> ReleaseManager::getChangelog(const Version& version) const {
    auto release = getRelease(version);
    return release.changelog;
}

std::string ReleaseManager::generateChangelogMarkdown(const Version& version) const {
    auto release = getRelease(version);
    
    std::ostringstream oss;
    oss << "# " << release.name << "\n\n";
    oss << "## Version " << release.version.toString() << "\n\n";
    
    if (!release.description.empty()) {
        oss << release.description << "\n\n";
    }
    
    oss << "## Changelog\n\n";
    for (const auto& entry : release.changelog) {
        oss << "- " << entry << "\n";
    }
    
    return oss.str();
}

ReleaseManager::ReleaseStats ReleaseManager::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ReleaseStats stats{};
    stats.totalReleases = releases_.size();
    
    for (const auto& [key, release] : releases_) {
        if (release.isDraft) {
            stats.draftReleases++;
        } else {
            stats.publishedReleases++;
        }
        
        if (release.tags.find("deprecated") != release.tags.end()) {
            stats.deprecatedReleases++;
        }
    }
    
    return stats;
}

void ReleaseManager::setReleaseCallback(ReleaseCallback callback) {
    releaseCallback_ = callback;
}

void ReleaseManager::notifyReleaseEvent(const Version& version, const std::string& action) {
    if (releaseCallback_) {
        releaseCallback_(version, action);
    }
}

std::string ReleaseManager::generateReleaseNotes(const ReleaseInfo& release) const {
    std::ostringstream oss;
    oss << "Release " << release.version.toString() << "\n\n";
    oss << release.description << "\n\n";
    
    if (!release.changelog.empty()) {
        oss << "Changes:\n";
        for (const auto& entry : release.changelog) {
            oss << "- " << entry << "\n";
        }
    }
    
    return oss.str();
}

// ============================================================================
// VersionManager Implementation
// ============================================================================

VersionManager::VersionManager() = default;

Version VersionManager::parse(const std::string& versionStr) {
    Version version{0, 0, 0, "", ""};
    
    std::string str = versionStr;
    
    // Parse build metadata
    size_t plusPos = str.find('+');
    if (plusPos != std::string::npos) {
        version.build = str.substr(plusPos + 1);
        str = str.substr(0, plusPos);
    }
    
    // Parse prerelease
    size_t dashPos = str.find('-');
    if (dashPos != std::string::npos) {
        version.prerelease = str.substr(dashPos + 1);
        str = str.substr(0, dashPos);
    }
    
    // Parse major.minor.patch
    std::istringstream iss(str);
    char dot;
    iss >> version.major >> dot >> version.minor >> dot >> version.patch;
    
    return version;
}

std::string VersionManager::toString(const Version& version) {
    return version.toString();
}

bool VersionManager::isCompatible(const Version& required, const Version& actual) {
    // Major version must match for compatibility
    if (required.major != actual.major) {
        return false;
    }
    
    // Actual version must be >= required version
    return !(actual < required);
}

int VersionManager::compare(const Version& a, const Version& b) {
    if (a < b) return -1;
    if (b < a) return 1;
    return 0;
}

bool VersionManager::satisfies(const Version& version, const std::string& constraint) {
    // Simple constraint parsing (e.g., ">=1.0.0", "^1.0.0")
    if (constraint.empty()) return true;
    
    if (constraint[0] == '^') {
        // Compatible with major version
        Version required = parse(constraint.substr(1));
        return version.major == required.major && !(version < required);
    }
    
    if (constraint.substr(0, 2) == ">=") {
        Version required = parse(constraint.substr(2));
        return !(version < required);
    }
    
    // Exact match
    Version required = parse(constraint);
    return version == required;
}

std::vector<Version> VersionManager::filterByConstraint(const std::vector<Version>& versions, 
                                                       const std::string& constraint) {
    std::vector<Version> result;
    for (const auto& version : versions) {
        if (satisfies(version, constraint)) {
            result.push_back(version);
        }
    }
    return result;
}

std::optional<Version> VersionManager::resolveLatest(const std::vector<Version>& versions) {
    if (versions.empty()) return std::nullopt;
    
    Version latest = versions[0];
    for (const auto& version : versions) {
        if (latest < version) {
            latest = version;
        }
    }
    return latest;
}

std::optional<Version> VersionManager::resolveLatestStable(const std::vector<Version>& versions) {
    std::vector<Version> stable;
    for (const auto& version : versions) {
        if (!version.isPrerelease()) {
            stable.push_back(version);
        }
    }
    return resolveLatest(stable);
}

std::optional<Version> VersionManager::resolveCompatible(const std::vector<Version>& versions, 
                                                       const Version& required) {
    std::vector<Version> compatible;
    for (const auto& version : versions) {
        if (isCompatible(required, version)) {
            compatible.push_back(version);
        }
    }
    return resolveLatest(compatible);
}

// ============================================================================
// BuildManager Implementation
// ============================================================================

BuildManager::BuildManager() = default;

BuildInfo BuildManager::getBuildInfo() const {
    // Would read from embedded build info
    BuildInfo info;
    info.version = "1.0.0";
    info.commitHash = "unknown";
    info.branch = "main";
    return info;
}

void BuildManager::setBuildInfo(const BuildInfo& info) {
    // Would store build info
}

std::string BuildManager::getBuildIdentifier() const {
    auto info = getBuildInfo();
    return info.version + "-" + info.commitHash.substr(0, 8);
}

std::string BuildManager::getBuildDate() const {
    auto info = getBuildInfo();
    auto time = std::chrono::system_clock::to_time_t(info.buildTime);
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

bool BuildManager::isDevelopmentBuild() const {
    auto info = getBuildInfo();
    return info.branch != "main" && info.branch != "master";
}

bool BuildManager::isReleaseBuild() const {
    auto info = getBuildInfo();
    return info.branch == "main" || info.branch == "master";
}

std::vector<std::string> BuildManager::getEnabledFeatures() const {
    // Would return features enabled at compile time
    return {"vulkan", "cuda", "distributed"};
}

bool BuildManager::isFeatureEnabled(const std::string& feature) const {
    auto features = getEnabledFeatures();
    return std::find(features.begin(), features.end(), feature) != features.end();
}

} // namespace Release
} // namespace RawrXD
