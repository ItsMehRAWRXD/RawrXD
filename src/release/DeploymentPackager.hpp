// RawrXD Deployment Packager
// Phase U.3: Deployment packaging and distribution
// Handles artifact packaging, distribution, and deployment automation

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>
#include <future>

namespace RawrXD {
namespace Release {

// Package format
enum class PackageFormat {
    TAR_GZ,         // Unix tarball
    ZIP,            // Windows zip
    DOCKER_IMAGE,   // Docker container
    OCI_BUNDLE,     // OCI-compliant bundle
    DEB,            // Debian package
    RPM,            // RedHat package
    MSI,            // Windows installer
    PKG,            // macOS package
    PORTABLE        // Portable archive
};

// Package contents
struct PackageContents {
    std::vector<std::string> binaries;
    std::vector<std::string> libraries;
    std::vector<std::string> configs;
    std::vector<std::string> docs;
    std::vector<std::string> scripts;
    std::map<std::string, std::string> metadata;
};

// Package specification
struct PackageSpec {
    std::string name;
    std::string version;
    PackageFormat format;
    PackageContents contents;
    std::vector<std::string> dependencies;
    std::map<std::string, std::string> platformTargets;  // platform -> arch
    std::string outputPath;
    bool includeSymbols{false};
    bool includeSource{false};
    bool compress{true};
};

// Packaged artifact
struct PackagedArtifact {
    std::string name;
    std::string path;
    std::string checksum;
    std::string signature;
    uint64_t size;
    PackageFormat format;
    std::chrono::system_clock::time_point createdAt;
    std::map<std::string, std::string> metadata;
};

// Distribution target
struct DistributionTarget {
    std::string name;
    std::string type;  // "s3", "github", "dockerhub", "artifactory", "ftp"
    std::string endpoint;
    std::map<std::string, std::string> credentials;
    std::map<std::string, std::string> config;
};

// Deployment configuration
struct DeploymentConfig {
    std::string environment;
    std::string version;
    std::vector<std::string> hosts;
    std::map<std::string, std::string> variables;
    std::map<std::string, std::string> secrets;
    bool rollingUpdate{true};
    uint32_t maxParallel{1};
    std::chrono::seconds healthCheckTimeout{30};
    std::chrono::seconds rollbackTimeout{300};
};

// Deployment status
enum class DeploymentStatus {
    PENDING,
    IN_PROGRESS,
    SUCCESS,
    FAILED,
    ROLLING_BACK,
    ROLLED_BACK
};

// Deployment result
struct DeploymentResult {
    std::string deploymentId;
    DeploymentStatus status;
    std::chrono::system_clock::time_point startedAt;
    std::chrono::system_clock::time_point completedAt;
    std::vector<std::string> successfulHosts;
    std::vector<std::string> failedHosts;
    std::string errorMessage;
    std::map<std::string, std::string> metadata;
};

// Deployment packager
class DeploymentPackager {
public:
    DeploymentPackager();
    ~DeploymentPackager();
    
    // Package creation
    bool createPackage(const PackageSpec& spec);
    bool createMultiPlatformPackage(const PackageSpec& spec, 
                                   const std::vector<std::string>& platforms);
    
    // Package inspection
    PackageContents inspectPackage(const std::string& packagePath) const;
    bool validatePackage(const std::string& packagePath);
    std::string calculateChecksum(const std::string& packagePath);
    bool signPackage(const std::string& packagePath, const std::string& keyPath);
    bool verifySignature(const std::string& packagePath, const std::string& publicKeyPath);
    
    // Package extraction
    bool extractPackage(const std::string& packagePath, const std::string& outputDir);
    bool extractFile(const std::string& packagePath, const std::string& fileName, 
                     const std::string& outputPath);
    
    // Distribution
    bool uploadToTarget(const PackagedArtifact& artifact, const DistributionTarget& target);
    bool downloadFromTarget(const std::string& artifactName, const DistributionTarget& target,
                           const std::string& outputPath);
    std::vector<PackagedArtifact> listArtifacts(const DistributionTarget& target) const;
    bool deleteArtifact(const std::string& artifactName, const DistributionTarget& target);
    
    // Deployment
    std::string startDeployment(const DeploymentConfig& config);
    bool cancelDeployment(const std::string& deploymentId);
    DeploymentResult getDeploymentResult(const std::string& deploymentId) const;
    std::vector<DeploymentResult> listDeployments() const;
    
    // Rollback
    bool rollbackDeployment(const std::string& deploymentId);
    bool rollbackToVersion(const std::string& environment, const std::string& version);
    
    // Health checks
    bool runDeploymentHealthCheck(const std::string& deploymentId);
    std::vector<std::string> getUnhealthyHosts(const std::string& deploymentId) const;
    
    // Configuration
    void addDistributionTarget(const DistributionTarget& target);
    void removeDistributionTarget(const std::string& targetName);
    std::vector<DistributionTarget> getDistributionTargets() const;
    
    // Templates
    void registerPackageTemplate(const std::string& name, const PackageSpec& spec);
    PackageSpec getPackageTemplate(const std::string& name) const;
    std::vector<std::string> listPackageTemplates() const;
    
    // Statistics
    struct PackagingStats {
        uint32_t packagesCreated;
        uint32_t packagesUploaded;
        uint32_t deploymentsStarted;
        uint32_t deploymentsSucceeded;
        uint32_t deploymentsFailed;
        uint32_t deploymentsRolledBack;
        uint64_t totalBytesPackaged;
        uint64_t totalBytesUploaded;
    };
    PackagingStats getStats() const;
    
    // Callbacks
    using ProgressCallback = std::function<void(const std::string& operation, 
                                                   uint64_t current, uint64_t total)>;
    using DeploymentCallback = std::function<void(const std::string& deploymentId,
                                                   DeploymentStatus status,
                                                   const std::map<std::string, std::string>& info)>;
    void setProgressCallback(ProgressCallback callback);
    void setDeploymentCallback(DeploymentCallback callback);

private:
    bool createTarGzPackage(const PackageSpec& spec);
    bool createZipPackage(const PackageSpec& spec);
    bool createDockerPackage(const PackageSpec& spec);
    bool createDebPackage(const PackageSpec& spec);
    bool createRpmPackage(const PackageSpec& spec);
    bool createMsiPackage(const PackageSpec& spec);
    
    void notifyProgress(const std::string& operation, uint64_t current, uint64_t total);
    void notifyDeployment(const std::string& deploymentId, DeploymentStatus status,
                         const std::map<std::string, std::string>& info);
    
    mutable std::mutex mutex_;
    std::map<std::string, DistributionTarget> targets_;
    std::map<std::string, PackageSpec> templates_;
    std::map<std::string, DeploymentResult> deployments_;
    ProgressCallback progressCallback_;
    DeploymentCallback deploymentCallback_;
    PackagingStats stats_{};
};

// Docker image builder
class DockerImageBuilder {
public:
    DockerImageBuilder();
    
    // Image building
    bool buildImage(const std::string& dockerfilePath, 
                   const std::string& tag,
                   const std::map<std::string, std::string>& buildArgs);
    bool buildMultiArchImage(const std::string& dockerfilePath,
                            const std::string& tag,
                            const std::vector<std::string>& platforms);
    
    // Image management
    bool tagImage(const std::string& sourceTag, const std::string& targetTag);
    bool pushImage(const std::string& tag, const std::string& registry);
    bool pullImage(const std::string& tag, const std::string& registry);
    bool removeImage(const std::string& tag);
    std::vector<std::string> listImages() const;
    
    // Image inspection
    std::map<std::string, std::string> inspectImage(const std::string& tag) const;
    uint64_t getImageSize(const std::string& tag) const;
    std::vector<std::string> getImageLayers(const std::string& tag) const;
    
    // Export/Import
    bool exportImage(const std::string& tag, const std::string& outputPath);
    bool importImage(const std::string& inputPath, const std::string& tag);
    
    // Registry operations
    bool loginToRegistry(const std::string& registry, 
                        const std::string& username, 
                        const std::string& password);
    bool logoutFromRegistry(const std::string& registry);
    std::vector<std::string> listRegistryTags(const std::string& imageName, 
                                               const std::string& registry) const;
};

// Kubernetes deployer
class KubernetesDeployer {
public:
    KubernetesDeployer();
    
    // Deployment
    bool applyManifest(const std::string& manifestPath, const std::string& namespace_ = "default");
    bool applyManifestString(const std::string& manifest, const std::string& namespace_ = "default");
    bool deleteManifest(const std::string& manifestPath, const std::string& namespace_ = "default");
    
    // Rollout
    bool rolloutDeployment(const std::string& deploymentName, 
                          const std::string& namespace_ = "default");
    bool rolloutStatus(const std::string& deploymentName,
                      const std::string& namespace_ = "default");
    bool rollbackDeployment(const std::string& deploymentName,
                           const std::string& namespace_ = "default");
    
    // Scaling
    bool scaleDeployment(const std::string& deploymentName,
                        int replicas,
                        const std::string& namespace_ = "default");
    int getDeploymentReplicas(const std::string& deploymentName,
                             const std::string& namespace_ = "default") const;
    
    // Health
    bool waitForDeployment(const std::string& deploymentName,
                          const std::string& namespace_ = "default",
                          std::chrono::seconds timeout = std::chrono::seconds{300});
    bool isDeploymentReady(const std::string& deploymentName,
                          const std::string& namespace_ = "default") const;
    std::vector<std::string> getPodStatuses(const std::string& deploymentName,
                                             const std::string& namespace_ = "default") const;
    
    // Configuration
    void setKubeconfig(const std::string& path);
    void setContext(const std::string& context);
    std::vector<std::string> getContexts() const;
    std::string getCurrentContext() const;
    
    // Secrets/ConfigMaps
    bool createSecret(const std::string& name,
                     const std::map<std::string, std::string>& data,
                     const std::string& namespace_ = "default");
    bool createConfigMap(const std::string& name,
                        const std::map<std::string, std::string>& data,
                        const std::string& namespace_ = "default");
};

// Cloud provider deployer
class CloudDeployer {
public:
    CloudDeployer();
    
    // AWS
    bool deployToECS(const DeploymentConfig& config, const std::string& clusterName);
    bool deployToEKS(const DeploymentConfig& config, const std::string& clusterName);
    bool deployToLambda(const std::string& functionName, const std::string& packagePath);
    
    // Azure
    bool deployToAKS(const DeploymentConfig& config, const std::string& clusterName);
    bool deployToContainerInstances(const DeploymentConfig& config, 
                                   const std::string& resourceGroup);
    
    // GCP
    bool deployToGKE(const DeploymentConfig& config, const std::string& clusterName);
    bool deployToCloudRun(const DeploymentConfig& config, const std::string& serviceName);
    
    // Credentials
    bool configureCredentials(const std::string& provider,
                             const std::map<std::string, std::string>& credentials);
};

} // namespace Release
} // namespace RawrXD
