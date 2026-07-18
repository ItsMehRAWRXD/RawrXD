/**
 * ContainerOrchestrator.hpp
 *
 * Phase K Batch 1/5: Container Orchestration
 *
 * Docker and Kubernetes integration for containerized deployment
 * with auto-scaling, service discovery, and health management.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <chrono>

namespace Deployment {

// ============================================================================
// Forward Declarations
// ============================================================================

class Container;
class ContainerImage;
class ContainerRegistry;
class KubernetesClient;
class Pod;
class Deployment;
class Service;

// ============================================================================
// Container Runtime
// ============================================================================

enum class ContainerRuntime {
    DOCKER,
    CONTAINERD,
    PODMAN,
    CRIO
};

// ============================================================================
// Container State
// ============================================================================

enum class ContainerState {
    CREATED,
    RUNNING,
    PAUSED,
    RESTARTING,
    REMOVING,
    EXITED,
    DEAD,
    UNKNOWN
};

std::string ContainerStateToString(ContainerState state);

// ============================================================================
// Container Configuration
// ============================================================================

/**
 * Container configuration.
 */
struct ContainerConfig {
    std::string image;
    std::string name;
    std::vector<std::string> command;
    std::vector<std::string> entrypoint;
    std::map<std::string, std::string> environment;
    std::map<std::string, std::string> labels;
    std::vector<std::pair<std::string, std::string>> volumes;
    std::vector<std::pair<uint16_t, uint16_t>> ports;
    std::vector<std::string> networks;
    std::string restartPolicy;
    std::optional<uint64_t> memoryLimit;
    std::optional<double> cpuLimit;
    std::optional<uint64_t> shmSize;
    bool autoRemove;
    bool privileged;
    std::string user;
    std::string workingDir;
    std::string hostname;
    std::vector<std::string> dns;
    std::vector<std::string> extraHosts;
    std::map<std::string, std::string> healthCheck;
};

// ============================================================================
// Container
// ============================================================================

/**
 * Container instance.
 */
class Container {
public:
    struct Stats {
        uint64_t cpuUsage;
        uint64_t memoryUsage;
        uint64_t memoryLimit;
        double memoryPercent;
        uint64_t networkRx;
        uint64_t networkTx;
        uint64_t blockRead;
        uint64_t blockWrite;
        uint32_t pids;
        std::chrono::system_clock::time_point timestamp;
    };
    
    struct Info {
        std::string id;
        std::string name;
        std::string image;
        ContainerState state;
        int exitCode;
        std::string error;
        std::chrono::system_clock::time_point created;
        std::chrono::system_clock::time_point started;
        std::chrono::system_clock::time_point finished;
        std::string ipAddress;
        std::string macAddress;
        std::vector<std::pair<uint16_t, uint16_t>> ports;
        std::map<std::string, std::string> labels;
    };
    
    explicit Container(const std::string& id);
    
    // Lifecycle
    bool Start();
    bool Stop(uint32_t timeoutSeconds = 10);
    bool Restart(uint32_t timeoutSeconds = 10);
    bool Pause();
    bool Unpause();
    bool Kill(int signal = 9);
    bool Remove(bool force = false, bool removeVolumes = false);
    
    // Info
    Info GetInfo() const;
    Stats GetStats() const;
    std::vector<Stats> GetStatsHistory() const;
    
    // Logs
    std::string GetLogs(uint32_t tail = 100) const;
    std::string GetLogsSince(std::chrono::system_clock::time_point since) const;
    void FollowLogs(std::function<void(const std::string&)> callback) const;
    
    // Exec
    std::string Exec(const std::string& command) const;
    std::string Exec(const std::vector<std::string>& command) const;
    
    // Files
    bool CopyTo(const std::string& sourcePath, const std::string& containerPath);
    bool CopyFrom(const std::string& containerPath, const std::string& destinationPath);
    
    // Accessors
    std::string GetId() const { return id_; }
    bool IsRunning() const;
    
private:
    std::string id_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Container Image
// ============================================================================

/**
 * Container image.
 */
class ContainerImage {
public:
    struct Config {
        std::string dockerfile;
        std::string context;
        std::map<std::string, std::string> buildArgs;
        std::vector<std::string> tags;
        std::vector<std::string> labels;
        bool noCache;
        bool pull;
        std::string target;
    };
    
    struct Info {
        std::string id;
        std::vector<std::string> tags;
        std::vector<std::string> digests;
        uint64_t size;
        std::chrono::system_clock::time_point created;
        std::map<std::string, std::string> labels;
    };
    
    explicit ContainerImage(const std::string& name);
    
    // Build
    bool Build(const Config& config);
    bool Build(const std::string& dockerfilePath);
    
    // Pull/Push
    bool Pull(const std::string& registry = "");
    bool Push(const std::string& registry = "");
    
    // Tag
    bool Tag(const std::string& newTag);
    
    // Info
    Info GetInfo() const;
    bool Exists() const;
    
    // Export/Import
    bool Export(const std::string& tarPath);
    bool Import(const std::string& tarPath);
    
    // History
    std::vector<std::map<std::string, std::string>> GetHistory() const;
    
    // Accessors
    std::string GetName() const { return name_; }
    
private:
    std::string name_;
};

// ============================================================================
// Container Registry
// ============================================================================

/**
 * Container registry client.
 */
class ContainerRegistry {
public:
    struct Config {
        std::string url;
        std::string username;
        std::string password;
        std::string token;
        bool insecure;
    };
    
    struct Repository {
        std::string name;
        uint64_t size;
        std::chrono::system_clock::time_point lastUpdated;
        std::vector<std::string> tags;
    };
    
    struct Manifest {
        std::string digest;
        std::vector<std::string> tags;
        uint64_t size;
        std::chrono::system_clock::time_point created;
        std::map<std::string, std::string> labels;
    };
    
    explicit ContainerRegistry(const Config& config);
    
    // Authentication
    bool Login();
    bool Logout();
    
    // Repositories
    std::vector<Repository> ListRepositories();
    std::optional<Repository> GetRepository(const std::string& name);
    bool DeleteRepository(const std::string& name);
    
    // Tags
    std::vector<std::string> ListTags(const std::string& repository);
    bool DeleteTag(const std::string& repository, const std::string& tag);
    bool Retag(const std::string& repository, const std::string& oldTag,
               const std::string& newTag);
    
    // Manifests
    std::optional<Manifest> GetManifest(const std::string& repository,
                                          const std::string& tag);
    bool DeleteManifest(const std::string& repository, const std::string& digest);
    
    // Vulnerability scanning
    struct Vulnerability {
        std::string severity;
        std::string description;
        std::string package;
        std::string fixedVersion;
        std::vector<std::string> cves;
    };
    std::vector<Vulnerability> ScanImage(const std::string& repository,
                                           const std::string& tag);
    
private:
    Config config_;
    std::string authToken_;
    
    bool Authenticate();
    std::string MakeRequest(const std::string& method, const std::string& path);
};

// ============================================================================
// Docker Client
// ============================================================================

/**
 * Docker client for container management.
 */
class DockerClient {
public:
    struct Config {
        std::string host = "unix:///var/run/docker.sock";
        std::string apiVersion = "1.41";
        std::optional<std::string> tlsCert;
        std::optional<std::string> tlsKey;
        std::optional<std::string> tlsCa;
    };
    
    explicit DockerClient(const Config& config = Config{});
    ~DockerClient();
    
    // Connection
    bool Connect();
    void Disconnect();
    bool IsConnected() const;
    std::string GetVersion() const;
    
    // Containers
    std::shared_ptr<Container> CreateContainer(const ContainerConfig& config);
    std::vector<std::shared_ptr<Container>> ListContainers(bool all = false);
    std::shared_ptr<Container> GetContainer(const std::string& id);
    std::shared_ptr<Container> GetContainerByName(const std::string& name);
    
    // Images
    std::vector<ContainerImage::Info> ListImages();
    bool RemoveImage(const std::string& id, bool force = false);
    bool PruneImages();
    
    // Networks
    struct Network {
        std::string id;
        std::string name;
        std::string driver;
        std::map<std::string, std::string> options;
        std::vector<std::string> containers;
    };
    std::vector<Network> ListNetworks();
    std::string CreateNetwork(const std::string& name, const std::string& driver = "bridge");
    bool RemoveNetwork(const std::string& id);
    
    // Volumes
    struct Volume {
        std::string name;
        std::string driver;
        std::string mountpoint;
        std::map<std::string, std::string> options;
    };
    std::vector<Volume> ListVolumes();
    std::string CreateVolume(const std::string& name, const std::string& driver = "local");
    bool RemoveVolume(const std::string& name, bool force = false);
    bool PruneVolumes();
    
    // System
    struct SystemInfo {
        std::string id;
        std::string name;
        std::string os;
        std::string kernelVersion;
        std::string dockerVersion;
        uint64_t memoryTotal;
        uint64_t memoryLimit;
        int cpus;
        uint64_t images;
        uint64_t containers;
        uint64_t containersRunning;
        uint64_t containersPaused;
        uint64_t containersStopped;
    };
    SystemInfo GetSystemInfo() const;
    
    struct DiskUsage {
        uint64_t images;
        uint64_t containers;
        uint64_t volumes;
        uint64_t buildCache;
    };
    DiskUsage GetDiskUsage() const;
    
    bool PruneContainers();
    bool PruneNetworks();
    bool PruneBuildCache();
    bool PruneAll();
    
    // Events
    using EventCallback = std::function<void(const std::map<std::string, std::string>&)>;
    void SubscribeEvents(EventCallback callback);
    void UnsubscribeEvents();
    
private:
    Config config_;
    bool connected_;
    std::thread eventThread_;
    std::atomic<bool> eventRunning_{false};
    EventCallback eventCallback_;
    
    std::string MakeRequest(const std::string& method, const std::string& path,
                           const std::optional<std::string>& body = std::nullopt);
    void EventLoop();
};

// ============================================================================
// Kubernetes Types
// ============================================================================

/**
 * Kubernetes resource types.
 */
namespace K8s {

enum class ResourceType {
    POD,
    DEPLOYMENT,
    SERVICE,
    INGRESS,
    CONFIGMAP,
    SECRET,
    PERSISTENT_VOLUME,
    PERSISTENT_VOLUME_CLAIM,
    STATEFUL_SET,
    DAEMON_SET,
    JOB,
    CRON_JOB,
    SERVICE_ACCOUNT,
    ROLE,
    ROLE_BINDING,
    NAMESPACE,
    NODE,
    HORIZONTAL_POD_AUTOSCALER,
    NETWORK_POLICY
};

// Pod spec
struct PodSpec {
    std::string name;
    std::vector<ContainerConfig> containers;
    std::vector<std::string> initContainers;
    std::map<std::string, std::string> nodeSelector;
    std::vector<std::string> tolerations;
    std::map<std::string, std::string> affinity;
    std::string restartPolicy;
    std::string serviceAccountName;
    bool hostNetwork;
    bool hostPID;
    bool hostIPC;
    std::map<std::string, std::string> securityContext;
};

// Deployment spec
struct DeploymentSpec {
    std::string name;
    std::string namespace_;
    int32_t replicas;
    int32_t revisionHistoryLimit;
    std::map<std::string, std::string> selector;
    PodSpec template_;
    std::map<std::string, std::string> strategy;
    int32_t minReadySeconds;
    int32_t progressDeadlineSeconds;
};

// Service spec
struct ServiceSpec {
    std::string name;
    std::string namespace_;
    std::string type;  // ClusterIP, NodePort, LoadBalancer, ExternalName
    std::map<std::string, std::string> selector;
    std::vector<std::map<std::string, std::string>> ports;
    std::string clusterIP;
    std::vector<std::string> externalIPs;
    std::string loadBalancerIP;
    std::vector<std::string> loadBalancerSourceRanges;
    std::string externalTrafficPolicy;
    std::string sessionAffinity;
};

// Ingress spec
struct IngressSpec {
    std::string name;
    std::string namespace_;
    std::vector<std::map<std::string, std::string>> rules;
    std::vector<std::map<std::string, std::string>> tls;
    std::string ingressClassName;
};

// ConfigMap
struct ConfigMap {
    std::string name;
    std::string namespace_;
    std::map<std::string, std::string> data;
    std::map<std::string, std::string> binaryData;
};

// Secret
struct Secret {
    std::string name;
    std::string namespace_;
    std::string type;
    std::map<std::string, std::string> data;
};

} // namespace K8s

// ============================================================================
// Kubernetes Client
// ============================================================================

/**
 * Kubernetes API client.
 */
class KubernetesClient {
public:
    struct Config {
        std::string server;
        std::string token;
        std::string clientCert;
        std::string clientKey;
        std::string caCert;
        bool insecureSkipTlsVerify;
        std::string namespace_ = "default";
        std::string context;
        std::string kubeconfig;
    };
    
    explicit KubernetesClient(const Config& config);
    ~KubernetesClient();
    
    // Connection
    bool Connect();
    void Disconnect();
    bool IsConnected() const;
    std::string GetVersion() const;
    
    // Namespaces
    std::vector<std::string> ListNamespaces();
    bool CreateNamespace(const std::string& name);
    bool DeleteNamespace(const std::string& name);
    void SetNamespace(const std::string& name);
    std::string GetNamespace() const;
    
    // Pods
    std::vector<K8s::PodSpec> ListPods(const std::string& namespace_ = "");
    std::optional<K8s::PodSpec> GetPod(const std::string& name,
                                         const std::string& namespace_ = "");
    bool CreatePod(const K8s::PodSpec& spec);
    bool DeletePod(const std::string& name, const std::string& namespace_ = "");
    bool RestartPod(const std::string& name, const std::string& namespace_ = "");
    std::string GetPodLogs(const std::string& name, const std::string& namespace_ = "");
    std::string ExecInPod(const std::string& name, const std::vector<std::string>& command,
                          const std::string& namespace_ = "");
    
    // Deployments
    std::vector<K8s::DeploymentSpec> ListDeployments(const std::string& namespace_ = "");
    bool CreateDeployment(const K8s::DeploymentSpec& spec);
    bool UpdateDeployment(const K8s::DeploymentSpec& spec);
    bool DeleteDeployment(const std::string& name, const std::string& namespace_ = "");
    bool ScaleDeployment(const std::string& name, int32_t replicas,
                         const std::string& namespace_ = "");
    bool RolloutDeployment(const std::string& name, const std::string& namespace_ = "");
    bool RollbackDeployment(const std::string& name, const std::string& namespace_ = "");
    
    // Services
    std::vector<K8s::ServiceSpec> ListServices(const std::string& namespace_ = "");
    bool CreateService(const K8s::ServiceSpec& spec);
    bool DeleteService(const std::string& name, const std::string& namespace_ = "");
    std::optional<K8s::ServiceSpec> GetService(const std::string& name,
                                                const std::string& namespace_ = "");
    
    // Ingress
    std::vector<K8s::IngressSpec> ListIngresses(const std::string& namespace_ = "");
    bool CreateIngress(const K8s::IngressSpec& spec);
    bool DeleteIngress(const std::string& name, const std::string& namespace_ = "");
    
    // ConfigMaps
    std::vector<K8s::ConfigMap> ListConfigMaps(const std::string& namespace_ = "");
    bool CreateConfigMap(const K8s::ConfigMap& configMap);
    bool UpdateConfigMap(const K8s::ConfigMap& configMap);
    bool DeleteConfigMap(const std::string& name, const std::string& namespace_ = "");
    std::optional<K8s::ConfigMap> GetConfigMap(const std::string& name,
                                               const std::string& namespace_ = "");
    
    // Secrets
    std::vector<K8s::Secret> ListSecrets(const std::string& namespace_ = "");
    bool CreateSecret(const K8s::Secret& secret);
    bool UpdateSecret(const K8s::Secret& secret);
    bool DeleteSecret(const std::string& name, const std::string& namespace_ = "");
    std::optional<K8s::Secret> GetSecret(const std::string& name,
                                          const std::string& namespace_ = "");
    
    // Nodes
    struct NodeInfo {
        std::string name;
        std::string status;
        std::map<std::string, std::string> labels;
        std::map<std::string, std::string> annotations;
        uint64_t cpuCapacity;
        uint64_t memoryCapacity;
        uint64_t cpuAllocatable;
        uint64_t memoryAllocatable;
        std::string osImage;
        std::string kernelVersion;
        std::string kubeletVersion;
    };
    std::vector<NodeInfo> ListNodes();
    bool CordonNode(const std::string& name);
    bool UncordonNode(const std::string& name);
    bool DrainNode(const std::string& name);
    
    // Events
    struct Event {
        std::string type;
        std::string reason;
        std::string message;
        std::string namespace_;
        std::string involvedObject;
        std::chrono::system_clock::time_point timestamp;
        int32_t count;
    };
    std::vector<Event> ListEvents(const std::string& namespace_ = "");
    
    // Apply YAML
    bool ApplyYaml(const std::string& yaml);
    bool DeleteYaml(const std::string& yaml);
    
    // Watch
    using WatchCallback = std::function<void(const std::map<std::string, std::string>&)>;
    void WatchPods(WatchCallback callback, const std::string& namespace_ = "");
    void WatchDeployments(WatchCallback callback, const std::string& namespace_ = "");
    void StopWatching();
    
private:
    Config config_;
    bool connected_;
    std::atomic<bool> watching_{false};
    std::thread watchThread_;
    
    std::string MakeRequest(const std::string& method, const std::string& path,
                           const std::optional<std::string>& body = std::nullopt);
    void WatchLoop(const std::string& resource, WatchCallback callback);
};

// ============================================================================
// Helm Client
// ============================================================================

/**
 * Helm package manager client.
 */
class HelmClient {
public:
    struct Chart {
        std::string name;
        std::string version;
        std::string appVersion;
        std::string description;
        std::vector<std::string> keywords;
        std::string home;
        std::vector<std::string> sources;
        std::vector<std::map<std::string, std::string>> maintainers;
        std::string engine;
        std::string icon;
    };
    
    struct Release {
        std::string name;
        std::string namespace_;
        std::string revision;
        std::string status;
        Chart chart;
        std::chrono::system_clock::time_point updated;
    };
    
    struct Values {
        std::map<std::string, std::string> values;
    };
    
    HelmClient();
    explicit HelmClient(const std::string& kubeconfig);
    
    // Repositories
    bool RepoAdd(const std::string& name, const std::string& url);
    bool RepoRemove(const std::string& name);
    bool RepoUpdate();
    std::vector<std::map<std::string, std::string>> RepoList();
    
    // Search
    std::vector<Chart> Search(const std::string& keyword);
    std::vector<Chart> SearchRepo(const std::string& repo, const std::string& keyword);
    
    // Install/Upgrade
    bool Install(const std::string& releaseName, const std::string& chart,
                 const Values& values = Values{}, const std::string& namespace_ = "default");
    bool Upgrade(const std::string& releaseName, const std::string& chart,
                 const Values& values = Values{}, const std::string& namespace_ = "default");
    bool InstallOrUpgrade(const std::string& releaseName, const std::string& chart,
                          const Values& values = Values{}, const std::string& namespace_ = "default");
    bool Uninstall(const std::string& releaseName, const std::string& namespace_ = "default");
    
    // Releases
    std::vector<Release> ListReleases();
    std::vector<Release> ListReleases(const std::string& namespace_);
    std::optional<Release> GetRelease(const std::string& name,
                                        const std::string& namespace_ = "default");
    bool Rollback(const std::string& releaseName, int revision,
                  const std::string& namespace_ = "default");
    std::string GetHistory(const std::string& releaseName,
                           const std::string& namespace_ = "default");
    
    // Values
    Values GetValues(const std::string& releaseName, const std::string& namespace_ = "default");
    bool SetValues(const std::string& releaseName, const Values& values,
                   const std::string& namespace_ = "default");
    
    // Template
    std::string Template(const std::string& chart, const Values& values = Values{});
    
    // Lint
    std::vector<std::string> Lint(const std::string& chartPath);
    
    // Package
    bool Package(const std::string& chartPath, const std::string& destination = ".");
    
private:
    std::string kubeconfig_;
    
    std::string Execute(const std::string& command);
};

} // namespace Deployment
