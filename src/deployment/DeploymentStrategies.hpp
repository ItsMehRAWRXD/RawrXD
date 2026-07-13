/**
 * DeploymentStrategies.hpp
 *
 * Phase K Batch 4/5: Deployment Strategies
 *
 * Advanced deployment strategies including blue-green, canary,
 * rolling updates, and feature flags.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <chrono>
#include <functional>

namespace Deployment {

// ============================================================================
// Forward Declarations
// ============================================================================

class DeploymentStrategy;
class BlueGreenDeployment;
class CanaryDeployment;
class RollingDeployment;
class FeatureFlagManager;

// ============================================================================
// Deployment Types
// ============================================================================

enum class DeploymentType {
    BLUE_GREEN,
    CANARY,
    ROLLING,
    RECREATE,
    SHADOW,
    A_B_TESTING,
    FEATURE_FLAG
};

enum class DeploymentStatus {
    PENDING,
    IN_PROGRESS,
    PAUSED,
    PROMOTING,
    COMPLETED,
    ROLLED_BACK,
    FAILED
};

// ============================================================================
// Health Check
// ============================================================================

/**
 * Health check configuration.
 */
struct HealthCheck {
    enum class Type {
        HTTP,
        TCP,
        COMMAND,
        GRPC
    };
    
    Type type;
    std::string endpoint;
    uint32_t port;
    std::vector<int> expectedCodes;
    std::string expectedResponse;
    uint32_t initialDelaySeconds;
    uint32_t periodSeconds;
    uint32_t timeoutSeconds;
    uint32_t successThreshold;
    uint32_t failureThreshold;
    
    HealthCheck();
    
    static HealthCheck Http(const std::string& endpoint, uint32_t port);
    static HealthCheck Tcp(uint32_t port);
    static HealthCheck Command(const std::string& command);
    static HealthCheck Grpc(uint32_t port);
};

// ============================================================================
// Deployment Target
// ============================================================================

/**
 * Deployment target configuration.
 */
struct DeploymentTarget {
    std::string name;
    std::string environment;
    std::string version;
    std::string image;
    std::map<std::string, std::string> labels;
    std::map<std::string, std::string> annotations;
    std::map<std::string, std::string> environmentVariables;
    std::vector<std::pair<uint16_t, uint16_t>> ports;
    std::vector<std::string> volumes;
    HealthCheck healthCheck;
    std::optional<uint64_t> memoryLimit;
    std::optional<double> cpuLimit;
    uint32_t replicas;
    std::map<std::string, std::string> resources;
};

// ============================================================================
// Deployment Metrics
// ============================================================================

/**
 * Deployment metrics for analysis.
 */
struct DeploymentMetrics {
    uint64_t requestCount;
    uint64_t errorCount;
    double errorRate;
    double latencyP50;
    double latencyP95;
    double latencyP99;
    double cpuUsage;
    double memoryUsage;
    uint32_t activeConnections;
    uint32_t queueDepth;
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Deployment Strategy Base
// ============================================================================

/**
 * Base class for deployment strategies.
 */
class DeploymentStrategy {
public:
    struct Config {
        std::string name;
        DeploymentType type;
        std::string namespace_;
        uint32_t timeoutMinutes;
        bool autoRollback;
        bool autoPromote;
        uint32_t analysisIntervalSeconds;
        uint32_t analysisThreshold;
    };
    
    explicit DeploymentStrategy(const Config& config);
    virtual ~DeploymentStrategy() = default;
    
    // Deployment lifecycle
    virtual bool Initialize(const DeploymentTarget& target) = 0;
    virtual bool Deploy() = 0;
    virtual bool Promote() = 0;
    virtual bool Rollback() = 0;
    virtual bool Abort() = 0;
    
    // Status
    DeploymentStatus GetStatus() const;
    std::string GetStatusMessage() const;
    double GetProgress() const;
    
    // Metrics
    virtual DeploymentMetrics GetMetrics() = 0;
    virtual bool IsHealthy() = 0;
    
    // Events
    using EventCallback = std::function<void(const std::string& event, const std::map<std::string, std::string>&)>;
    void SetEventCallback(EventCallback callback);
    
protected:
    Config config_;
    DeploymentStatus status_;
    std::string statusMessage_;
    double progress_;
    EventCallback eventCallback_;
    mutable std::mutex mutex_;
    
    void UpdateStatus(DeploymentStatus status, const std::string& message);
    void UpdateProgress(double progress);
    void EmitEvent(const std::string& event, const std::map<std::string, std::string>& data);
};

// ============================================================================
// Blue-Green Deployment
// ============================================================================

/**
 * Blue-green deployment strategy.
 */
class BlueGreenDeployment : public DeploymentStrategy {
public:
    struct Config {
        std::string blueEnvironment;
        std::string greenEnvironment;
        std::string activeEnvironment;
        std::string serviceName;
        std::string ingressName;
        uint32_t smokeTestDurationSeconds;
        bool keepBlueAfterDeploy;
    };
    
    explicit BlueGreenDeployment(const DeploymentStrategy::Config& baseConfig,
                                  const Config& config);
    
    // Implementation
    bool Initialize(const DeploymentTarget& target) override;
    bool Deploy() override;
    bool Promote() override;
    bool Rollback() override;
    bool Abort() override;
    
    // Blue-Green specific
    bool SwitchTraffic(const std::string& from, const std::string& to);
    bool RunSmokeTests();
    bool CleanupOldEnvironment();
    std::string GetInactiveEnvironment() const;
    
    // Metrics
    DeploymentMetrics GetMetrics() override;
    bool IsHealthy() override;
    
private:
    Config bgConfig_;
    DeploymentTarget target_;
    std::string inactiveEnvironment_;
    
    bool DeployToEnvironment(const std::string& environment);
    bool UpdateServiceSelector(const std::string& environment);
    bool UpdateIngressBackend(const std::string& environment);
};

// ============================================================================
// Canary Deployment
// ============================================================================

/**
 * Canary deployment strategy.
 */
class CanaryDeployment : public DeploymentStrategy {
public:
    struct Step {
        uint32_t weight;           // Traffic percentage (0-100)
        uint32_t durationMinutes;
        std::map<std::string, std::string> metricsThresholds;
        bool pause;
        bool manualApproval;
    };
    
    struct Config {
        std::vector<Step> steps;
        uint32_t baselineReplicas;
        uint32_t canaryReplicas;
        bool mirrorTraffic;
        bool progressiveTrafficShift;
        std::string analysisTemplate;
        std::string successCriteria;
        std::string failureCriteria;
    };
    
    explicit CanaryDeployment(const DeploymentStrategy::Config& baseConfig,
                             const Config& config);
    
    // Implementation
    bool Initialize(const DeploymentTarget& target) override;
    bool Deploy() override;
    bool Promote() override;
    bool Rollback() override;
    bool Abort() override;
    
    // Canary specific
    bool AdvanceStep();
    bool Pause();
    bool Resume();
    bool SetWeight(uint32_t weight);
    bool SetStep(uint32_t stepIndex);
    uint32_t GetCurrentStep() const;
    uint32_t GetCurrentWeight() const;
    
    // Analysis
    bool RunAnalysis();
    bool IsAnalysisSuccessful();
    std::string GetAnalysisReport() const;
    
    // Metrics
    DeploymentMetrics GetMetrics() override;
    bool IsHealthy() override;
    
private:
    Config canaryConfig_;
    DeploymentTarget target_;
    uint32_t currentStep_;
    std::vector<DeploymentMetrics> metricsHistory_;
    
    bool DeployCanary();
    bool UpdateTrafficSplit(uint32_t weight);
    bool ScaleCanary(uint32_t replicas);
    bool ScaleBaseline(uint32_t replicas);
    bool PromoteToBaseline();
};

// ============================================================================
// Rolling Deployment
// ============================================================================

/**
 * Rolling deployment strategy.
 */
class RollingDeployment : public DeploymentStrategy {
public:
    struct Config {
        uint32_t maxSurge;           // Percentage or absolute
        uint32_t maxUnavailable;     // Percentage or absolute
        uint32_t partition;          // For partitioned rollouts
        uint32_t delaySeconds;       // Delay between batches
        bool waitForHealthy;         // Wait for pods to be healthy
        uint32_t progressDeadlineSeconds;
        bool minReadySeconds;
    };
    
    explicit RollingDeployment(const DeploymentStrategy::Config& baseConfig,
                                const Config& config);
    
    // Implementation
    bool Initialize(const DeploymentTarget& target) override;
    bool Deploy() override;
    bool Promote() override;
    bool Rollback() override;
    bool Abort() override;
    
    // Rolling specific
    bool Pause();
    bool Resume();
    bool Restart();
    bool SetPartition(uint32_t partition);
    
    // Progress
    uint32_t GetUpdatedReplicas() const;
    uint32_t GetReadyReplicas() const;
    uint32_t GetAvailableReplicas() const;
    
    // Metrics
    DeploymentMetrics GetMetrics() override;
    bool IsHealthy() override;
    
private:
    Config rollingConfig_;
    DeploymentTarget target_;
    bool paused_;
    
    bool UpdateDeployment();
    bool WaitForRollout();
    bool CheckProgress();
};

// ============================================================================
// Shadow Deployment
// ============================================================================

/**
 * Shadow deployment for testing in production.
 */
class ShadowDeployment : public DeploymentStrategy {
public:
    struct Config {
        uint32_t shadowPercentage;
        bool mirrorTraffic;
        bool compareResponses;
        std::vector<std::string> headersToRemove;
        uint32_t durationMinutes;
        std::string comparisonMetric;
    };
    
    explicit ShadowDeployment(const DeploymentStrategy::Config& baseConfig,
                               const Config& config);
    
    // Implementation
    bool Initialize(const DeploymentTarget& target) override;
    bool Deploy() override;
    bool Promote() override;
    bool Rollback() override;
    bool Abort() override;
    
    // Shadow specific
    bool StartShadow();
    bool StopShadow();
    bool SetShadowPercentage(uint32_t percentage);
    std::string GetComparisonReport() const;
    
    // Metrics
    DeploymentMetrics GetMetrics() override;
    bool IsHealthy() override;
    
private:
    Config shadowConfig_;
    DeploymentTarget target_;
    bool shadowing_;
    
    bool ConfigureProxy();
    bool StartTrafficMirroring();
    bool StopTrafficMirroring();
};

// ============================================================================
// A/B Testing
// ============================================================================

/**
 * A/B testing deployment strategy.
 */
class ABTestingDeployment : public DeploymentStrategy {
public:
    struct Variant {
        std::string name;
        uint32_t weight;
        std::map<std::string, std::string> headers;
        std::map<std::string, std::string> cookies;
        std::string userAgentRegex;
    };
    
    struct Config {
        std::vector<Variant> variants;
        std::string winningVariant;
        std::map<std::string, std::string> successCriteria;
        uint32_t durationDays;
        uint32_t minSampleSize;
    };
    
    explicit ABTestingDeployment(const DeploymentStrategy::Config& baseConfig,
                                  const Config& config);
    
    // Implementation
    bool Initialize(const DeploymentTarget& target) override;
    bool Deploy() override;
    bool Promote() override;
    bool Rollback() override;
    bool Abort() override;
    
    // A/B specific
    bool DeclareWinner(const std::string& variant);
    std::string GetWinningVariant() const;
    std::map<std::string, double> GetVariantMetrics() const;
    bool IsStatisticallySignificant() const;
    
    // Metrics
    DeploymentMetrics GetMetrics() override;
    bool IsHealthy() override;
    
private:
    Config abConfig_;
    DeploymentTarget target_;
    std::map<std::string, DeploymentMetrics> variantMetrics_;
    
    bool ConfigureRouting();
    bool CollectMetrics();
    bool AnalyzeResults();
};

// ============================================================================
// Feature Flag
// ============================================================================

/**
 * Feature flag definition.
 */
struct FeatureFlag {
    std::string name;
    std::string description;
    bool enabled;
    
    // Targeting
    struct Targeting {
        std::vector<std::string> users;
        std::vector<std::string> groups;
        std::vector<std::string> environments;
        std::map<std::string, std::string> attributes;
        uint32_t percentage;
    };
    Targeting targeting;
    
    // Variants
    struct Variant {
        std::string name;
        uint32_t weight;
        std::map<std::string, std::string> payload;
    };
    std::vector<Variant> variants;
    
    // Scheduling
    std::optional<std::chrono::system_clock::time_point> startTime;
    std::optional<std::chrono::system_clock::time_point> endTime;
    
    // Metadata
    std::string createdBy;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point updatedAt;
    std::vector<std::string> tags;
};

// ============================================================================
// Feature Flag Manager
// ============================================================================

/**
 * Feature flag management system.
 */
class FeatureFlagManager {
public:
    struct Config {
        std::string provider;  // launchdarkly, split, unleash, flagsmith, custom
        std::string apiKey;
        std::string apiUrl;
        uint32_t refreshIntervalSeconds;
        bool offlineMode;
        std::string fallbackFile;
    };
    
    struct EvaluationContext {
        std::string userId;
        std::string sessionId;
        std::map<std::string, std::string> attributes;
        std::map<std::string, std::string> headers;
    };
    
    explicit FeatureFlagManager(const Config& config);
    ~FeatureFlagManager();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Flags
    void RegisterFlag(const FeatureFlag& flag);
    void UpdateFlag(const FeatureFlag& flag);
    void DeleteFlag(const std::string& name);
    std::optional<FeatureFlag> GetFlag(const std::string& name) const;
    std::vector<FeatureFlag> GetFlags() const;
    std::vector<FeatureFlag> GetFlagsByTag(const std::string& tag) const;
    
    // Evaluation
    bool IsEnabled(const std::string& flagName,
                   const EvaluationContext& context = EvaluationContext{});
    std::string GetVariant(const std::string& flagName,
                         const EvaluationContext& context = EvaluationContext{});
    std::map<std::string, std::string> GetPayload(const std::string& flagName,
                                                   const EvaluationContext& context = EvaluationContext{});
    
    // Bulk evaluation
    std::map<std::string, bool> EvaluateAll(const EvaluationContext& context);
    
    // Targeting
    void AddUserToFlag(const std::string& flagName, const std::string& userId);
    void RemoveUserFromFlag(const std::string& flagName, const std::string& userId);
    void SetFlagPercentage(const std::string& flagName, uint32_t percentage);
    
    // Scheduling
    void ScheduleFlag(const std::string& flagName,
                      std::chrono::system_clock::time_point startTime);
    void UnscheduleFlag(const std::string& flagName);
    
    // Sync
    bool Sync();
    bool SyncFromProvider();
    bool ExportToFile(const std::string& path);
    bool ImportFromFile(const std::string& path);
    
    // Events
    void TrackEvent(const std::string& event, const std::string& flagName,
                    const EvaluationContext& context);
    std::vector<std::map<std::string, std::string>> GetEvents(const std::string& flagName);
    
    // Analytics
    struct FlagAnalytics {
        std::string flagName;
        uint64_t evaluations;
        uint64_t enabledCount;
        double enabledPercentage;
        std::map<std::string, uint64_t> variantDistribution;
    };
    std::vector<FlagAnalytics> GetAnalytics(std::chrono::system_clock::time_point since);
    
private:
    Config config_;
    std::map<std::string, FeatureFlag> flags_;
    std::atomic<bool> initialized_{false};
    mutable std::mutex mutex_;
    
    bool EvaluateTargeting(const FeatureFlag& flag, const EvaluationContext& context);
    std::string SelectVariant(const FeatureFlag& flag, const EvaluationContext& context);
    uint32_t HashUser(const std::string& userId, const std::string& flagName);
};

// ============================================================================
// Deployment Factory
// ============================================================================

/**
 * Factory for creating deployment strategies.
 */
class DeploymentFactory {
public:
    static std::unique_ptr<DeploymentStrategy> Create(
        DeploymentType type,
        const DeploymentStrategy::Config& config);
    
    static std::unique_ptr<BlueGreenDeployment> CreateBlueGreen(
        const DeploymentStrategy::Config& baseConfig,
        const BlueGreenDeployment::Config& config);
    
    static std::unique_ptr<CanaryDeployment> CreateCanary(
        const DeploymentStrategy::Config& baseConfig,
        const CanaryDeployment::Config& config);
    
    static std::unique_ptr<RollingDeployment> CreateRolling(
        const DeploymentStrategy::Config& baseConfig,
        const RollingDeployment::Config& config);
    
    static std::unique_ptr<ShadowDeployment> CreateShadow(
        const DeploymentStrategy::Config& baseConfig,
        const ShadowDeployment::Config& config);
    
    static std::unique_ptr<ABTestingDeployment> CreateABTesting(
        const DeploymentStrategy::Config& baseConfig,
        const ABTestingDeployment::Config& config);
};

// ============================================================================
// Deployment Orchestrator
// ============================================================================

/**
 * Orchestrates deployments across multiple strategies.
 */
class DeploymentOrchestrator {
public:
    struct Deployment {
        std::string id;
        std::string name;
        std::unique_ptr<DeploymentStrategy> strategy;
        DeploymentTarget target;
        std::vector<std::string> dependencies;
        std::chrono::system_clock::time_point scheduledTime;
    };
    
    DeploymentOrchestrator();
    
    // Registration
    std::string RegisterDeployment(Deployment&& deployment);
    void UnregisterDeployment(const std::string& id);
    
    // Execution
    bool Execute(const std::string& id);
    bool ExecuteAll();
    bool ExecuteBatch(const std::vector<std::string>& ids);
    
    // Control
    bool Pause(const std::string& id);
    bool Resume(const std::string& id);
    bool Cancel(const std::string& id);
    bool Rollback(const std::string& id);
    
    // Status
    DeploymentStatus GetStatus(const std::string& id) const;
    std::vector<std::pair<std::string, DeploymentStatus>> GetAllStatuses() const;
    
    // Scheduling
    bool Schedule(const std::string& id, std::chrono::system_clock::time_point time);
    bool ScheduleRecurring(const std::string& id, const std::string& cronExpression);
    
private:
    std::map<std::string, Deployment> deployments_;
    std::map<std::string, std::thread> runningDeployments_;
    mutable std::mutex mutex_;
    
    std::vector<std::string> GetExecutionOrder();
    bool CheckDependencies(const std::string& id);
};

} // namespace Deployment
