// SKIP_AUTOGEN
// Production-Grade Deployment Infrastructure
// Containerization, orchestration, deployment strategies, rollback mechanisms
#pragma once

#include <QString>
#include <QStringList>
#include <QVector>
#include <QList>
#include <QMap>
#include <QVariant>
#include <QVariantMap>
#include <QObject>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <QUuid>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Agentic {

// ========== DEPLOYMENT STRUCTURES ==========

struct DockerConfig {
    QString applicationName;
    QString baseImage;
    QString workdir;
    QString workingDir;  // Alias for workdir
    QVector<QString> dependencies;
    QVector<QString> buildCommands;
    QMap<QString, QString> environmentVariables;
    QMap<QString, QString> environment;  // Alias for environmentVariables
    QVector<int> exposedPorts;
    QString healthCheckCommand;
    QStringList entrypoint;
    QStringList cmd;
    QMap<QString, QString> buildArgs;
    QVector<QString> copyFiles;
    QVector<QString> runCommands;
};

struct KubernetesConfig {
    QString namespaceName;
    QString serviceName;  // Required by cpp
    QString image;        // Required by cpp
    QString imagePullPolicy; // "Always", "Never", "IfNotPresent"
    int replicas;
    int minReplicas;
    int maxReplicas;
    QString storageClass;
    bool persistentStorage;
    QMap<QString, QString> nodeSelectors;
    QVector<QString> tolerations;
};

struct DeploymentPhase {
    QString phaseName;
    QString name;  // Alias for phaseName
    int sequence;
    QVector<QString> tasks;
    QDateTime startTime;
    QDateTime endTime;
    QString status;
    double durationSeconds;
    int progress;  // Phase progress percentage
};

struct DeploymentExecution {
    QString deploymentId;
    QString applicationName;
    QString name;  // Alias for applicationName used in some contexts
    QString version;
    QString environment;
    QString strategy; // "blue-green", "canary", "rolling", "recreate"
    QDateTime startTime;
    QDateTime completedTime;
    QString status; // "pending", "in-progress", "completed", "failed", "rolled-back"
    int progressPercentage;
    int progress;  // Alias for progressPercentage
    QString error;
    QVector<DeploymentPhase> phases;  // Phases of this deployment
};

struct RollbackInfo {
    QString rollbackId;
    QString deploymentId;
    QString targetVersion;
    QString fromVersion;  // Version being rolled back from
    QString toVersion;    // Version being rolled back to
    QDateTime initiatedAt;
    QDateTime startTime;  // Alias for initiatedAt
    QString initiatedBy;
    QString reason;
    QString status;
    QDateTime completedAt;
    int progress;  // Rollback progress percentage
};

struct HealthCheckResult {
    QString serviceName;
    bool healthy;
    int responseTimeMs;
    int statusCode;
    QString lastCheckedAt;
    QString message;
    QVector<QString> issues;
};

struct EnvironmentConfig {
    QString environmentId;  // Required by cpp
    QString name;           // Required by cpp
    QString type;           // Required by cpp (development, staging, production)
    QString status;         // Required by cpp (active, inactive)
    QDateTime createdAt;    // Required by cpp
    QString environment;
    QString region;
    int instances;
    QString machineType;
    QString osVersion;
    QMap<QString, QString> configValues;
    QVariantMap variables;  // Required by cpp
    QStringList secrets;    // Required by cpp
    bool autoScalingEnabled;
    double cpuThreshold;
    double memoryThreshold;
};

struct ReleaseNotes {
    QString releaseId;     // Required by cpp
    QString version;
    QString title;
    QString description;
    QString status;        // Required by cpp (draft, published)
    QDateTime releaseDate;
    QDateTime createdAt;   // Required by cpp
    QDateTime publishedAt; // Required by cpp
    QVector<QString> features;
    QVector<QString> bugFixes;
    QVector<QString> breaking;
    QVector<QString> artifacts;  // Required by cpp
    QString downloadUrl;
    QString releaseNotes;
};

// ========== DOCKERFILE GENERATOR ==========

class DockerfileGenerator : public QObject {
    Q_OBJECT

public:
    explicit DockerfileGenerator(QObject* parent = nullptr);
    ~DockerfileGenerator();

    // Dockerfile Generation
    QString generateDockerfile(const DockerConfig& config);
    QString generateMultiStageDockerfile(const QVector<DockerConfig>& stages);
    QString generateDockerComposeFile(const QVector<QString>& services);

    // Best Practices
    bool optimizeDockerfile(QString& dockerfile);
    QString addSecurityBestPractices(const QString& dockerfile);
    QString addPerformanceOptimizations(const QString& dockerfile);

    // Image Management
    bool buildImage(const DockerConfig& config, const QString& tag);
    bool pushImage(const QString& imageName, const QString& registry);
    bool scanImageForVulnerabilities(const QString& imageName);
    QVector<QString> getImageVulnerabilities(const QString& imageName);
    QStringList listImages();
    bool removeImage(const QString& tag);

    // Validation
    bool validateDockerfile(const QString& dockerfile);
    QVector<QString> lintDockerfile(const QString& dockerfile);

signals:
    void dockerfilGenerated(QString imageName);
    void imageBuildStarted(QString imageName);
    void imageBuildCompleted(QString imageName);
    void imageBuilFailed(QString imageName, QString error);
    void securityIssueDetected(QString imageName, QString issue);
    void buildError(QString error);
    void buildProgress(int percent, QString message);
    void buildCompleted(QString imageName);
    void pushProgress(int percent, QString message);
    void pushCompleted(QString imageName);
    void imageRemoved(QString imageName);

private:
    QString generateBaseStage(const DockerConfig& config);
    QString generateBuildStage(const DockerConfig& config);
    QString generateRuntimeStage(const DockerConfig& config);
};

// ========== KUBERNETES ORCHESTRATOR ==========

class KubernetesOrchestrator : public QObject {
    Q_OBJECT

public:
    explicit KubernetesOrchestrator(QObject* parent = nullptr);
    ~KubernetesOrchestrator();

    // Cluster Management
    bool initializeCluster(const QString& clusterName, const KubernetesConfig& config);
    bool connectToCluster(const QString& kubeConfigPath);
    bool scaleCluster(int nodeCount);
    QString getClusterStatus();

    // Namespace Management
    bool createNamespace(const QString& namespaceName);
    bool deleteNamespace(const QString& namespaceName);
    QVector<QString> listNamespaces();

    // Service Deployment (matches cpp)
    bool deployService(const KubernetesConfig& config);
    bool scaleDeployment(const QString& name, int replicas);
    bool deleteService(const QString& name);
    QList<QString> listPods(const QString& namespaceName);
    QString getPodLogs(const QString& podName);
    bool applyConfig(const QString& configYaml);

    // Legacy Deployment Management
    QString deployApplication(const QString& namespaceName, const QString& manifestFile);
    bool updateDeployment(const QString& namespaceName, const QString& deploymentName, const QString& newImage);
    bool deleteDeployment(const QString& namespaceName, const QString& deploymentName);

    // Service Management
    bool createService(const QString& namespaceName, const QString& serviceName, int port);
    QString getServiceEndpoint(const QString& namespaceName, const QString& serviceName);
    bool exposeService(const QString& namespaceName, const QString& serviceName);

    // ConfigMap & Secrets
    bool createConfigMap(const QString& namespaceName, const QString& configName, const QMap<QString, QString>& data);
    bool createSecret(const QString& namespaceName, const QString& secretName, const QMap<QString, QString>& data);
    bool updateConfigMap(const QString& namespaceName, const QString& configName, const QMap<QString, QString>& data);

    // Health & Status
    QVector<HealthCheckResult> getDeploymentHealth(const QString& namespaceName);
    QString getDeploymentLogs(const QString& namespaceName, const QString& podName, int lines = 100);
    bool watchDeployment(const QString& namespaceName, const QString& deploymentName);

    // Ingress & Load Balancing
    bool createIngress(const QString& namespaceName, const QString& ingressName, const QJsonObject& rules);
    QString getIngressStatus(const QString& namespaceName, const QString& ingressName);

signals:
    void deploymentStarted(QString serviceName);
    void deploymentProgress(QString serviceName, int percent, QString message);
    void deploymentCompleted(QString serviceName);
    void deploymentError(QString serviceName, QString error);
    void scalingStarted(QString serviceName, int replicas);
    void scalingCompleted(QString serviceName, int replicas);
    void scalingError(QString serviceName, QString error);
    void serviceDeleted(QString serviceName);
    void configApplied(QString configYaml);
    void configError(QString error);
    void deploymentSucceeded(QString namespaceName, QString deploymentName);
    void deploymentFailed(QString namespaceName, QString deploymentName, QString error);
    void podCrashed(QString namespaceName, QString podName);
    void resourceLimitExceeded(QString namespaceName, QString podName);

private:
    QString m_kubeConfigPath;
    QString m_currentContext;
};

// ========== DEPLOYMENT ORCHESTRATOR ==========

class DeploymentOrchestrator : public QObject {
    Q_OBJECT

public:
    explicit DeploymentOrchestrator(QObject* parent = nullptr);
    ~DeploymentOrchestrator();

    // Deployment Execution
    QString initializeDeployment(const QString& applicationName, const QString& version, const QString& environment);
    bool executeDeployment(const QString& deploymentId);
    bool pauseDeployment(const QString& deploymentId);
    bool resumeDeployment(const QString& deploymentId);
    bool cancelDeployment(const QString& deploymentId);

    // Deployment Strategies
    bool executeBlueGreenDeployment(const QString& deploymentId);
    bool executeCanaryDeployment(const QString& deploymentId, int canaryPercentage);
    bool executeRollingDeployment(const QString& deploymentId, int batchSize);
    bool executeRecreateDeployment(const QString& deploymentId);

    // Pre-Deployment Checks
    bool runPreDeploymentValidation(const QString& deploymentId);
    bool runSecurityChecks(const QString& deploymentId);
    bool runPerformanceChecks(const QString& deploymentId);
    bool runCompatibilityChecks(const QString& deploymentId);

    // Smoke Testing
    bool runSmokeTests(const QString& deploymentId);
    bool runIntegrationTests(const QString& deploymentId);
    bool verifyDeployment(const QString& deploymentId);

    // Deployment Status
    DeploymentExecution getDeploymentStatus(const QString& deploymentId);
    int getDeploymentProgress(const QString& deploymentId);
    QVector<DeploymentPhase> getDeploymentPhases(const QString& deploymentId);

    // Deployment History
    QVector<DeploymentExecution> getDeploymentHistory(const QString& applicationName);
    QString generateDeploymentReport(const QString& deploymentId);
    
    // Additional deployment management
    DeploymentExecution startDeployment(const QString& name, const QString& version);
    QList<DeploymentExecution> listDeployments();
    bool promoteDeployment(const QString& deploymentId, const QString& targetEnvironment);

signals:
    void deploymentPhaseStarted(QString deploymentId, QString phaseName);
    void deploymentPhaseCompleted(QString deploymentId, QString phaseName);
    void deploymentProgressUpdated(QString deploymentId, int percentage);
    void deploymentSucceeded(QString deploymentId);
    void deploymentFailed(QString deploymentId, QString error);
    void preDeploymentCheckFailed(QString checkName, QString error);
    void smokeTestFailed(QString testName);
    // Additional signals used in implementation
    void deploymentStarted(QString deploymentId);
    void deploymentError(QString deploymentId, QString error);
    void deploymentCancelled(QString deploymentId);
    void deploymentPromoted(QString deploymentId, QString targetEnvironment);
    void promotionError(QString deploymentId, QString error);

private:
    QMap<QString, DeploymentExecution> m_deployments;
    QMap<QString, DeploymentExecution> m_activeDeployments;  // Active deployments tracking
    QMap<QString, QVector<DeploymentPhase>> m_deploymentPhases;

    bool executePhase(const QString& deploymentId, const DeploymentPhase& phase);
};

// ========== ROLLBACK MANAGER ==========

class RollbackManager : public QObject {
    Q_OBJECT

public:
    explicit RollbackManager(QObject* parent = nullptr);
    ~RollbackManager();

    // Rollback Management (matches cpp)
    RollbackInfo initiateRollback(const QString& deploymentId, const QString& targetVersion);
    bool cancelRollback(const QString& rollbackId);
    RollbackInfo getRollbackStatus(const QString& rollbackId);
    QList<RollbackInfo> listRollbacks();
    QStringList getAvailableVersions(const QString& deploymentId);

    // Legacy Rollback Management
    bool executeRollback(const QString& rollbackId);
    bool pauseRollback(const QString& rollbackId);
    bool resumeRollback(const QString& rollbackId);

    // Version Management
    QString getCurrentVersion(const QString& applicationName);
    QString getPreviousVersion(const QString& applicationName);

    // Automated Rollback
    bool enableAutomaticRollback(const QString& applicationName);
    bool setRollbackThreshold(const QString& applicationName, double errorRateThreshold);
    bool triggerAutomaticRollback(const QString& applicationName);

    // Rollback Analysis
    RollbackInfo getRollbackInfo(const QString& rollbackId);
    QVector<RollbackInfo> getRollbackHistory(const QString& applicationName);
    QString generateRollbackReport(const QString& rollbackId);

    // Post-Rollback Verification
    bool verifyRollback(const QString& rollbackId);
    bool runPostRollbackTests(const QString& rollbackId);

signals:
    void rollbackInitiated(QString rollbackId, QString reason);
    void rollbackStarted(QString rollbackId);
    void rollbackCompleted(QString rollbackId);
    void rollbackFailed(QString rollbackId, QString error);
    void rollbackError(QString rollbackId, QString error);
    void rollbackCancelled(QString rollbackId);
    void automaticRollbackTriggered(QString applicationName);

private:
    QMap<QString, RollbackInfo> m_rollbackHistory;
    QMap<QString, RollbackInfo> m_rollbacks;  // Active rollbacks tracking
    QMap<QString, double> m_rollbackThresholds;
};

// ========== ENVIRONMENT MANAGER ==========

class EnvironmentManager : public QObject {
    Q_OBJECT

public:
    explicit EnvironmentManager(QObject* parent = nullptr);
    ~EnvironmentManager();

    // Environment Setup (matches cpp)
    EnvironmentConfig createEnvironment(const QString& name, const QString& type);
    bool deleteEnvironment(const QString& environmentId);
    EnvironmentConfig getEnvironment(const QString& environmentId);
    QList<EnvironmentConfig> listEnvironments();
    bool updateEnvironment(const QString& environmentId, const QVariantMap& updates);

    // Legacy Environment Setup
    bool createEnvironment(const EnvironmentConfig& config);
    bool configureEnvironment(const QString& environment, const EnvironmentConfig& config);

    // Configuration Management
    bool setConfigValue(const QString& environment, const QString& key, const QString& value);
    QString getConfigValue(const QString& environment, const QString& key);
    QMap<QString, QString> getEnvironmentConfig(const QString& environment);

    // Secret Management
    bool createSecret(const QString& environment, const QString& secretName, const QString& value);
    bool rotateSecret(const QString& environment, const QString& secretName);
    bool deleteSecret(const QString& environment, const QString& secretName);

    // Environment Promotion
    bool promoteEnvironment(const QString& fromEnv, const QString& toEnv);
    bool syncConfiguration(const QString& sourceEnv, const QString& targetEnv);

    // Environment Health
    QString getEnvironmentHealth(const QString& environment);
    int getEnvironmentUptime(const QString& environment);
    QVector<QString> getEnvironmentIssues(const QString& environment);

signals:
    void environmentCreated(QString environmentId);
    void environmentDeleted(QString environmentId);
    void environmentUpdated(QString environmentId);
    void environmentError(QString environmentId, QString error);
    void environmentConfigured(QString environment);
    void configurationUpdated(QString environment, QString key);
    void secretRotated(QString environment, QString secretName);
    void environmentHealthDegraded(QString environment);

private:
    QMap<QString, EnvironmentConfig> m_environments;
    QMap<QString, QMap<QString, QString>> m_secrets;
};

// ========== RELEASE MANAGER ==========

class ReleaseManager : public QObject {
    Q_OBJECT

public:
    explicit ReleaseManager(QObject* parent = nullptr);
    ~ReleaseManager();

    // Release Planning (matches cpp)
    ReleaseNotes createRelease(const QString& version, const QString& description);
    bool publishRelease(const QString& releaseId);
    ReleaseNotes getRelease(const QString& releaseId);
    QList<ReleaseNotes> listReleases();
    bool addReleaseArtifact(const QString& releaseId, const QString& artifactPath);
    bool updateReleaseNotes(const QString& releaseId, const ReleaseNotes& notes);

    // Legacy Release Planning
    bool createRelease(const QString& version);
    bool addFeatureToRelease(const QString& version, const QString& featureName);
    bool addBugFixToRelease(const QString& version, const QString& bugFix);
    bool addBreakingChangeWarning(const QString& version, const QString& warning);

    // Release Notes Generation
    ReleaseNotes generateReleaseNotes(const QString& version);
    QString generateReleaseNotesMarkdown(const QString& version);
    QString generateReleaseNotesHTML(const QString& version);

    // Release Publishing
    bool publishRelease(const QString& version, bool legacy);
    bool createGitHubRelease(const QString& version, const ReleaseNotes& notes);
    bool uploadArtifacts(const QString& version, const QVector<QString>& artifactPaths);

    // Release Tracking
    QVector<QString> getReleaseHistory();
    ReleaseNotes getReleaseNotes(const QString& version);
    QString getLatestReleaseVersion();

    // Changelog Management
    QString generateChangelog();
    bool updateChangelog(const QString& version, const QString& changes);

signals:
    void releaseCreated(QString releaseId);
    void releasePublished(QString releaseId);
    void releaseUpdated(QString releaseId);
    void releaseError(QString releaseId, QString error);
    void artifactAdded(QString releaseId, QString artifactPath);
    void releaseNotesGenerated(QString version);
    void releaseArtifactsUploaded(QString version);

private:
    QMap<QString, ReleaseNotes> m_releases;
};

// ========== DEPLOYMENT UTILITIES ==========

class DeploymentUtils {
public:
    static QString validateDeploymentConfig(const DockerConfig& config);
    static QString validateKubernetesConfig(const KubernetesConfig& config);
    static int estimateDeploymentTime(const QString& strategy, int instanceCount);
    static QString selectOptimalDeploymentStrategy(const QString& applicationType, int userBase);
    static QJsonObject generateDeploymentManifest(const QString& applicationName, const QString& version);
};

} // namespace Agentic
} // namespace RawrXD
