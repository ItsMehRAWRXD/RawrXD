#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <tuple>
#include <mutex>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace RawrXD {

// Forward declarations
enum class TriggerType { Manual, Scheduled, Webhook, OnCommit };
enum class DeploymentStrategy { Immediate, Canary, BlueGreen };
enum class JobStatus { Pending, Running, Completed, Failed, Cancelled };

class CICDSettings {
public:
    using ShowCallback = void(*)(void* ctx);

    explicit CICDSettings(void* parent = nullptr) : m_parent(parent) {}
    ~CICDSettings() = default;

    void setShowCallback(ShowCallback cb, void* ctx) {
        m_showCb = cb;
        m_showCtx = ctx;
    }

    void show() {
        if (m_showCb) {
            m_showCb(m_showCtx ? m_showCtx : m_parent);
            return;
        }
#if defined(_WIN32)
        MessageBoxA(static_cast<HWND>(m_parent),
                    "CI/CD settings dialog callback is not wired yet.",
                    "RawrXD CI/CD Settings",
                    MB_OK | MB_ICONINFORMATION);
#endif
    }

    struct TrainingJob {
        std::string jobId;
        std::string jobName;
        std::string description;
        std::string modelName;
        std::string datasetPath;
        int epochs = 10;
        int batchSize = 32;
        float learningRate = 0.001f;
        std::string optimizer = "adam";
        int numGPUs = 1;
        std::string priority = "normal";
        TriggerType trigger = TriggerType::Manual;
        std::string cronSchedule;
        bool enabled = true;
        int64_t createdAt = 0;
        int64_t lastRunAt = 0;
        int successCount = 0;
        int failureCount = 0;
    };

    struct PipelineStage {
        std::string stageName;
        std::string description;
        bool enabled = true;
        int timeoutSeconds = 600;
        std::vector<std::string> commands;
        bool continueOnError = false;
    };

    struct DeploymentConfig {
        std::string modelPath;
        DeploymentStrategy strategy = DeploymentStrategy::Immediate;
        float canaryPercentage = 0.1f;
        std::string targetEnvironment = "staging";
        bool requireApproval = false;
        std::vector<std::string> approvers;
        bool rollbackOnFailure = true;
        int maxConcurrentRequests = 100;
    };

    struct JobRunLog {
        std::string jobId;
        std::string runId;
        JobStatus status = JobStatus::Pending;
        int64_t startTime = 0;
        int64_t endTime = 0;
        std::string outputLog;
        std::string errorMessage;
        float accuracy = 0.0f;
        float loss = 0.0f;
        std::string artifactPath;
    };

    struct NotificationConfig {
        bool enableSlack = false;
        std::string slackWebhookUrl;
        std::string slackChannel;
        bool enableEmail = false;
        std::vector<std::string> emailRecipients;
        bool notifyOnSuccess = true;
        bool notifyOnFailure = true;
        bool notifyOnStart = false;
    };

    // Job Management
    bool createJob(const TrainingJob& job);
    bool updateJob(const std::string& jobId, const TrainingJob& job);
    TrainingJob getJob(const std::string& jobId) const;
    std::vector<TrainingJob> listJobs() const;
    bool deleteJob(const std::string& jobId);
    bool setJobEnabled(const std::string& jobId, bool enabled);

    // Execution
    std::string queueJob(const std::string& jobId);
    bool cancelJob(const std::string& runId);
    JobStatus getJobStatus(const std::string& runId) const;
    std::vector<JobRunLog> getJobHistory(const std::string& jobId, int limit = 10) const;
    std::tuple<int, int, int, float> getJobStatistics(const std::string& jobId) const;

    // Pipelines
    bool definePipeline(const std::string& jobId, const std::vector<PipelineStage>& stages);
    std::vector<PipelineStage> getPipeline(const std::string& jobId) const;
    std::map<std::string, std::string> getPipelineTemplates() const;

    // Deployment
    bool setDeploymentConfig(const std::string& jobId, const DeploymentConfig& config);
    DeploymentConfig getDeploymentConfig(const std::string& jobId) const;
    std::string deployModel(const std::string& jobId, const std::string& runId);
    bool rollbackDeployment(const std::string& deploymentId, const std::string& targetRunId);

    // Webhooks
    std::string registerWebhook(const std::string& jobId, const std::string& platform,
                               const std::string& repository, const std::string& branch);
    std::string handleWebhook(const std::string& webhookData);

    // Notification
    bool setNotificationConfig(const NotificationConfig& config);
    NotificationConfig getNotificationConfig() const;
    bool sendTestNotification() const;

    // Artifacts
    bool storeArtifact(const std::string& artifactId, const std::string& artifactPath, const std::string& metadata);
    std::string getArtifact(const std::string& artifactId) const;
    std::vector<std::string> listArtifacts(const std::string& jobId) const;
    int cleanupOldArtifacts(int olderThanDays);

    // Config Persistence
    std::string exportConfiguration() const;
    bool importConfiguration(const std::string& config);
    bool saveToFile(const std::string& filePath) const;
    bool loadFromFile(const std::string& filePath);

private:
    std::string generateJobId();
    std::string generateRunId();
    std::string generateDeploymentId();

    mutable std::mutex m_mutex;
    std::map<std::string, TrainingJob> m_jobs;
    std::map<std::string, JobRunLog> m_runLogs;
    std::map<std::string, std::vector<PipelineStage>> m_pipelines;
    std::map<std::string, DeploymentConfig> m_deploymentConfigs;
    std::map<std::string, std::string> m_artifacts;

    NotificationConfig m_notificationConfig;
    void* m_parent = nullptr;
    ShowCallback m_showCb = nullptr;
    void* m_showCtx = nullptr;
};

} // namespace RawrXD

