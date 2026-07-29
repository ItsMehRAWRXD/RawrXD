<<<<<<< HEAD
#pragma once
/*  TaskOrchestrator.h  -  RollarCoaster AI Orchestration (C++20, no Qt)
    
    Natural language task → task splitting → model selection → parallel execution.
*/

#include <functional>
#include <map>
#include <string>
#include <vector>

class MainWindow;

namespace RawrXD {
namespace Backend {
struct ToolResult;
struct AgenticToolExecutor;
}

struct TaskDefinition {
    std::string id;
    std::string description;
    std::string model;
    std::string type;
    int priority = 5;
    int estimatedTokens = 1000;
    std::string parameters;   // JSON-serialized (replaces QJsonObject)
    int64_t memoryLimit = 0;
    std::string memoryStrategy = "balanced";
};

struct OrchestrationResult {
    std::string taskId;
    std::string model;
    std::string result;
    bool success = false;
    std::string error;
    int executionTime = 0;
};

class TaskOrchestrator {
public:
    explicit TaskOrchestrator(MainWindow* parent = nullptr);
    ~TaskOrchestrator();

    void orchestrateTask(const std::string& naturalLanguageDescription);

    RawrXD::Backend::ToolResult executeTool(const std::string& toolName, const std::string& paramsJson);

    std::vector<std::string> getAvailableModels() const;
    bool isModelAvailable(const std::string& model) const;
    void setModelPreferences(const std::map<std::string, int>& preferences);

    std::vector<TaskDefinition> getCurrentTasks() const;
    OrchestrationResult getTaskResult(const std::string& taskId) const;
    void cancelTask(const std::string& taskId);

    void setMemoryProfile(const std::string& profileName);
    void setGlobalMemoryLimit(int64_t limitBytes);
    void setTaskMemoryStrategy(const std::string& strategy);
    int64_t getAvailableMemory() const;
    int64_t getTotalMemoryUsage() const;
    bool canAllocateMemory(int64_t requestedBytes) const;
    void allocateTaskMemory(const std::string& taskId, int64_t bytes);
    void releaseTaskMemory(const std::string& taskId);

    std::vector<TaskDefinition> decomposeComplexTask(const std::string& description);
    std::vector<TaskDefinition> createMemoryAwareSubtasks(const TaskDefinition& mainTask);
    int calculateOptimalParallelism() const;

    using TaskSplitCompletedFn = std::function<void(const std::vector<TaskDefinition>&)>;
    using ModelSelectionCompletedFn = std::function<void(const std::map<std::string, std::string>&)>;
    using TabCreatedFn = std::function<void(const std::string& tabName, const std::string& model)>;
    using TaskStartedFn = std::function<void(const std::string& taskId, const std::string& model)>;
    using TaskProgressFn = std::function<void(const std::string& taskId, int progress)>;
    using TaskCompletedFn = std::function<void(const OrchestrationResult&)>;
    using OrchestrationCompletedFn = std::function<void(const std::vector<OrchestrationResult>&)>;
    using ErrorFn = std::function<void(const std::string&)>;

    void setOnTaskSplitCompleted(TaskSplitCompletedFn fn) { m_onTaskSplitCompleted = std::move(fn); }
    void setOnModelSelectionCompleted(ModelSelectionCompletedFn fn) { m_onModelSelectionCompleted = std::move(fn); }
    void setOnTabCreated(TabCreatedFn fn) { m_onTabCreated = std::move(fn); }
    void setOnTaskStarted(TaskStartedFn fn) { m_onTaskStarted = std::move(fn); }
    void setOnTaskProgress(TaskProgressFn fn) { m_onTaskProgress = std::move(fn); }
    void setOnTaskCompleted(TaskCompletedFn fn) { m_onTaskCompleted = std::move(fn); }
    void setOnOrchestrationCompleted(OrchestrationCompletedFn fn) { m_onOrchestrationCompleted = std::move(fn); }
    void setOnErrorOccurred(ErrorFn fn) { m_onErrorOccurred = std::move(fn); }

private:
    void handleTaskSplitResponse(void* reply);
    void handleModelResponse(void* reply, const std::string& taskId);
    void handleTaskCompletion(const std::string& taskId, const std::string& result);

    std::vector<TaskDefinition> parseNaturalLanguage(const std::string& description);
    std::string determineTaskType(const std::string& description);
    int estimateTokenCount(const std::string& description);

    std::string selectModelForTask(const TaskDefinition& task);
    std::map<std::string, int> getModelCapabilities() const;
    void balanceWorkload(std::vector<TaskDefinition>& tasks);

    void executeTask(const TaskDefinition& task);
    void createExecutionTab(const TaskDefinition& task);
    void sendToRollarCoaster(const std::string& model, const std::string& prompt);

    std::string generateTaskId() const;
    std::string createRollarCoasterRequest(const std::string& model, const std::string& prompt) const;

    MainWindow* m_mainWindow = nullptr;
    void* m_networkManager = nullptr;  // WinHTTP or similar

    RawrXD::Backend::AgenticToolExecutor* m_toolExecutor = nullptr;

    std::string m_rollarCoasterEndpoint;
    int m_maxParallelTasks = 4;
    int m_taskTimeout = 60000;

    std::string m_memoryProfile;
    int64_t m_globalMemoryLimit = 0;
    std::string m_defaultMemoryStrategy;
    std::map<std::string, int64_t> m_taskMemoryUsage;
    int64_t m_totalMemoryAllocated = 0;

    std::map<std::string, TaskDefinition> m_activeTasks;
    std::map<std::string, OrchestrationResult> m_completedTasks;
    std::map<std::string, int> m_modelWorkloads;
    std::map<std::string, int> m_modelPreferences;
    std::map<std::string, std::vector<std::string>> m_modelCapabilities;
    std::map<std::string, std::map<std::string, int64_t>> m_memoryProfiles;

    TaskSplitCompletedFn m_onTaskSplitCompleted;
    ModelSelectionCompletedFn m_onModelSelectionCompleted;
    TabCreatedFn m_onTabCreated;
    TaskStartedFn m_onTaskStarted;
    TaskProgressFn m_onTaskProgress;
    TaskCompletedFn m_onTaskCompleted;
    OrchestrationCompletedFn m_onOrchestrationCompleted;
    ErrorFn m_onErrorOccurred;
};

} // namespace RawrXD
=======
#pragma once
/*  TaskOrchestrator.h  -  RollarCoaster AI Orchestration System
    
    This orchestrator enables natural language task description → automatic task splitting → 
    model selection → parallel execution across multiple IDE tabs.
    
    Features:
    - Natural language parsing and intent recognition
    - Intelligent task decomposition into subtasks
    - Model selection based on task type (codellama, deepseek-coder, your-custom-model, mock-model)
    - Dynamic tab creation for parallel execution
    - Workload balancing across available models
    - Real-time progress tracking and result aggregation
    
    Integration with RollarCoaster AI system via ports 11438-11439
*/

#include <QObject>
#include <QString>
#include <QList>
#include <QHash>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkAccessManager>
#include <QNetworkReply>

// Agentic tool executor for autonomous operations (backend implementation)
#include "backend/agentic_tools.h"

class MainWindow;

namespace RawrXD {

struct TaskDefinition {
    QString id;
    QString description;
    QString model;           // Selected model: codellama, deepseek-coder, your-custom-model, mock-model
    QString type;           // Task type: code_generation, explanation, refactoring, analysis, etc.
    int priority;           // Priority level (1-10)
    int estimatedTokens;    // Estimated token count
    QJsonObject parameters; // Task-specific parameters
    
    // Memory management
    qint64 memoryLimit;     // Memory limit in bytes (0 = unlimited)
    QString memoryStrategy; // Memory allocation strategy: "conservative", "balanced", "aggressive"
    
    TaskDefinition() : priority(5), estimatedTokens(1000), memoryLimit(0), memoryStrategy("balanced") {}
};

struct OrchestrationResult {
    QString taskId;
    QString model;
    QString result;
    bool success;
    QString error;
    int executionTime;      // Execution time in milliseconds
    
    OrchestrationResult() : success(false), executionTime(0) {}
};

class TaskOrchestrator : public QObject
{
    Q_OBJECT

public:
    explicit TaskOrchestrator(MainWindow* parent = nullptr);
    ~TaskOrchestrator();

    // Main orchestration method
    void orchestrateTask(const QString& naturalLanguageDescription);

    // Expose tool execution (agentic/autonomous) similar to AgenticChat
    RawrXD::Backend::ToolResult executeTool(const QString& toolName, const QJsonObject& params);
    
    // Model management
    QList<QString> getAvailableModels() const;
    bool isModelAvailable(const QString& model) const;
    void setModelPreferences(const QHash<QString, int>& preferences);
    
    // Task management
    QList<TaskDefinition> getCurrentTasks() const;
    OrchestrationResult getTaskResult(const QString& taskId) const;
    void cancelTask(const QString& taskId);
    
    // Memory management
    void setMemoryProfile(const QString& profileName);
    void setGlobalMemoryLimit(qint64 limitBytes);
    void setTaskMemoryStrategy(const QString& strategy);
    qint64 getAvailableMemory() const;
    qint64 getTotalMemoryUsage() const;
    bool canAllocateMemory(qint64 requestedBytes) const;
    void allocateTaskMemory(const QString& taskId, qint64 bytes);
    void releaseTaskMemory(const QString& taskId);
    
    // Enhanced task decomposition
    QList<TaskDefinition> decomposeComplexTask(const QString& description);
    QList<TaskDefinition> createMemoryAwareSubtasks(const TaskDefinition& mainTask);
    int calculateOptimalParallelism() const;

signals:
    void taskSplitCompleted(const QList<TaskDefinition>& tasks);
    void modelSelectionCompleted(const QHash<QString, QString>& modelAssignments);
    void tabCreated(const QString& tabName, const QString& model);
    void taskStarted(const QString& taskId, const QString& model);
    void taskProgress(const QString& taskId, int progress);
    void taskCompleted(const OrchestrationResult& result);
    void orchestrationCompleted(const QList<OrchestrationResult>& results);
    void errorOccurred(const QString& errorMessage);

private slots:
    void handleTaskSplitResponse(QNetworkReply* reply);
    void handleModelResponse(QNetworkReply* reply, const QString& taskId);
    void handleTaskCompletion(const QString& taskId, const QString& result);

private:
    // Task parsing and splitting
    QList<TaskDefinition> parseNaturalLanguage(const QString& description);
    QString determineTaskType(const QString& description);
    int estimateTokenCount(const QString& description);
    
    // Model selection
    QString selectModelForTask(const TaskDefinition& task);
    QHash<QString, int> getModelCapabilities() const;
    void balanceWorkload(QList<TaskDefinition>& tasks);
    
    // Execution management
    void executeTask(const TaskDefinition& task);
    void createExecutionTab(const TaskDefinition& task);
    void sendToRollarCoaster(const QString& model, const QString& prompt);
    
    // Utility methods
    QString generateTaskId() const;
    QJsonObject createRollarCoasterRequest(const QString& model, const QString& prompt) const;
    
    MainWindow* m_mainWindow;
    QNetworkAccessManager* m_networkManager;

    // Agentic tool executor for autonomous tool access
    RawrXD::Backend::AgenticToolExecutor m_toolExecutor;
    
    // Configuration
    QString m_rollarCoasterEndpoint;
    int m_maxParallelTasks;
    int m_taskTimeout;
    
    // Memory management
    QString m_memoryProfile;           // Current memory profile: "minimal", "standard", "large", "unlimited"
    qint64 m_globalMemoryLimit;        // Global memory limit in bytes
    QString m_defaultMemoryStrategy;   // Default memory strategy
    QHash<QString, qint64> m_taskMemoryUsage; // Memory usage per task
    qint64 m_totalMemoryAllocated;     // Total memory currently allocated
    
    // State management
    QHash<QString, TaskDefinition> m_activeTasks;
    QHash<QString, OrchestrationResult> m_completedTasks;
    QHash<QString, int> m_modelWorkloads;
    QHash<QString, int> m_modelPreferences;
    
    // Model capabilities mapping
    QHash<QString, QList<QString>> m_modelCapabilities;
    
    // Memory profiles (KB to GB ranges)
    QHash<QString, QHash<QString, qint64>> m_memoryProfiles;
};

} // namespace RawrXD
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
