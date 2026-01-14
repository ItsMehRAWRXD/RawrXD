/**
 * @file AgentOrchestrator.h
 * @brief Complete Multi-Agent AI Coordination System for RawrXD Agentic IDE
 * 
 * Provides orchestration and coordination for multiple AI agents working together:
 * - Task delegation and coordination between agents
 * - Agent lifecycle management (spawn, monitor, terminate)
 * - Inter-agent communication and message routing
 * - Agent resource allocation and load balancing
 * - Conflict resolution and consensus building
 * - Performance monitoring and optimization
 * 
 * @author RawrXD Team
 * @copyright 2024 RawrXD
 */

#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QMap>
#include <QHash>
#include <QSet>
#include <QList>
#include <QJsonObject>
#include <QJsonDocument>
#include <QTimer>
#include <QThread>
#include <QProcess>
#include <QMutex>
#include <QQueue>
#include <QPair>
#include <memory>
#include <functional>

namespace RawrXD {

/**
 * @brief Types of AI agents
 */
enum class AgentType {
    CodeAnalyzer,       ///< Code analysis and review
    BugDetector,        ///< Bug detection and reporting
    Refactorer,         ///< Code refactoring assistance
    TestGenerator,      ///< Test case generation
    Documenter,         ///< Documentation generation
    PerformanceOptimizer, ///< Performance optimization
    SecurityAuditor,    ///< Security analysis
    CodeCompleter,      ///< Code completion and suggestions
    TaskPlanner,        ///< Task planning and execution
    CodeReviewer,       ///< Code review and quality assurance
    DependencyAnalyzer, ///< Dependency analysis
    MigrationAssistant,  ///< Code migration assistance
    Custom              ///< Custom agent type
};

/**
 * @brief Agent capabilities
 */
enum class AgentCapability {
    CodeAnalysis,       ///< Parse and analyze code
    PatternMatching,    ///< Identify code patterns
    Refactoring,        ///< Perform code refactoring
    Testing,           ///< Generate and run tests
    Documentation,     ///< Generate documentation
    Performance,       ///< Analyze performance
    Security,          ///< Security analysis
    Completion,        ///< Code completion
    Planning,          ///< Task planning
    Review,           ///< Code review
    Migration,        ///< Code migration
    Custom            ///< Custom capability
};

/**
 * @brief Agent status
 */
enum class AgentStatus {
    Idle,              ///< Agent is idle and available
    Busy,              ///< Agent is processing a task
    Waiting,           ///< Agent is waiting for input
    Error,             ///< Agent encountered an error
    Terminated,        ///< Agent has been terminated
    Maintenance        ///< Agent is under maintenance
};

/**
 * @brief Task priority levels
 */
enum class TaskPriority {
    Low,               ///< Low priority task
    Normal,           ///< Normal priority task
    High,             ///< High priority task
    Critical,         ///< Critical priority task
    Emergency         ///< Emergency priority task
};

/**
 * @brief Task types
 */
enum class TaskType {
    Analysis,          ///< Code analysis task
    Generation,        ///< Code generation task
    Refactoring,       ///< Refactoring task
    Testing,          ///< Testing task
    Documentation,    ///< Documentation task
    Optimization,     ///< Optimization task
    Security,         ///< Security task
    Review,           ///< Review task
    Migration,        ///< Migration task
    Custom            ///< Custom task type
};

/**
 * @brief Represents an AI agent
 */
class Agent {
public:
    Agent();
    Agent(const QString& id, AgentType type, const QString& name);
    
    QString id() const { return m_id; }
    void setId(const QString& id) { m_id = id; }
    
    QString name() const { return m_name; }
    void setName(const QString& name) { m_name = name; }
    
    AgentType type() const { return m_type; }
    void setType(AgentType type) { m_type = type; }
    
    AgentStatus status() const { return m_status; }
    void setStatus(AgentStatus status) { m_status = status; }
    
    QString description() const { return m_description; }
    void setDescription(const QString& desc) { m_description = desc; }
    
    QSet<AgentCapability> capabilities() const { return m_capabilities; }
    void addCapability(AgentCapability capability);
    void removeCapability(AgentCapability capability);
    bool hasCapability(AgentCapability capability) const;
    
    QString version() const { return m_version; }
    void setVersion(const QString& version) { m_version = version; }
    
    QString configuration() const { return m_configuration; }
    void setConfiguration(const QString& config) { m_configuration = config; }
    
    double cpuUsage() const { return m_cpuUsage; }
    void setCpuUsage(double usage) { m_cpuUsage = usage; }
    
    double memoryUsage() const { return m_memoryUsage; }
    void setMemoryUsage(double usage) { m_memoryUsage = usage; }
    
    int activeTasks() const { return m_activeTasks; }
    void setActiveTasks(int tasks) { m_activeTasks = tasks; }
    
    int maxConcurrentTasks() const { return m_maxConcurrentTasks; }
    void setMaxConcurrentTasks(int max) { m_maxConcurrentTasks = max; }
    
    QJsonObject metadata() const { return m_metadata; }
    void setMetadata(const QJsonObject& metadata) { m_metadata = metadata; }
    
    QDateTime lastActivity() const { return m_lastActivity; }
    void setLastActivity(const QDateTime& time) { m_lastActivity = time; }
    
    bool isHealthy() const;
    bool isAvailable() const;
    
private:
    QString m_id;
    QString m_name;
    AgentType m_type;
    AgentStatus m_status;
    QString m_description;
    QSet<AgentCapability> m_capabilities;
    QString m_version;
    QString m_configuration;
    double m_cpuUsage;
    double m_memoryUsage;
    int m_activeTasks;
    int m_maxConcurrentTasks;
    QJsonObject m_metadata;
    QDateTime m_lastActivity;
};

/**
 * @brief Represents a task to be executed by agents
 */
class AgentTask {
public:
    AgentTask();
    AgentTask(const QString& id, TaskType type, const QString& description);
    
    QString id() const { return m_id; }
    void setId(const QString& id) { m_id = id; }
    
    TaskType type() const { return m_type; }
    void setType(TaskType type) { m_type = type; }
    
    QString description() const { return m_description; }
    void setDescription(const QString& desc) { m_description = desc; }
    
    TaskPriority priority() const { return m_priority; }
    void setPriority(TaskPriority priority) { m_priority = priority; }
    
    QString requester() const { return m_requester; }
    void setRequester(const QString& requester) { m_requester = requester; }
    
    QJsonObject parameters() const { return m_parameters; }
    void setParameters(const QJsonObject& params) { m_parameters = params; }
    
    QStringList requiredCapabilities() const { return m_requiredCapabilities; }
    void setRequiredCapabilities(const QStringList& capabilities) { m_requiredCapabilities = capabilities; }
    
    QStringList assignedAgents() const { return m_assignedAgents; }
    void assignAgent(const QString& agentId);
    void unassignAgent(const QString& agentId);
    void setAssignedAgents(const QStringList& agents) { m_assignedAgents = agents; }
    
    AgentStatus status() const { return m_status; }
    void setStatus(AgentStatus status) { m_status = status; }
    
    QJsonObject result() const { return m_result; }
    void setResult(const QJsonObject& result) { m_result = result; }
    
    QString errorMessage() const { return m_errorMessage; }
    void setErrorMessage(const QString& error) { m_errorMessage = error; }
    
    QDateTime createdAt() const { return m_createdAt; }
    void setCreatedAt(const QDateTime& time) { m_createdAt = time; }
    
    QDateTime startedAt() const { return m_startedAt; }
    void setStartedAt(const QDateTime& time) { m_startedAt = time; }
    
    QDateTime completedAt() const { return m_completedAt; }
    void setCompletedAt(const QDateTime& time) { m_completedAt = time; }
    
    int progress() const { return m_progress; }
    void setProgress(int progress) { m_progress = qBound(0, progress, 100); }
    
    bool isCompleted() const;
    bool isFailed() const;
    bool isInProgress() const;
    
private:
    QString m_id;
    TaskType m_type;
    QString m_description;
    TaskPriority m_priority;
    QString m_requester;
    QJsonObject m_parameters;
    QStringList m_requiredCapabilities;
    QStringList m_assignedAgents;
    AgentStatus m_status;
    QJsonObject m_result;
    QString m_errorMessage;
    QDateTime m_createdAt;
    QDateTime m_startedAt;
    QDateTime m_completedAt;
    int m_progress;
};

/**
 * @brief Inter-agent communication message
 */
class AgentMessage {
public:
    AgentMessage();
    AgentMessage(const QString& from, const QString& to, const QString& type);
    
    QString from() const { return m_from; }
    void setFrom(const QString& from) { m_from = from; }
    
    QString to() const { return m_to; }
    void setTo(const QString& to) { m_to = to; }
    
    QString type() const { return m_type; }
    void setType(const QString& type) { m_type = type; }
    
    QString content() const { return m_content; }
    void setContent(const QString& content) { m_content = content; }
    
    QJsonObject metadata() const { return m_metadata; }
    void setMetadata(const QJsonObject& metadata) { m_metadata = metadata; }
    
    QString correlationId() const { return m_correlationId; }
    void setCorrelationId(const QString& id) { m_correlationId = id; }
    
    QDateTime timestamp() const { return m_timestamp; }
    void setTimestamp(const QDateTime& time) { m_timestamp = time; }
    
    bool isBroadcast() const { return m_to.isEmpty() || m_to == QStringLiteral("*"); }
    
private:
    QString m_from;
    QString m_to;
    QString m_type;
    QString m_content;
    QJsonObject m_metadata;
    QString m_correlationId;
    QDateTime m_timestamp;
};

/**
 * @brief Agent orchestration configuration
 */
struct AgentOrchestrationConfig {
    int maxAgents;
    int maxConcurrentTasks;
    int taskTimeoutMs;
    int healthCheckIntervalMs;
    bool enableLoadBalancing;
    bool enableAutoScaling;
    bool enableConflictResolution;
    bool enableConsensusBuilding;
    QString logLevel;
    
    AgentOrchestrationConfig() : maxAgents(10), maxConcurrentTasks(50), taskTimeoutMs(300000), 
                                healthCheckIntervalMs(30000), enableLoadBalancing(true),
                                enableAutoScaling(false), enableConflictResolution(true),
                                enableConsensusBuilding(true), logLevel(QStringLiteral("INFO")) {}
};

/**
 * @brief Complete Multi-Agent AI Orchestration System
 * 
 * Provides comprehensive coordination for multiple AI agents:
 * - Agent lifecycle management (create, monitor, terminate)
 * - Task distribution and load balancing
 * - Inter-agent communication and coordination
 * - Conflict resolution and consensus building
 * - Performance monitoring and optimization
 * - Resource management and scaling
 * 
 * Thread-safe with built-in monitoring and health checks.
 */
class AgentOrchestrator : public QObject {
    Q_OBJECT
    
public:
    /**
     * @brief Construct an AgentOrchestrator
     * @param parent Parent QObject
     */
    explicit AgentOrchestrator(QObject* parent = nullptr);
    
    /**
     * @brief Destructor
     */
    ~AgentOrchestrator() override;
    
    /**
     * @brief Initialize the orchestrator
     * @param config Configuration
     * @return true if initialization successful
     */
    bool initialize(const AgentOrchestrationConfig& config);
    
    /**
     * @brief Shutdown the orchestrator
     */
    void shutdown();
    
    /**
     * @brief Register a new agent
     * @param type Agent type
     * @param name Agent name
     * @param capabilities Agent capabilities
     * @param configuration Agent configuration
     * @return Agent ID if successful, empty string otherwise
     */
    QString registerAgent(AgentType type, const QString& name, 
                         const QSet<AgentCapability>& capabilities,
                         const QString& configuration = QString());
    
    /**
     * @brief Unregister an agent
     * @param agentId Agent ID
     * @return true if successful
     */
    bool unregisterAgent(const QString& agentId);
    
    /**
     * @brief Get agent by ID
     * @param agentId Agent ID
     * @return Agent object
     */
    Agent getAgent(const QString& agentId) const;
    
    /**
     * @brief Get all registered agents
     * @return List of agents
     */
    QList<Agent> getAgents() const;
    
    /**
     * @brief Get agents by type
     * @param type Agent type
     * @return List of agents
     */
    QList<Agent> getAgentsByType(AgentType type) const;
    
    /**
     * @brief Get available agents for a task
     * @param capabilities Required capabilities
     * @param maxAgents Maximum number of agents
     * @return List of available agents
     */
    QList<Agent> getAvailableAgents(const QSet<AgentCapability>& capabilities, int maxAgents = 1) const;
    
    /**
     * @brief Submit a task for execution
     * @param type Task type
     * @param description Task description
     * @param parameters Task parameters
     * @param requiredCapabilities Required agent capabilities
     * @param priority Task priority
     * @param requester Requester ID
     * @return Task ID if successful, empty string otherwise
     */
    QString submitTask(TaskType type, const QString& description,
                      const QJsonObject& parameters,
                      const QSet<AgentCapability>& requiredCapabilities,
                      TaskPriority priority = TaskPriority::Normal,
                      const QString& requester = QString());
    
    /**
     * @brief Get task by ID
     * @param taskId Task ID
     * @return Task object
     */
    AgentTask getTask(const QString& taskId) const;
    
    /**
     * @brief Get all tasks
     * @return List of tasks
     */
    QList<AgentTask> getTasks() const;
    
    /**
     * @brief Get tasks by status
     * @param status Task status
     * @return List of tasks
     */
    QList<AgentTask> getTasksByStatus(AgentStatus status) const;
    
    /**
     * @brief Cancel a task
     * @param taskId Task ID
     * @return true if successful
     */
    bool cancelTask(const QString& taskId);
    
    /**
     * @brief Send message between agents
     * @param from Source agent ID
     * @param to Target agent ID (empty for broadcast)
     * @param type Message type
     * @param content Message content
     * @param metadata Additional metadata
     * @return true if successful
     */
    bool sendMessage(const QString& from, const QString& to, const QString& type,
                    const QString& content, const QJsonObject& metadata = QJsonObject());
    
    /**
     * @brief Broadcast message to all agents
     * @param from Source agent ID
     * @param type Message type
     * @param content Message content
     * @param metadata Additional metadata
     * @return true if successful
     */
    bool broadcastMessage(const QString& from, const QString& type, const QString& content,
                         const QJsonObject& metadata = QJsonObject());
    
    /**
     * @brief Get message history
     * @param agentId Agent ID (empty for all agents)
     * @param limit Maximum number of messages
     * @return List of messages
     */
    QList<AgentMessage> getMessageHistory(const QString& agentId = QString(), int limit = 100) const;
    
    /**
     * @brief Request consensus on a decision
     * @param decision Decision description
     * @param agents Agents to involve
     * @param callback Callback when consensus reached
     * @return Consensus request ID
     */
    QString requestConsensus(const QString& decision, const QStringList& agents,
                           std::function<void(bool, const QJsonObject&)> callback);
    
    /**
     * @brief Resolve conflict between agents
     * @param conflictType Type of conflict
     * @param agents Involved agents
     * @param context Conflict context
     * @param callback Callback when resolved
     * @return Conflict resolution ID
     */
    QString resolveConflict(const QString& conflictType, const QStringList& agents,
                          const QJsonObject& context,
                          std::function<void(const QJsonObject&)> callback);
    
    /**
     * @brief Scale up/down agent pool
     * @param agentType Agent type to scale
     * @param targetCount Target number of agents
     * @return true if scaling initiated
     */
    bool scaleAgents(AgentType agentType, int targetCount);
    
    /**
     * @brief Get orchestration statistics
     * @return Statistics object
     */
    QJsonObject getStatistics() const;
    
    /**
     * @brief Set orchestration configuration
     * @param config Configuration
     */
    void setConfiguration(const AgentOrchestrationConfig& config);
    
    /**
     * @brief Get orchestration configuration
     * @return Configuration
     */
    AgentOrchestrationConfig configuration() const;
    
signals:
    /**
     * @brief Emitted when agent status changes
     * @param agentId Agent ID
     * @param oldStatus Previous status
     * @param newStatus New status
     */
    void agentStatusChanged(const QString& agentId, AgentStatus oldStatus, AgentStatus newStatus);
    
    /**
     * @brief Emitted when task status changes
     * @param taskId Task ID
     * @param oldStatus Previous status
     * @param newStatus New status
     * @param progress Progress percentage
     */
    void taskStatusChanged(const QString& taskId, AgentStatus oldStatus, AgentStatus newStatus, int progress);
    
    /**
     * @brief Emitted when task is completed
     * @param taskId Task ID
     * @param result Task result
     */
    void taskCompleted(const QString& taskId, const QJsonObject& result);
    
    /**
     * @brief Emitted when task fails
     * @param taskId Task ID
     * @param error Error message
     */
    void taskFailed(const QString& taskId, const QString& error);
    
    /**
     * @brief Emitted when message is received
     * @param message Message object
     */
    void messageReceived(const AgentMessage& message);
    
    /**
     * @brief Emitted when consensus is reached
     * @param requestId Consensus request ID
     * @param reached Whether consensus was reached
     * @param result Consensus result
     */
    void consensusReached(const QString& requestId, bool reached, const QJsonObject& result);
    
    /**
     * @brief Emitted when conflict is resolved
     * @param conflictId Conflict resolution ID
     * @param resolution Resolution object
     */
    void conflictResolved(const QString& conflictId, const QJsonObject& resolution);
    
    /**
     * @brief Emitted when error occurs
     * @param error Error message
     * @param errorCode Error code
     */
    void error(const QString& error, int errorCode = -1);
    
private slots:
    void onHealthCheckTimer();
    void onTaskTimeoutTimer();
    void onLoadBalancingTimer();
    
private:
    /**
     * @brief Initialize default agents
     */
    void initializeDefaultAgents();
    
    /**
     * @brief Find best agent for task
     * @param task Task to assign
     * @return Agent ID if found, empty string otherwise
     */
    QString findBestAgent(const AgentTask& task) const;
    
    /**
     * @brief Assign task to agent
     * @param taskId Task ID
     * @param agentId Agent ID
     * @return true if successful
     */
    bool assignTask(const QString& taskId, const QString& agentId);
    
    /**
     * @brief Process task queue
     */
    void processTaskQueue();
    
    /**
     * @brief Check agent health
     * @param agentId Agent ID
     * @return true if healthy
     */
    bool checkAgentHealth(const QString& agentId) const;
    
    /**
     * @brief Load balance agents
     */
    void loadBalanceAgents();
    
    /**
     * @brief Clean up completed/failed tasks
     */
    void cleanupTasks();
    
    /**
     * @brief Generate unique ID
     */
    QString generateId() const;
    
    /**
     * @brief Validate agent capabilities
     * @param agentId Agent ID
     * @param requiredCapabilities Required capabilities
     * @return true if agent has all required capabilities
     */
    bool validateAgentCapabilities(const QString& agentId, const QSet<AgentCapability>& requiredCapabilities) const;
    
    // Member variables
    AgentOrchestrationConfig m_config;
    QMap<QString, Agent> m_agents;
    QMap<QString, AgentTask> m_tasks;
    QQueue<QString> m_taskQueue;
    QList<AgentMessage> m_messageHistory;
    QMap<QString, std::function<void(const QJsonObject&)>> m_consensusCallbacks;
    QMap<QString, std::function<void(const QJsonObject&)>> m_conflictResolutionCallbacks;
    
    // Timers
    QTimer* m_healthCheckTimer;
    QTimer* m_taskTimeoutTimer;
    QTimer* m_loadBalancingTimer;
    
    // Thread safety
    mutable QMutex m_mutex;
    
    // Statistics
    int m_totalTasksSubmitted;
    int m_totalTasksCompleted;
    int m_totalTasksFailed;
    qint64 m_totalProcessingTime;
    
    // Constants
    static constexpr int MAX_MESSAGE_HISTORY = 1000;
    static constexpr int DEFAULT_TASK_TIMEOUT = 300000; // 5 minutes
    static constexpr int DEFAULT_HEALTH_CHECK_INTERVAL = 30000; // 30 seconds
};

} // namespace RawrXD
