#pragma once
#include "../qtapp/integration/ProdIntegration.h"
#include <QObject>
#include <QString>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonArray>
#include <QUuid>
#include <QMutex>
#include <QMap>
#include <QQueue>
#include <functional>

namespace RawrXD {
namespace Integration {
namespace Agentic {

// Agent task status
enum class TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    Timeout
};

inline QString taskStatusToString(TaskStatus status) {
    switch (status) {
        case TaskStatus::Pending: return QStringLiteral("pending");
        case TaskStatus::Running: return QStringLiteral("running");
        case TaskStatus::Completed: return QStringLiteral("completed");
        case TaskStatus::Failed: return QStringLiteral("failed");
        case TaskStatus::Cancelled: return QStringLiteral("cancelled");
        case TaskStatus::Timeout: return QStringLiteral("timeout");
        default: return QStringLiteral("unknown");
    }
}

// Agent task tracking
struct AgentTask {
    QString taskId;
    QString agentId;
    QString taskType;
    QString description;
    TaskStatus status;
    QDateTime startTime;
    QDateTime endTime;
    qint64 durationMs;
    QJsonObject metadata;
    QString errorMessage;
    int retryCount;
    
    QJsonObject toJson() const {
        QJsonObject obj;
        obj.insert(QStringLiteral("task_id"), taskId);
        obj.insert(QStringLiteral("agent_id"), agentId);
        obj.insert(QStringLiteral("task_type"), taskType);
        obj.insert(QStringLiteral("description"), description);
        obj.insert(QStringLiteral("status"), taskStatusToString(status));
        obj.insert(QStringLiteral("start_time"), startTime.toString(Qt::ISODate));
        obj.insert(QStringLiteral("end_time"), endTime.toString(Qt::ISODate));
        obj.insert(QStringLiteral("duration_ms"), durationMs);
        obj.insert(QStringLiteral("metadata"), metadata);
        obj.insert(QStringLiteral("error_message"), errorMessage);
        obj.insert(QStringLiteral("retry_count"), retryCount);
        return obj;
    }
};

// Agent lifecycle tracker
class AgentLifecycleTracker {
public:
    static AgentLifecycleTracker& instance() {
        static AgentLifecycleTracker tracker;
        return tracker;
    }

    QString registerAgent(const QString& agentType, const QString& agentName = QString()) {
        QMutexLocker lock(&m_mutex);
        
        const QString agentId = QUuid::createUuid().toString(QUuid::WithoutBraces);
        
        AgentInfo info;
        info.id = agentId;
        info.type = agentType;
        info.name = agentName.isEmpty() ? agentType : agentName;
        info.registeredAt = QDateTime::currentDateTime();
        info.status = QStringLiteral("active");
        info.taskCount = 0;
        info.successCount = 0;
        info.failureCount = 0;
        
        m_agents[agentId] = info;
        
        if (Config::loggingEnabled()) {
            logInfo(QStringLiteral("AgentLifecycleTracker"), QStringLiteral("register"),
                    QStringLiteral("Agent registered: %1 (%2)").arg(agentId, agentType));
        }
        
        if (Config::metricsEnabled()) {
            recordMetric("agent_registered", 1);
        }
        
        return agentId;
    }

    void unregisterAgent(const QString& agentId) {
        QMutexLocker lock(&m_mutex);
        
        auto it = m_agents.find(agentId);
        if (it != m_agents.end()) {
            if (Config::loggingEnabled()) {
                logInfo(QStringLiteral("AgentLifecycleTracker"), QStringLiteral("unregister"),
                        QStringLiteral("Agent unregistered: %1 (tasks: %2, success: %3, failure: %4)")
                        .arg(agentId).arg(it->taskCount).arg(it->successCount).arg(it->failureCount));
            }
            
            m_agents.erase(it);
            
            if (Config::metricsEnabled()) {
                recordMetric("agent_unregistered", 1);
            }
        }
    }

    QString startTask(const QString& agentId, const QString& taskType, const QString& description = QString()) {
        QMutexLocker lock(&m_mutex);
        
        const QString taskId = QUuid::createUuid().toString(QUuid::WithoutBraces);
        
        AgentTask task;
        task.taskId = taskId;
        task.agentId = agentId;
        task.taskType = taskType;
        task.description = description;
        task.status = TaskStatus::Running;
        task.startTime = QDateTime::currentDateTime();
        task.retryCount = 0;
        
        m_tasks[taskId] = task;
        
        // Update agent info
        auto agentIt = m_agents.find(agentId);
        if (agentIt != m_agents.end()) {
            agentIt->taskCount++;
        }
        
        if (Config::loggingEnabled()) {
            logInfo(QStringLiteral("AgentLifecycleTracker"), QStringLiteral("task_start"),
                    QStringLiteral("Task started: %1 (agent: %2, type: %3)").arg(taskId, agentId, taskType));
        }
        
        if (Config::metricsEnabled()) {
            recordMetric("agent_task_started", 1);
        }
        
        return taskId;
    }

    void completeTask(const QString& taskId, bool success = true, const QString& errorMessage = QString()) {
        QMutexLocker lock(&m_mutex);
        
        auto taskIt = m_tasks.find(taskId);
        if (taskIt != m_tasks.end()) {
            taskIt->endTime = QDateTime::currentDateTime();
            taskIt->durationMs = taskIt->startTime.msecsTo(taskIt->endTime);
            taskIt->status = success ? TaskStatus::Completed : TaskStatus::Failed;
            taskIt->errorMessage = errorMessage;
            
            // Update agent stats
            auto agentIt = m_agents.find(taskIt->agentId);
            if (agentIt != m_agents.end()) {
                if (success) {
                    agentIt->successCount++;
                } else {
                    agentIt->failureCount++;
                }
            }
            
            if (Config::loggingEnabled()) {
                logInfo(QStringLiteral("AgentLifecycleTracker"), QStringLiteral("task_complete"),
                        QStringLiteral("Task completed: %1 (%2) in %3ms")
                        .arg(taskId).arg(success ? "success" : "failure").arg(taskIt->durationMs));
            }
            
            if (Config::metricsEnabled()) {
                const QString metricName = success ? QStringLiteral("agent_task_success") 
                                                  : QStringLiteral("agent_task_failure");
                recordMetric(metricName, 1);
                recordMetric("agent_task_duration_ms", taskIt->durationMs);
            }
        }
    }

    void updateTaskStatus(const QString& taskId, TaskStatus status, const QString& message = QString()) {
        QMutexLocker lock(&m_mutex);
        
        auto taskIt = m_tasks.find(taskId);
        if (taskIt != m_tasks.end()) {
            taskIt->status = status;
            if (!message.isEmpty()) {
                taskIt->errorMessage = message;
            }
            
            if (Config::loggingEnabled()) {
                logDebug(QStringLiteral("AgentLifecycleTracker"), QStringLiteral("task_update"),
                        QStringLiteral("Task %1 status: %2").arg(taskId, taskStatusToString(status)));
            }
        }
    }

    QJsonArray getActiveAgents() const {
        QMutexLocker lock(&m_mutex);
        
        QJsonArray result;
        for (const auto& agent : m_agents) {
            QJsonObject obj;
            obj.insert(QStringLiteral("id"), agent.id);
            obj.insert(QStringLiteral("type"), agent.type);
            obj.insert(QStringLiteral("name"), agent.name);
            obj.insert(QStringLiteral("status"), agent.status);
            obj.insert(QStringLiteral("registered_at"), agent.registeredAt.toString(Qt::ISODate));
            obj.insert(QStringLiteral("task_count"), agent.taskCount);
            obj.insert(QStringLiteral("success_count"), agent.successCount);
            obj.insert(QStringLiteral("failure_count"), agent.failureCount);
            result.append(obj);
        }
        
        return result;
    }

    QJsonArray getActiveTasks() const {
        QMutexLocker lock(&m_mutex);
        
        QJsonArray result;
        for (const auto& task : m_tasks) {
            if (task.status == TaskStatus::Running || task.status == TaskStatus::Pending) {
                result.append(task.toJson());
            }
        }
        
        return result;
    }

    QJsonArray getTaskHistory(int maxTasks = 100) const {
        QMutexLocker lock(&m_mutex);
        
        QJsonArray result;
        int count = 0;
        
        for (const auto& task : m_tasks) {
            if (count++ >= maxTasks) break;
            result.append(task.toJson());
        }
        
        return result;
    }

    QJsonObject getAgentStats(const QString& agentId) const {
        QMutexLocker lock(&m_mutex);
        
        QJsonObject stats;
        auto it = m_agents.find(agentId);
        if (it != m_agents.end()) {
            stats.insert(QStringLiteral("id"), it->id);
            stats.insert(QStringLiteral("type"), it->type);
            stats.insert(QStringLiteral("name"), it->name);
            stats.insert(QStringLiteral("task_count"), it->taskCount);
            stats.insert(QStringLiteral("success_count"), it->successCount);
            stats.insert(QStringLiteral("failure_count"), it->failureCount);
            stats.insert(QStringLiteral("success_rate"), 
                        it->taskCount > 0 ? static_cast<double>(it->successCount) / it->taskCount : 0.0);
        }
        
        return stats;
    }

private:
    struct AgentInfo {
        QString id;
        QString type;
        QString name;
        QDateTime registeredAt;
        QString status;
        int taskCount;
        int successCount;
        int failureCount;
    };

    AgentLifecycleTracker() = default;
    
    mutable QMutex m_mutex;
    QMap<QString, AgentInfo> m_agents;
    QMap<QString, AgentTask> m_tasks;
};

// RAII agent task wrapper
class ScopedAgentTask {
public:
    ScopedAgentTask(const QString& agentId, const QString& taskType, const QString& description = QString())
        : m_agentId(agentId) {
        m_taskId = AgentLifecycleTracker::instance().startTask(agentId, taskType, description);
    }

    ~ScopedAgentTask() {
        if (!m_completed) {
            AgentLifecycleTracker::instance().completeTask(m_taskId, true);
        }
    }

    void complete(bool success = true, const QString& errorMessage = QString()) {
        AgentLifecycleTracker::instance().completeTask(m_taskId, success, errorMessage);
        m_completed = true;
    }

    void updateStatus(TaskStatus status, const QString& message = QString()) {
        AgentLifecycleTracker::instance().updateTaskStatus(m_taskId, status, message);
    }

    QString taskId() const { return m_taskId; }

private:
    QString m_agentId;
    QString m_taskId;
    bool m_completed = false;
};

// Agent communication tracker (for multi-agent coordination)
class AgentCommunicationTracker {
public:
    static AgentCommunicationTracker& instance() {
        static AgentCommunicationTracker tracker;
        return tracker;
    }

    void recordMessage(const QString& fromAgent, const QString& toAgent, 
                       const QString& messageType, const QJsonObject& payload = QJsonObject()) {
        if (!Config::loggingEnabled()) return;
        
        QJsonObject msg;
        msg.insert(QStringLiteral("from"), fromAgent);
        msg.insert(QStringLiteral("to"), toAgent);
        msg.insert(QStringLiteral("type"), messageType);
        msg.insert(QStringLiteral("timestamp"), QDateTime::currentDateTime().toString(Qt::ISODate));
        msg.insert(QStringLiteral("payload"), payload);
        
        logDebug(QStringLiteral("AgentCommunicationTracker"), QStringLiteral("message"),
                QStringLiteral("%1 -> %2: %3").arg(fromAgent, toAgent, messageType));
        
        if (Config::metricsEnabled()) {
            recordMetric("agent_message_sent", 1);
        }
    }

    void recordBroadcast(const QString& fromAgent, const QString& messageType, 
                        int recipientCount, const QJsonObject& payload = QJsonObject()) {
        if (!Config::loggingEnabled()) return;
        
        logDebug(QStringLiteral("AgentCommunicationTracker"), QStringLiteral("broadcast"),
                QStringLiteral("%1 broadcast %2 to %3 agents")
                .arg(fromAgent, messageType).arg(recipientCount));
        
        if (Config::metricsEnabled()) {
            recordMetric("agent_broadcast", 1);
            recordMetric("agent_broadcast_recipients", recipientCount);
        }
    }

private:
    AgentCommunicationTracker() = default;
};

} // namespace Agentic
} // namespace Integration
} // namespace RawrXD
