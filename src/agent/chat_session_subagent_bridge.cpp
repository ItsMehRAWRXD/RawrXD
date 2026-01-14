#include "chat_session_subagent_bridge.hpp"
#include "subagent_task_distributor.hpp"
#include <QDebug>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMutex>

// ============================================================================
// ChatSessionSubagentBridge Implementation
// ============================================================================

ChatSessionSubagentBridge::ChatSessionSubagentBridge(QObject* parent)
    : QObject(parent)
{
    qInfo() << "[ChatSessionSubagentBridge] Initialized";
}

ChatSessionSubagentBridge::~ChatSessionSubagentBridge()
{
    QMutexLocker locker(&m_mutex);
    
    // Clean up all sessions
    for (const auto& sessionId : m_coordinators.keys()) {
        locker.unlock();
        cleanupSession(sessionId);
        locker.relock();
    }
}

void ChatSessionSubagentBridge::initializeForSession(const QString& sessionId, int initialSubagents)
{
    QMutexLocker locker(&m_mutex);
    
    if (m_coordinators.contains(sessionId)) {
        qWarning() << "[ChatSessionSubagentBridge] Session already initialized:" << sessionId;
        return;
    }
    
    locker.unlock();
    
    // Create new coordinator for this session
    auto coordinator = std::make_shared<MultitaskingCoordinator>(sessionId, this);
    
    // Connect signals
    connect(coordinator.get(), &MultitaskingCoordinator::taskCompleted,
            this, [this, sessionId](const QString& taskId, const QJsonObject& result) {
                emit taskCompleted(sessionId, taskId, QString::fromUtf8(QJsonDocument(result).toJson(QJsonDocument::Compact)));
                onMultitaskingTaskCompleted(taskId, QString::fromUtf8(QJsonDocument(result).toJson(QJsonDocument::Compact)));
            });
    
    connect(coordinator.get(), &MultitaskingCoordinator::taskFailed,
            this, [this, sessionId](const QString& taskId, const QString& error) {
                emit taskFailed(sessionId, taskId, error);
                onMultitaskingTaskFailed(taskId, error);
            });
    
    connect(coordinator.get(), &MultitaskingCoordinator::taskProgress,
            this, [this, sessionId](const QString& taskId, double percentComplete) {
                emit taskProgressUpdated(sessionId, taskId, percentComplete);
                onMultitaskingTaskProgress(taskId, percentComplete);
            });
    
    connect(coordinator.get(), &MultitaskingCoordinator::subagentAdded,
            this, [this, sessionId](int totalCount) {
                emit subagentAdded(sessionId, totalCount);
                onSubagentAdded(totalCount);
            });
    
    connect(coordinator.get(), &MultitaskingCoordinator::subagentRemoved,
            this, [this, sessionId](int totalCount) {
                emit subagentRemoved(sessionId, totalCount);
                onSubagentRemoved(totalCount);
            });
    
    connect(coordinator.get(), &MultitaskingCoordinator::resourceWarning,
            this, [this, sessionId](const QString& resourceType, double usage) {
                emit resourceWarning(sessionId, resourceType, usage);
                onResourceWarning(resourceType, usage);
            });
    
    // Initialize subagents
    coordinator->initializeSubagents(initialSubagents);
    
    locker.relock();
    m_coordinators[sessionId] = coordinator;
    locker.unlock();
    
    emit sessionInitialized(sessionId, initialSubagents);
    
    qInfo() << "[ChatSessionSubagentBridge] Session initialized:" << sessionId
            << "with" << initialSubagents << "subagents";
}

void ChatSessionSubagentBridge::cleanupSession(const QString& sessionId)
{
    QMutexLocker locker(&m_mutex);
    
    if (!m_coordinators.contains(sessionId)) {
        return;
    }
    
    auto coordinator = m_coordinators[sessionId];
    m_coordinators.remove(sessionId);
    m_chatWidgets.remove(sessionId);
    
    // Remove all tasks associated with this session
    QStringList tasksToRemove;
    for (const auto& taskId : m_taskToSessionMap.keys()) {
        if (m_taskToSessionMap[taskId] == sessionId) {
            tasksToRemove.append(taskId);
        }
    }
    for (const auto& taskId : tasksToRemove) {
        m_taskToSessionMap.remove(taskId);
    }
    
    locker.unlock();
    
    emit sessionCleaned(sessionId);
    
    qInfo() << "[ChatSessionSubagentBridge] Session cleaned:" << sessionId;
}

bool ChatSessionSubagentBridge::isSessionInitialized(const QString& sessionId) const
{
    QMutexLocker locker(&m_mutex);
    return m_coordinators.contains(sessionId);
}

int ChatSessionSubagentBridge::getSubagentCountForSession(const QString& sessionId) const
{
    auto coordinator = getCoordinator(sessionId);
    if (!coordinator) {
        return 0;
    }
    return coordinator->getSubagentCount();
}

int ChatSessionSubagentBridge::getAvailableSubagentsForSession(const QString& sessionId) const
{
    auto coordinator = getCoordinator(sessionId);
    if (!coordinator) {
        return 0;
    }
    return coordinator->getAvailableSubagentCount();
}

bool ChatSessionSubagentBridge::addSubagentToSession(const QString& sessionId)
{
    auto coordinator = getCoordinator(sessionId);
    if (!coordinator) {
        return false;
    }
    
    bool result = coordinator->addSubagent();
    
    if (result) {
        qInfo() << "[ChatSessionSubagentBridge] Session:" << sessionId
                << "Subagent added. Total:" << coordinator->getSubagentCount();
    }
    
    return result;
}

bool ChatSessionSubagentBridge::removeSubagentFromSession(const QString& sessionId)
{
    auto coordinator = getCoordinator(sessionId);
    if (!coordinator) {
        return false;
    }
    
    bool result = coordinator->removeSubagent();
    
    if (result) {
        qInfo() << "[ChatSessionSubagentBridge] Session:" << sessionId
                << "Subagent removed. Total:" << coordinator->getSubagentCount();
    }
    
    return result;
}

void ChatSessionSubagentBridge::scaleSubagentsForSession(const QString& sessionId, int targetCount)
{
    auto coordinator = getCoordinator(sessionId);
    if (!coordinator) {
        return;
    }
    
    coordinator->scaleSubagents(targetCount);
    
    qInfo() << "[ChatSessionSubagentBridge] Session:" << sessionId
            << "Scaled to" << targetCount << "subagents";
}

QString ChatSessionSubagentBridge::submitChatTask(const QString& sessionId,
                                                 const QString& taskDescription,
                                                 std::function<QString()> chatResponseHandler)
{
    auto coordinator = getCoordinator(sessionId);
    if (!coordinator) {
        return QString();
    }
    
    QString taskId = coordinator->submitTask(taskDescription,
        [taskDescription, chatResponseHandler]() -> QJsonObject {
            QJsonObject result;
            result["taskDescription"] = taskDescription;
            
            if (chatResponseHandler) {
                QString response = chatResponseHandler();
                result["response"] = response;
            }
            
            result["completedAt"] = QDateTime::currentDateTime().toString(Qt::ISODate);
            return result;
        });
    
    if (!taskId.isEmpty()) {
        QMutexLocker locker(&m_mutex);
        m_taskToSessionMap[taskId] = sessionId;
        locker.unlock();
        
        emit taskSubmitted(sessionId, taskId);
        
        qInfo() << "[ChatSessionSubagentBridge] Task submitted for session:" << sessionId
                << "TaskId:" << taskId;
    }
    
    return taskId;
}

QString ChatSessionSubagentBridge::submitParallelChatTasks(const QString& sessionId,
                                                         const QStringList& taskDescriptions)
{
    auto coordinator = getCoordinator(sessionId);
    if (!coordinator) {
        return QString();
    }
    
    QList<SubagentTaskDistributor::DistributedTask> tasks;
    
    for (const auto& description : taskDescriptions) {
        SubagentTaskDistributor::DistributedTask task;
        task.taskId = description + "_" + QString::number(QDateTime::currentMSecsSinceEpoch());
        task.description = description;
        task.executor = [description]() -> QJsonObject {
            QJsonObject result;
            result["taskDescription"] = description;
            result["completedAt"] = QDateTime::currentDateTime().toString(Qt::ISODate);
            return result;
        };
        task.dependencyMode = SubagentTaskDistributor::TaskDependency::NoDelay;
        
        tasks.append(task);
    }
    
    QString groupId = coordinator->submitParallelTasks(tasks);
    
    if (!groupId.isEmpty()) {
        QMutexLocker locker(&m_mutex);
        m_taskToSessionMap[groupId] = sessionId;
        locker.unlock();
        
        emit taskSubmitted(sessionId, groupId);
    }
    
    return groupId;
}

QString ChatSessionSubagentBridge::submitSequentialChatTasks(const QString& sessionId,
                                                           const QStringList& taskDescriptions)
{
    auto coordinator = getCoordinator(sessionId);
    if (!coordinator) {
        return QString();
    }
    
    QList<SubagentTaskDistributor::DistributedTask> tasks;
    
    for (const auto& description : taskDescriptions) {
        SubagentTaskDistributor::DistributedTask task;
        task.taskId = description + "_" + QString::number(QDateTime::currentMSecsSinceEpoch());
        task.description = description;
        task.executor = [description]() -> QJsonObject {
            QJsonObject result;
            result["taskDescription"] = description;
            result["completedAt"] = QDateTime::currentDateTime().toString(Qt::ISODate);
            return result;
        };
        task.dependencyMode = SubagentTaskDistributor::TaskDependency::Sequential;
        
        tasks.append(task);
    }
    
    QString groupId = coordinator->submitSequentialTasks(tasks);
    
    if (!groupId.isEmpty()) {
        QMutexLocker locker(&m_mutex);
        m_taskToSessionMap[groupId] = sessionId;
        locker.unlock();
        
        emit taskSubmitted(sessionId, groupId);
    }
    
    return groupId;
}

bool ChatSessionSubagentBridge::cancelTaskForSession(const QString& sessionId, const QString& taskId)
{
    auto coordinator = getCoordinator(sessionId);
    if (!coordinator) {
        return false;
    }
    
    return coordinator->cancelTask(taskId);
}

QString ChatSessionSubagentBridge::getTaskStatusForSession(const QString& sessionId, const QString& taskId) const
{
    auto coordinator = getCoordinator(sessionId);
    if (!coordinator) {
        return QString();
    }
    
    QJsonObject status = coordinator->getTaskStatus(taskId);
    return QString::fromUtf8(QJsonDocument(status).toJson(QJsonDocument::Compact));
}

QString ChatSessionSubagentBridge::getTaskResultForSession(const QString& sessionId, const QString& taskId) const
{
    auto coordinator = getCoordinator(sessionId);
    if (!coordinator) {
        return QString();
    }
    
    QJsonObject result = coordinator->getTaskResult(taskId);
    return QString::fromUtf8(QJsonDocument(result).toJson(QJsonDocument::Compact));
}

void ChatSessionSubagentBridge::integrateChatWidget(const QString& sessionId, AIChatWidget* chatWidget)
{
    QMutexLocker locker(&m_mutex);
    m_chatWidgets[sessionId] = chatWidget;
    
    qInfo() << "[ChatSessionSubagentBridge] Chat widget integrated for session:" << sessionId;
}

void ChatSessionSubagentBridge::removeChatWidget(const QString& sessionId)
{
    QMutexLocker locker(&m_mutex);
    m_chatWidgets.remove(sessionId);
    
    qInfo() << "[ChatSessionSubagentBridge] Chat widget removed for session:" << sessionId;
}

int ChatSessionSubagentBridge::getTotalActiveSubagents() const
{
    QMutexLocker locker(&m_mutex);
    
    int total = 0;
    for (const auto& coordinator : m_coordinators) {
        if (coordinator) {
            total += coordinator->getSubagentCount();
        }
    }
    
    return total;
}

QStringList ChatSessionSubagentBridge::getActiveSessions() const
{
    QMutexLocker locker(&m_mutex);
    return m_coordinators.keys();
}

QString ChatSessionSubagentBridge::getSessionWithMostIdleSubagents() const
{
    QMutexLocker locker(&m_mutex);
    
    QString bestSession;
    int maxIdle = 0;
    
    for (const auto& sessionId : m_coordinators.keys()) {
        auto coordinator = m_coordinators[sessionId];
        if (coordinator) {
            int idleCount = coordinator->getAvailableSubagentCount();
            if (idleCount > maxIdle) {
                maxIdle = idleCount;
                bestSession = sessionId;
            }
        }
    }
    
    return bestSession;
}

QString ChatSessionSubagentBridge::getSessionMetricsJson(const QString& sessionId) const
{
    auto coordinator = getCoordinator(sessionId);
    if (!coordinator) {
        return QString();
    }
    
    QJsonObject metrics = coordinator->getCoordinatorMetrics();
    return QString::fromUtf8(QJsonDocument(metrics).toJson(QJsonDocument::Indented));
}

QString ChatSessionSubagentBridge::getGlobalMetricsJson() const
{
    QMutexLocker locker(&m_mutex);
    
    QJsonObject global;
    global["totalSessions"] = m_coordinators.size();
    global["totalSubagents"] = getTotalActiveSubagents();
    global["totalActiveTasks"] = m_taskToSessionMap.size();
    
    QJsonArray sessionMetrics;
    for (const auto& sessionId : m_coordinators.keys()) {
        auto coordinator = m_coordinators[sessionId];
        if (coordinator) {
            sessionMetrics.append(coordinator->getCoordinatorMetrics());
        }
    }
    
    global["sessions"] = sessionMetrics;
    
    return QString::fromUtf8(QJsonDocument(global).toJson(QJsonDocument::Indented));
}

MultitaskingCoordinator* ChatSessionSubagentBridge::getCoordinator(const QString& sessionId) const
{
    QMutexLocker locker(&m_mutex);
    
    if (m_coordinators.contains(sessionId)) {
        return m_coordinators[sessionId].get();
    }
    
    return nullptr;
}

bool ChatSessionSubagentBridge::validateSession(const QString& sessionId) const
{
    QMutexLocker locker(&m_mutex);
    return m_coordinators.contains(sessionId);
}

void ChatSessionSubagentBridge::onMultitaskingTaskCompleted(const QString& taskId, const QString& result)
{
    qInfo() << "[ChatSessionSubagentBridge] Task completed:" << taskId;
}

void ChatSessionSubagentBridge::onMultitaskingTaskFailed(const QString& taskId, const QString& error)
{
    qWarning() << "[ChatSessionSubagentBridge] Task failed:" << taskId << "-" << error;
}

void ChatSessionSubagentBridge::onMultitaskingTaskProgress(const QString& taskId, double percentComplete)
{
    qDebug() << "[ChatSessionSubagentBridge] Task progress:" << taskId << percentComplete << "%";
}

void ChatSessionSubagentBridge::onSubagentAdded(int totalCount)
{
    qInfo() << "[ChatSessionSubagentBridge] Subagent added. Total count:" << totalCount;
}

void ChatSessionSubagentBridge::onSubagentRemoved(int totalCount)
{
    qInfo() << "[ChatSessionSubagentBridge] Subagent removed. Total count:" << totalCount;
}

void ChatSessionSubagentBridge::onResourceWarning(const QString& resourceType, double usage)
{
    qWarning() << "[ChatSessionSubagentBridge] Resource warning:" << resourceType << "usage ratio:" << usage;
}

// ============================================================================
// ChatSessionSubagentManager Implementation
// ============================================================================

ChatSessionSubagentBridge* ChatSessionSubagentManager::s_instance = nullptr;
QMutex ChatSessionSubagentManager::s_mutex;

ChatSessionSubagentBridge* ChatSessionSubagentManager::getInstance()
{
    if (s_instance == nullptr) {
        QMutexLocker locker(&s_mutex);
        if (s_instance == nullptr) {
            s_instance = new ChatSessionSubagentBridge();
        }
    }
    return s_instance;
}
