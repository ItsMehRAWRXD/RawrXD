#include "agent_cancellation.h"
#include "logging/structured_logger.h"
#include "error_handler.h"
#include <QUuid>
#include <QCoreApplication>
#include <QTimer>

namespace RawrXD {

AgentCancellationManager& AgentCancellationManager::instance() {
    static AgentCancellationManager instance;
    return instance;
}

void AgentCancellationManager::initialize() {
    QMutexLocker lock(&mutex_);
    
    if (initialized_) {
        return;
    }
    
    initialized_ = true;
    
    LOG_INFO("Agent cancellation manager initialized");
}

void AgentCancellationManager::shutdown() {
    QMutexLocker lock(&mutex_);
    
    if (initialized_) {
        cancelAllAgents(true, 10000); // 10 second timeout for shutdown
        
        if (shutdownHandler_) {
            try {
                shutdownHandler_();
            } catch (const std::exception& e) {
                ERROR_EXCEPTION(e, ErrorContext()
                    .setSeverity(ErrorSeverity::HIGH)
                    .setCategory(ErrorCategory::AGENT)
                    .setOperation("Agent shutdown handler"));
            }
        }
        
        agents_.clear();
        initialized_ = false;
        
        LOG_INFO("Agent cancellation manager shut down");
    }
}

QString AgentCancellationManager::registerAgent(const QString& agentType, const QString& description) {
    QMutexLocker lock(&mutex_);
    
    QString agentId = generateAgentId(agentType);
    
    AgentInfo info;
    info.id = agentId;
    info.type = agentType;
    info.description = description;
    info.token = QSharedPointer<CancellationToken>(new CancellationToken());
    info.startTime = QDateTime::currentDateTime();
    info.running = true;
    
    agents_[agentId] = info;
    
    emit agentStarted(agentId, agentType);
    
    LOG_INFO("Agent registered", {
        {"agent_id", agentId},
        {"agent_type", agentType},
        {"description", description}
    });
    
    return agentId;
}

bool AgentCancellationManager::unregisterAgent(const QString& agentId) {
    QMutexLocker lock(&mutex_);
    
    if (!agents_.contains(agentId)) {
        return false;
    }
    
    AgentInfo info = agents_[agentId];
    info.running = false;
    
    // Perform cleanup if handler exists
    if (info.cleanupHandler) {
        try {
            info.cleanupHandler();
        } catch (const std::exception& e) {
            ERROR_EXCEPTION(e, ErrorContext()
                .setSeverity(ErrorSeverity::MEDIUM)
                .setCategory(ErrorCategory::AGENT)
                .setOperation("Agent cleanup handler")
                .addMetadata("agent_id", agentId));
        }
    }
    
    agents_.remove(agentId);
    
    emit agentCompleted(agentId, true);
    
    LOG_INFO("Agent unregistered", {{"agent_id", agentId}});
    
    return true;
}

bool AgentCancellationManager::cancelAgent(const QString& agentId, bool waitForCompletion, int timeoutMs) {
    QMutexLocker lock(&mutex_);
    
    if (!agents_.contains(agentId)) {
        return false;
    }
    
    AgentInfo& info = agents_[agentId];
    
    if (!info.running) {
        return true; // Already completed
    }
    
    // Cancel the token
    info.token->cancel();
    
    emit agentCancelled(agentId);
    
    LOG_INFO("Agent cancellation requested", {{"agent_id", agentId}});
    
    if (waitForCompletion) {
        // Wait for agent to complete
        QTimer timer;
        timer.setSingleShot(true);
        
        QEventLoop loop;
        QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
        
        // Check periodically if agent has completed
        QTimer checkTimer;
        checkTimer.setInterval(100);
        QObject::connect(&checkTimer, &QTimer::timeout, [&]() {
            QMutexLocker innerLock(&mutex_);
            if (!agents_.contains(agentId) || !agents_[agentId].running) {
                loop.quit();
            }
        });
        
        timer.start(timeoutMs);
        checkTimer.start();
        loop.exec();
        
        checkTimer.stop();
        
        if (timer.isActive()) {
            // Agent completed before timeout
            timer.stop();
            LOG_INFO("Agent cancelled successfully", {{"agent_id", agentId}});
            return true;
        } else {
            // Timeout reached
            LOG_WARN("Agent cancellation timeout", {{"agent_id", agentId}, {"timeout_ms", timeoutMs}});
            return false;
        }
    }
    
    return true;
}

void AgentCancellationManager::cancelAllAgents(bool waitForCompletion, int timeoutMs) {
    QMutexLocker lock(&mutex_);
    
    QList<QString> agentIds = agents_.keys();
    
    LOG_INFO("Cancelling all agents", {{"agent_count", agentIds.size()}});
    
    for (const QString& agentId : agentIds) {
        // Don't wait for individual agents when cancelling all
        cancelAgent(agentId, false, 0);
    }
    
    if (waitForCompletion) {
        // Wait for all agents to complete
        QTimer timer;
        timer.setSingleShot(true);
        
        QEventLoop loop;
        QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
        
        QTimer checkTimer;
        checkTimer.setInterval(100);
        QObject::connect(&checkTimer, &QTimer::timeout, [&]() {
            QMutexLocker innerLock(&mutex_);
            if (agents_.isEmpty()) {
                loop.quit();
            }
        });
        
        timer.start(timeoutMs);
        checkTimer.start();
        loop.exec();
        
        checkTimer.stop();
        
        if (timer.isActive()) {
            // All agents completed before timeout
            timer.stop();
            LOG_INFO("All agents cancelled successfully");
        } else {
            // Timeout reached
            LOG_WARN("Agent cancellation timeout for some agents", {{"remaining_agents", agents_.size()}});
        }
    }
}

bool AgentCancellationManager::isAgentRunning(const QString& agentId) const {
    QMutexLocker lock(&mutex_);
    
    if (!agents_.contains(agentId)) {
        return false;
    }
    
    return agents_[agentId].running;
}

QList<QString> AgentCancellationManager::getRunningAgents() const {
    QMutexLocker lock(&mutex_);
    
    QList<QString> running;
    
    for (auto it = agents_.begin(); it != agents_.end(); ++it) {
        if (it.value().running) {
            running.append(it.key());
        }
    }
    
    return running;
}

int AgentCancellationManager::getAgentCount() const {
    QMutexLocker lock(&mutex_);
    return agents_.size();
}

QSharedPointer<CancellationToken> AgentCancellationManager::getToken(const QString& agentId) {
    QMutexLocker lock(&mutex_);
    
    if (!agents_.contains(agentId)) {
        return QSharedPointer<CancellationToken>();
    }
    
    return agents_[agentId].token;
}

void AgentCancellationManager::setShutdownHandler(std::function<void()> handler) {
    QMutexLocker lock(&mutex_);
    shutdownHandler_ = handler;
}

void AgentCancellationManager::setCleanupHandler(const QString& agentId, std::function<void()> handler) {
    QMutexLocker lock(&mutex_);
    
    if (agents_.contains(agentId)) {
        agents_[agentId].cleanupHandler = handler;
    }
}

QString AgentCancellationManager::generateAgentId(const QString& agentType) {
    QString baseId = agentType + "_" + QUuid::createUuid().toString(QUuid::WithoutBraces);
    baseId.replace("{", "");
    baseId.replace("}", "");
    baseId.replace("-", "_");
    return baseId;
}

void AgentCancellationManager::performCleanup(const QString& agentId) {
    QMutexLocker lock(&mutex_);
    
    if (agents_.contains(agentId) && agents_[agentId].cleanupHandler) {
        try {
            agents_[agentId].cleanupHandler();
        } catch (const std::exception& e) {
            ERROR_EXCEPTION(e, ErrorContext()
                .setSeverity(ErrorSeverity::MEDIUM)
                .setCategory(ErrorCategory::AGENT)
                .setOperation("Agent cleanup")
                .addMetadata("agent_id", agentId));
        }
    }
}

AgentCancellationManager::~AgentCancellationManager() {
    shutdown();
}

} // namespace RawrXD