#pragma once

#include <QString>
#include <QObject>
#include <QMap>
#include <memory>

class AIChatWidget;
class MultitaskingCoordinator;
class SubagentPool;

/**
 * @brief ChatSessionSubagentBridge - Integrates subagent multitasking with AI chat sessions
 * 
 * This class bridges the gap between:
 * - AIChatWidget (UI for chat interactions)
 * - MultitaskingCoordinator (subagent management)
 * - Chat sessions (persistent conversation context)
 * 
 * Features:
 * - Auto-create subagent pool per chat session
 * - Submit tasks from chat context
 * - Integrate task results back into chat
 * - Monitor multitasking progress in UI
 * - Manage up to 20 concurrent subagents per session
 */
class ChatSessionSubagentBridge : public QObject {
    Q_OBJECT

public:
    explicit ChatSessionSubagentBridge(QObject* parent = nullptr);
    ~ChatSessionSubagentBridge() override;

    // Chat session management
    void initializeForSession(const QString& sessionId, int initialSubagents = 5);
    void cleanupSession(const QString& sessionId);
    bool isSessionInitialized(const QString& sessionId) const;

    // Subagent control per session
    int getSubagentCountForSession(const QString& sessionId) const;
    int getAvailableSubagentsForSession(const QString& sessionId) const;
    bool addSubagentToSession(const QString& sessionId);
    bool removeSubagentFromSession(const QString& sessionId);
    void scaleSubagentsForSession(const QString& sessionId, int targetCount);

    // Task submission from chat
    QString submitChatTask(const QString& sessionId,
                          const QString& taskDescription,
                          std::function<QString()> chatResponseHandler = nullptr);

    QString submitParallelChatTasks(const QString& sessionId,
                                   const QStringList& taskDescriptions);

    QString submitSequentialChatTasks(const QString& sessionId,
                                     const QStringList& taskDescriptions);

    // Task management
    bool cancelTaskForSession(const QString& sessionId, const QString& taskId);
    QString getTaskStatusForSession(const QString& sessionId, const QString& taskId) const;
    QString getTaskResultForSession(const QString& sessionId, const QString& taskId) const;

    // Chat integration
    void integrateChatWidget(const QString& sessionId, AIChatWidget* chatWidget);
    void removeChatWidget(const QString& sessionId);

    // Multi-session control
    int getTotalActiveSubagents() const;
    QStringList getActiveSessions() const;
    QString getSessionWithMostIdleSubagents() const;

    // Metrics
    QString getSessionMetricsJson(const QString& sessionId) const;
    QString getGlobalMetricsJson() const;

signals:
    void sessionInitialized(const QString& sessionId, int subagentCount);
    void sessionCleaned(const QString& sessionId);
    void taskSubmitted(const QString& sessionId, const QString& taskId);
    void taskProgressUpdated(const QString& sessionId, const QString& taskId, double percentComplete);
    void taskCompleted(const QString& sessionId, const QString& taskId, const QString& result);
    void taskFailed(const QString& sessionId, const QString& taskId, const QString& error);
    void subagentAdded(const QString& sessionId, int totalCount);
    void subagentRemoved(const QString& sessionId, int totalCount);
    void resourceWarning(const QString& sessionId, const QString& resourceType, double usage);

private slots:
    void onMultitaskingTaskCompleted(const QString& taskId, const QString& result);
    void onMultitaskingTaskFailed(const QString& taskId, const QString& error);
    void onMultitaskingTaskProgress(const QString& taskId, double percentComplete);
    void onSubagentAdded(int totalCount);
    void onSubagentRemoved(int totalCount);
    void onResourceWarning(const QString& resourceType, double usage);

private:
    // Session management
    QMap<QString, std::shared_ptr<MultitaskingCoordinator>> m_coordinators;
    QMap<QString, AIChatWidget*> m_chatWidgets;
    QMap<QString, QString> m_taskToSessionMap;  // taskId -> sessionId
    
    mutable QMutex m_mutex;
    
    // Helper methods
    MultitaskingCoordinator* getCoordinator(const QString& sessionId) const;
    bool validateSession(const QString& sessionId) const;
};

/**
 * @brief ChatSessionSubagentManager - Global manager for all chat session subagent bridges
 * 
 * Singleton that manages:
 * - Per-session subagent pools
 * - Cross-session resource sharing
 * - Global metrics
 */
class ChatSessionSubagentManager {
public:
    static ChatSessionSubagentBridge* getInstance();
    
private:
    ChatSessionSubagentManager() = default;
    static ChatSessionSubagentBridge* s_instance;
    static QMutex s_mutex;
};
