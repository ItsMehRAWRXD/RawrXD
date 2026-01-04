#pragma once

#include <QString>
#include <QJsonObject>
#include <QJsonArray>
#include <memory>
#include "database_manager.h"

namespace RawrXD {
namespace Database {

struct ChatMessage {
    QString sessionId;
    QString role;
    QString content;
    qint64 timestamp;
};

struct ChatCheckpoint {
    QString checkpointId;
    QString sessionId;
    QString title;
    qint64 timestamp;
    int messageCount;
};

class ChatHistoryManager {
public:
    explicit ChatHistoryManager(std::shared_ptr<DatabaseManager> dbManager);
    
    bool initialize();
    
    // Session management
    QString createSession(const QString& title = "New Chat");
    QJsonArray getSessions();
    bool deleteSession(const QString& sessionId);
    
    // Message management
    bool addMessage(const QString& sessionId, const QString& role, const QString& content);
    QJsonArray getMessages(const QString& sessionId);
    
    // Checkpoint management
    QString createCheckpoint(const QString& sessionId, const QString& title = "");
    QJsonArray getCheckpoints(const QString& sessionId);
    bool restoreCheckpoint(const QString& checkpointId);
    bool deleteCheckpoint(const QString& checkpointId);
    QString getLatestCheckpoint(const QString& sessionId);
    
    // Auto-checkpoint configuration
    void setAutoCheckpointInterval(int minutes);
    bool shouldAutoCheckpoint(const QString& sessionId);
    QString autoCheckpoint(const QString& sessionId);
    
private:
    std::shared_ptr<DatabaseManager> m_dbManager;
    bool m_initialized = false;
    int m_autoCheckpointMinutes = 5;  // Auto-checkpoint every 5 minutes by default
    QMap<QString, qint64> m_lastCheckpointTime;  // Track last checkpoint per session
};

} // namespace Database
} // namespace RawrXD
