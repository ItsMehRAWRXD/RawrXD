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
    
private:
    std::shared_ptr<DatabaseManager> m_dbManager;
    bool m_initialized = false;
};

} // namespace Database
} // namespace RawrXD
