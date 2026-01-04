#include "chat_history_manager.h"
#include <QDateTime>
#include <QUuid>
#include <QDebug>

namespace RawrXD {
namespace Database {

ChatHistoryManager::ChatHistoryManager(std::shared_ptr<DatabaseManager> dbManager)
    : m_dbManager(dbManager)
{
}

bool ChatHistoryManager::initialize() {
    if (m_initialized) return true;
    if (!m_dbManager) return false;

    // Create tables if they don't exist
    bool s1 = m_dbManager->executeMutation(
        "CREATE TABLE IF NOT EXISTS chat_sessions ("
        "id TEXT PRIMARY KEY, "
        "title TEXT, "
        "created_at INTEGER"
        ")", {}, "sqlite");

    bool s2 = m_dbManager->executeMutation(
        "CREATE TABLE IF NOT EXISTS chat_messages ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "session_id TEXT, "
        "role TEXT, "
        "content TEXT, "
        "timestamp INTEGER, "
        "FOREIGN KEY(session_id) REFERENCES chat_sessions(id)"
        ")", {}, "sqlite");

    m_initialized = s1 && s2;
    return m_initialized;
}

QString ChatHistoryManager::createSession(const QString& title) {
    if (!initialize()) return "";

    QString sessionId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    qint64 now = QDateTime::currentMSecsSinceEpoch();

    bool success = m_dbManager->executeMutation(
        "INSERT INTO chat_sessions (id, title, created_at) VALUES (?, ?, ?)",
        {sessionId, title, now}, "sqlite");

    return success ? sessionId : "";
}

QJsonArray ChatHistoryManager::getSessions() {
    if (!initialize()) return QJsonArray();

    QueryResult result = m_dbManager->executeQuery(
        "SELECT * FROM chat_sessions ORDER BY created_at DESC", {}, "sqlite");

    QJsonArray sessions;
    for (const auto& row : result.rows) {
        QJsonObject obj;
        QVariantMap map = row.toMap();
        obj["id"] = map["id"].toString();
        obj["title"] = map["title"].toString();
        obj["created_at"] = map["created_at"].toLongLong();
        sessions.append(obj);
    }
    return sessions;
}

bool ChatHistoryManager::deleteSession(const QString& sessionId) {
    if (!initialize()) return false;

    // Delete messages first due to foreign key (though SQLite might not enforce it by default)
    m_dbManager->executeMutation("DELETE FROM chat_messages WHERE session_id = ?", {sessionId}, "sqlite");
    return m_dbManager->executeMutation("DELETE FROM chat_sessions WHERE id = ?", {sessionId}, "sqlite");
}

bool ChatHistoryManager::addMessage(const QString& sessionId, const QString& role, const QString& content) {
    if (!initialize()) return false;

    qint64 now = QDateTime::currentMSecsSinceEpoch();
    return m_dbManager->executeMutation(
        "INSERT INTO chat_messages (session_id, role, content, timestamp) VALUES (?, ?, ?, ?)",
        {sessionId, role, content, now}, "sqlite");
}

QJsonArray ChatHistoryManager::getMessages(const QString& sessionId) {
    if (!initialize()) return QJsonArray();

    QueryResult result = m_dbManager->executeQuery(
        "SELECT role, content, timestamp FROM chat_messages WHERE session_id = ? ORDER BY timestamp ASC",
        {sessionId}, "sqlite");

    QJsonArray messages;
    for (const auto& row : result.rows) {
        QJsonObject obj;
        QVariantMap map = row.toMap();
        obj["role"] = map["role"].toString();
        obj["content"] = map["content"].toString();
        obj["timestamp"] = map["timestamp"].toLongLong();
        messages.append(obj);
    }
    return messages;
}

} // namespace Database
} // namespace RawrXD
