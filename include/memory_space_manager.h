<<<<<<< HEAD
#pragma once

// C++20, no Qt. Persistent memory space for agent conversations/preferences.

#include <string>
#include <map>
#include <vector>

class MemorySpaceManager
{
public:
    static MemorySpaceManager& instance();

    bool isEnabled() const { return m_enabled; }
    void setEnabled(bool enabled) { m_enabled = enabled; }

    int64_t limitBytes() const { return m_limitBytes; }
    void setLimitBytes(int64_t bytes) { m_limitBytes = bytes; }

    void persist(const std::map<std::string, std::string>& memoryMap);
    std::map<std::string, std::string> loadMemory() const;

    std::vector<std::string> listKeys() const;
    bool deleteKey(const std::string& key);
    void clearAll();
    int64_t currentSizeBytes() const;

private:
    MemorySpaceManager() = default;
    std::string memoryFilePath() const;
    std::string settingsFilePath() const;
    std::string readJson() const;
    bool writeJson(const std::string& json) const;
    void ensureConfig();

    bool m_enabled = false;
    int64_t m_limitBytes = 134217728;
};
=======
#pragma once

#include <QObject>
#include <QMap>
#include <QVariant>
#include <QStringList>
#include <QJsonObject>

// Manages persistent memory space for agent conversations/preferences.
class MemorySpaceManager : public QObject
{
    Q_OBJECT
public:
    static MemorySpaceManager& instance();

    bool isEnabled() const;
    void setEnabled(bool enabled);

    qint64 limitBytes() const;
    void setLimitBytes(qint64 bytes);

    // Persist the in-memory map to disk, enforcing size limits.
    void persist(const QMap<QString, QVariant>& memoryMap);

    // Load the stored memory into a simple string map.
    QMap<QString, QString> loadMemory() const;

    // Utility helpers for UI/ops.
    QStringList listKeys() const;
    bool deleteKey(const QString& key);
    void clearAll();
    qint64 currentSizeBytes() const;

private:
    MemorySpaceManager();
    QString memoryFilePath() const;
    QString settingsFilePath() const;
    QJsonObject readJson() const;
    bool writeJson(const QJsonObject& obj) const;
    void ensureConfig();

    bool m_enabled = false;
    qint64 m_limitBytes = 134217728; // Default 128 MB
};
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
