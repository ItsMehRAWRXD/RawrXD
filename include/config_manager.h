#pragma once

#include <QJsonObject>
#include <QMutex>
#include <QString>

namespace RawrXD {
class ConfigManager {
public:
    static ConfigManager& instance();

    bool load(const QString& path = QString());
    QJsonObject root() const;

    // Helpers
    QJsonObject section(const QString& name) const;
    QString getString(const QString& dottedKey, const QString& defaultValue = QString()) const;
    bool getBool(const QString& dottedKey, bool defaultValue = false) const;
    int getInt(const QString& dottedKey, int defaultValue = 0) const;

private:
    ConfigManager() = default;
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    QString resolveEnvironment(const QString& value) const;
    QJsonValue lookup(const QString& dottedKey) const;

    mutable QMutex mutex_;
    QJsonObject root_;
    bool loaded_ = false;
};
} // namespace RawrXD
