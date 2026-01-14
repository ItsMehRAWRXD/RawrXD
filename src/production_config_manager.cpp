#include "production_config_manager.h"
#include <QDir>
#include <QDebug>
#include <QCoreApplication>

namespace RawrXD {

ProductionConfigManager& ProductionConfigManager::instance() {
    static ProductionConfigManager instance;
    return instance;
}

ProductionConfigManager::ProductionConfigManager(QObject* parent)
    : QObject(parent)
    , m_currentEnvironment("production")
    , m_hotReloadEnabled(false)
    , m_watcher(nullptr)
{
    // Try to detect environment from environment variable
    QString envVar = qgetenv("RAWRXD_ENV");
    if (!envVar.isEmpty()) {
        m_currentEnvironment = envVar.toLower();
    }
}

ProductionConfigManager::~ProductionConfigManager() {
    if (m_watcher) {
        delete m_watcher;
    }
}

bool ProductionConfigManager::loadConfig(const QString& configPath) {
    QMutexLocker lock(&m_mutex);
    
    QString path = configPath;
    if (path.isEmpty()) {
        path = resolveConfigPath(m_currentEnvironment);
    }
    
    if (!loadConfigFromFile(path)) {
        emit configError(QString("Failed to load config from: %1").arg(path));
        return false;
    }
    
    m_currentConfigPath = path;
    
    // Setup hot reload if enabled
    if (m_hotReloadEnabled && getValue("features.external_config_reload").toBool(true)) {
        if (!m_watcher) {
            m_watcher = new QFileSystemWatcher(this);
            connect(m_watcher, &QFileSystemWatcher::fileChanged,
                    this, &ProductionConfigManager::onConfigFileChanged);
        }
        
        if (!m_watcher->files().contains(path)) {
            m_watcher->addPath(path);
        }
    }
    
    emit configLoaded(m_currentEnvironment);
    return true;
}

bool ProductionConfigManager::loadEnvironmentConfig(const QString& environment) {
    m_currentEnvironment = environment;
    return loadConfig(resolveConfigPath(environment));
}

bool ProductionConfigManager::reloadConfig() {
    return loadConfig(m_currentConfigPath);
}

bool ProductionConfigManager::isFeatureEnabled(const QString& featureName) const {
    QMutexLocker lock(&m_mutex);
    return getValue(QString("features.%1").arg(featureName)).toBool(false);
}

void ProductionConfigManager::setFeatureEnabled(const QString& featureName, bool enabled) {
    QMutexLocker lock(&m_mutex);
    
    QJsonObject features = m_config["features"].toObject();
    features[featureName] = enabled;
    m_config["features"] = features;
    
    emit featureToggled(featureName, enabled);
}

QJsonObject ProductionConfigManager::getLoggingConfig() const {
    QMutexLocker lock(&m_mutex);
    return m_config["logging"].toObject();
}

QJsonObject ProductionConfigManager::getMetricsConfig() const {
    QMutexLocker lock(&m_mutex);
    return m_config["metrics"].toObject();
}

QJsonObject ProductionConfigManager::getTracingConfig() const {
    QMutexLocker lock(&m_mutex);
    return m_config["tracing"].toObject();
}

QJsonObject ProductionConfigManager::getHotpatchingConfig() const {
    QMutexLocker lock(&m_mutex);
    return m_config["hotpatching"].toObject();
}

QJsonObject ProductionConfigManager::getErrorDetectionConfig() const {
    QMutexLocker lock(&m_mutex);
    return m_config["error_detection"].toObject();
}

QJsonObject ProductionConfigManager::getResourceLimitsConfig() const {
    QMutexLocker lock(&m_mutex);
    return m_config["resource_limits"].toObject();
}

QJsonObject ProductionConfigManager::getHealthChecksConfig() const {
    QMutexLocker lock(&m_mutex);
    return m_config["health_checks"].toObject();
}

QJsonValue ProductionConfigManager::getValue(const QString& path) const {
    QMutexLocker lock(&m_mutex);
    QStringList keys = path.split('.');
    return getNestedValue(m_config, keys);
}

QString ProductionConfigManager::getString(const QString& path, const QString& defaultValue) const {
    QJsonValue val = getValue(path);
    return val.isString() ? val.toString() : defaultValue;
}

int ProductionConfigManager::getInt(const QString& path, int defaultValue) const {
    QJsonValue val = getValue(path);
    return val.isDouble() ? val.toInt() : defaultValue;
}

double ProductionConfigManager::getDouble(const QString& path, double defaultValue) const {
    QJsonValue val = getValue(path);
    return val.isDouble() ? val.toDouble() : defaultValue;
}

bool ProductionConfigManager::getBool(const QString& path, bool defaultValue) const {
    QJsonValue val = getValue(path);
    return val.isBool() ? val.toBool() : defaultValue;
}

QString ProductionConfigManager::getConfigVersion() const {
    return getString("version", "unknown");
}

void ProductionConfigManager::enableHotReload(bool enable) {
    m_hotReloadEnabled = enable;
    
    if (enable && !m_currentConfigPath.isEmpty()) {
        if (!m_watcher) {
            m_watcher = new QFileSystemWatcher(this);
            connect(m_watcher, &QFileSystemWatcher::fileChanged,
                    this, &ProductionConfigManager::onConfigFileChanged);
        }
        
        if (!m_watcher->files().contains(m_currentConfigPath)) {
            m_watcher->addPath(m_currentConfigPath);
        }
    } else if (!enable && m_watcher) {
        m_watcher->removePaths(m_watcher->files());
    }
}

bool ProductionConfigManager::loadConfigFromFile(const QString& filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning() << "Failed to open config file:" << filePath;
        return false;
    }
    
    QByteArray data = file.readAll();
    file.close();
    
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(data, &parseError);
    
    if (parseError.error != QJsonParseError::NoError) {
        qWarning() << "JSON parse error:" << parseError.errorString();
        return false;
    }
    
    if (!doc.isObject()) {
        qWarning() << "Config root must be a JSON object";
        return false;
    }
    
    m_config = doc.object();
    return true;
}

QString ProductionConfigManager::resolveConfigPath(const QString& environment) const {
    // Try multiple locations in priority order
    QStringList searchPaths = {
        QString("./config/%1.json").arg(environment),
        QString("../config/%1.json").arg(environment),
        QString("config/%1.json").arg(environment),
        QString("%1/config/%2.json").arg(QCoreApplication::applicationDirPath()).arg(environment)
    };
    
    for (const QString& path : searchPaths) {
        if (QFile::exists(path)) {
            return path;
        }
    }
    
    // Fallback to production if environment-specific config not found
    if (environment != "production") {
        return resolveConfigPath("production");
    }
    
    return QString();
}

QJsonValue ProductionConfigManager::getNestedValue(const QJsonObject& obj, const QStringList& path) const {
    if (path.isEmpty()) {
        return QJsonValue();
    }
    
    QJsonObject current = obj;
    for (int i = 0; i < path.size() - 1; ++i) {
        if (!current.contains(path[i])) {
            return QJsonValue();
        }
        
        QJsonValue val = current[path[i]];
        if (!val.isObject()) {
            return QJsonValue();
        }
        
        current = val.toObject();
    }
    
    return current[path.last()];
}

void ProductionConfigManager::onConfigFileChanged(const QString& path) {
    qDebug() << "Config file changed, reloading:" << path;
    
    if (reloadConfig()) {
        emit configReloaded();
    } else {
        // Re-add watch if file was removed temporarily
        if (m_watcher && !m_watcher->files().contains(path)) {
            m_watcher->addPath(path);
        }
    }
}

} // namespace RawrXD
