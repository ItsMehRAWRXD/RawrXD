#include "settings_manager.h"
#include <QDebug>
#include <QStandardPaths>
#include <QJsonDocument>
#include <QFile>
#include <QDir>

SettingsManager::SettingsManager(QObject *parent)
    : QObject(parent),
      m_settings(nullptr),
      m_agentSettings(QMap<QString, QJsonObject>()),
      m_modelSettings(QMap<QString, QJsonObject>()),
      m_gpuBackends(QMap<QString, QJsonObject>())
{
    // Create QSettings with application organization and name
    QString configPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    m_settings = new QSettings(configPath + "/RawrXD.ini", QSettings::IniFormat, this);
    
    // Load compression settings
    m_compressionSettings.preferred_type = m_settings->value("compression/preferred_type", 2).toInt();
    m_compressionSettings.enable_stats = m_settings->value("compression/enable_stats", true).toBool();
    m_compressionSettings.max_decomp_bytes = m_settings->value("compression/max_bytes", 10ULL*1024*1024*1024).toULongLong();
    
    // Initialize defaults for first run
    initializeDefaults();
    
    qDebug() << "[SettingsManager] Initialized with config:" << m_settings->fileName();
}

SettingsManager& SettingsManager::instance()
{
    static SettingsManager s_instance;
    return s_instance;
}

SettingsManager::~SettingsManager()
{
    if (m_settings) {
        m_settings->sync();
    }
    qDebug() << "[SettingsManager] Destroyed";
}

void SettingsManager::setValue(const QString& key, const QVariant& value)
{
    if (m_settings) {
        qDebug() << "[SettingsManager] Setting value for key:" << key << "to:" << (key.contains("apiKey") ? "********" : value.toString());
        m_settings->setValue(key, value);
        
        // Update internal structs
        if (key == "compression/preferred_type") m_compressionSettings.preferred_type = value.toInt();
        else if (key == "compression/enable_stats") m_compressionSettings.enable_stats = value.toBool();
        else if (key == "compression/max_bytes") m_compressionSettings.max_decomp_bytes = value.toULongLong();
        
        m_settings->sync();
        emit settingChanged(key, value);
    } else {
        qWarning() << "[SettingsManager] Cannot set value, m_settings is null! Key:" << key;
    }
}

QVariant SettingsManager::getValue(const QString& key, const QVariant& defaultValue) const
{
    if (m_settings) {
        QVariant val = m_settings->value(key, defaultValue);
        qDebug() << "[SettingsManager] Getting value for key:" << key << "result:" << (key.contains("apiKey") ? "********" : val.toString());
        return val;
    }
    qWarning() << "[SettingsManager] Cannot get value, m_settings is null! Key:" << key;
    return defaultValue;
}

bool SettingsManager::contains(const QString& key) const
{
    if (m_settings) {
        return m_settings->contains(key);
    }
    return false;
}

void SettingsManager::remove(const QString& key)
{
    if (m_settings) {
        m_settings->remove(key);
        m_settings->sync();
        qDebug() << "[SettingsManager] Removed:" << key;
    }
}

void SettingsManager::sync()
{
    if (m_settings) {
        m_settings->sync();
        qDebug() << "[SettingsManager] Settings synced";
    }
}

void SettingsManager::setAgentSettings(const QString& agentId, const QJsonObject& settings)
{
    m_agentSettings[agentId] = settings;
    
    // Also save to QSettings
    if (m_settings) {
        QJsonDocument doc(settings);
        m_settings->setValue("agents/" + agentId, QString::fromUtf8(doc.toJson(QJsonDocument::Compact)));
        m_settings->sync();
    }
    
    emit agentSettingsChanged(agentId);
    qDebug() << "[SettingsManager] Agent settings updated:" << agentId;
}

QJsonObject SettingsManager::getAgentSettings(const QString& agentId) const
{
    auto it = m_agentSettings.find(agentId);
    if (it != m_agentSettings.end()) {
        return it.value();
    }
    return QJsonObject();
}

void SettingsManager::setModelSettings(const QString& modelPath, const QJsonObject& settings)
{
    m_modelSettings[modelPath] = settings;
    
    if (m_settings) {
        QJsonDocument doc(settings);
        QString modelKey = "models/" + modelPath;
        modelKey.replace('/', '_'); // Replace slashes with underscores
        m_settings->setValue(modelKey, QString::fromUtf8(doc.toJson(QJsonDocument::Compact)));
        m_settings->sync();
    }
    
    emit modelSettingsChanged(modelPath);
    qDebug() << "[SettingsManager] Model settings updated:" << modelPath;
}

QJsonObject SettingsManager::getModelSettings(const QString& modelPath) const
{
    auto it = m_modelSettings.find(modelPath);
    if (it != m_modelSettings.end()) {
        return it.value();
    }
    return QJsonObject();
}

void SettingsManager::setGPUBackend(const QString& backend, const QJsonObject& config)
{
    m_gpuBackends[backend] = config;
    
    if (m_settings) {
        QJsonDocument doc(config);
        m_settings->setValue("gpu/" + backend, QString::fromUtf8(doc.toJson(QJsonDocument::Compact)));
        m_settings->sync();
    }
    
    qDebug() << "[SettingsManager] GPU backend configured:" << backend;
}

QJsonObject SettingsManager::getGPUBackend(const QString& backend) const
{
    auto it = m_gpuBackends.find(backend);
    if (it != m_gpuBackends.end()) {
        return it.value();
    }
    return QJsonObject();
}

void SettingsManager::setSecuritySettings(const QJsonObject& settings)
{
    if (m_settings) {
        QJsonDocument doc(settings);
        m_settings->setValue("security", QString::fromUtf8(doc.toJson(QJsonDocument::Compact)));
        m_settings->sync();
    }
    
    emit securitySettingsChanged();
    qDebug() << "[SettingsManager] Security settings updated";
}

QJsonObject SettingsManager::getSecuritySettings() const
{
    if (m_settings && m_settings->contains("security")) {
        QString jsonStr = m_settings->value("security", "{}").toString();
        QJsonDocument doc = QJsonDocument::fromJson(jsonStr.toUtf8());
        return doc.object();
    }
    return QJsonObject();
}

QJsonObject SettingsManager::exportAllSettings() const
{
    QJsonObject allSettings;
    
    // Export all QSettings
    if (m_settings) {
        allSettings["qsettings"] = QJsonObject();
        for (const QString& key : m_settings->allKeys()) {
            QJsonValue val(QJsonValue::String);
            QVariant variant = m_settings->value(key);
            if (variant.type() == QVariant::Int) {
                val = QJsonValue(variant.toInt());
            } else if (variant.type() == QVariant::Bool) {
                val = QJsonValue(variant.toBool());
            } else {
                val = QJsonValue(variant.toString());
            }
            allSettings["qsettings"].toObject()[key] = val;
        }
    }
    
    // Export agent settings
    QJsonObject agentSettings;
    for (auto it = m_agentSettings.constBegin(); it != m_agentSettings.constEnd(); ++it) {
        agentSettings[it.key()] = it.value();
    }
    allSettings["agents"] = agentSettings;
    
    // Export model settings
    QJsonObject modelSettings;
    for (auto it = m_modelSettings.constBegin(); it != m_modelSettings.constEnd(); ++it) {
        modelSettings[it.key()] = it.value();
    }
    allSettings["models"] = modelSettings;
    
    return allSettings;
}

bool SettingsManager::importSettings(const QJsonObject& settings)
{
    try {
        if (settings.contains("qsettings")) {
            QJsonObject qsettings = settings["qsettings"].toObject();
            for (auto it = qsettings.constBegin(); it != qsettings.constEnd(); ++it) {
                setValue(it.key(), it.value().toVariant());
            }
        }
        
        if (settings.contains("agents")) {
            QJsonObject agents = settings["agents"].toObject();
            for (auto it = agents.constBegin(); it != agents.constEnd(); ++it) {
                setAgentSettings(it.key(), it.value().toObject());
            }
        }
        
        if (settings.contains("models")) {
            QJsonObject models = settings["models"].toObject();
            for (auto it = models.constBegin(); it != models.constEnd(); ++it) {
                setModelSettings(it.key(), it.value().toObject());
            }
        }
        
        qDebug() << "[SettingsManager] Settings imported successfully";
        return true;
    } catch (...) {
        qWarning() << "[SettingsManager] Error importing settings";
        return false;
    }
}

QString SettingsManager::getDefaultProjectRoot() const
{
    // Priority order:
    // 1. Settings file
    // 2. Environment variable
    // 3. Smart default (E:\ or D:\RawrXD-production-lazy-init or current dir)
    
    QString projectRoot = getValue("project/default_root", "").toString();
    
    if (!projectRoot.isEmpty()) {
        return projectRoot;
    }
    
    // Check environment variable
    projectRoot = qEnvironmentVariable("RAWRXD_PROJECT_ROOT");
    if (!projectRoot.isEmpty()) {
        return projectRoot;
    }
    
    // Smart defaults
    if (QFile::exists("E:\\")) {
        return "E:\\";
    } else if (QFile::exists("D:\\RawrXD-production-lazy-init")) {
        return "D:\\RawrXD-production-lazy-init";
    } else {
        return QDir::currentPath();
    }
}

void SettingsManager::setDefaultProjectRoot(const QString& path)
{
    setValue("project/default_root", path);
    qDebug() << "[SettingsManager] Default project root set to:" << path;
}

void SettingsManager::initializeDefaults()
{
    qDebug() << "[SettingsManager] Initializing default configuration...";
    
    // LLM Endpoints
    if (!contains("llm/ollama_endpoint")) {
        setValue("llm/ollama_endpoint", "http://localhost:11434");
    }
    if (!contains("llm/claude_endpoint")) {
        setValue("llm/claude_endpoint", "https://api.anthropic.com");
    }
    if (!contains("llm/openai_endpoint")) {
        setValue("llm/openai_endpoint", "https://api.openai.com/v1");
    }
    
    // GGUF Server
    if (!contains("gguf/server_port")) {
        setValue("gguf/server_port", 11434);
    }
    if (!contains("gguf/auto_start")) {
        setValue("gguf/auto_start", true);
    }
    
    // Project settings
    if (!contains("project/default_root")) {
        QString defaultRoot = getDefaultProjectRoot();
        setValue("project/default_root", defaultRoot);
        qDebug() << "[SettingsManager] Set default project root:" << defaultRoot;
    }
    
    // Model cache
    if (!contains("model/cache_dir")) {
        QString cacheDir = QStandardPaths::writableLocation(QStandardPaths::CacheLocation) + "/models";
        setValue("model/cache_dir", cacheDir);
        
        // Ensure cache directory exists
        QDir().mkpath(cacheDir);
        qDebug() << "[SettingsManager] Model cache directory:" << cacheDir;
    }
    
    // Agent settings
    if (!contains("agent/auto_bootstrap_enabled")) {
        setValue("agent/auto_bootstrap_enabled", true);
    }
    if (!contains("agent/max_concurrent_tasks")) {
        setValue("agent/max_concurrent_tasks", 3);
    }
    if (!contains("agent/timeout_seconds")) {
        setValue("agent/timeout_seconds", 300);
    }
    
    // Hotpatch settings
    if (!contains("hotpatch/enabled")) {
        setValue("hotpatch/enabled", true);
    }
    if (!contains("hotpatch/auto_backup")) {
        setValue("hotpatch/auto_backup", true);
    }
    
    // UI settings
    if (!contains("ui/theme")) {
        setValue("ui/theme", "dark");
    }
    if (!contains("ui/font_size")) {
        setValue("ui/font_size", 10);
    }
    
    // Logging
    if (!contains("log/level")) {
        setValue("log/level", "info");
    }
    if (!contains("log/file_enabled")) {
        setValue("log/file_enabled", true);
    }
    
    sync();
    qDebug() << "[SettingsManager] Default configuration initialized";
}

