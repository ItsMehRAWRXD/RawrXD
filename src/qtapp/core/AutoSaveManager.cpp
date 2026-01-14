/*
 * AutoSaveManager.cpp - Complete Implementation
 */

#include "AutoSaveManager.h"

#include <QTimer>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QStandardPaths>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <QDebug>
#include <QApplication>
#include <QMutexLocker>
#include <QCryptographicHash>

AutoSaveManager::AutoSaveManager(QObject* parent)
    : QObject(parent)
    , m_autoSaveTimer(new QTimer(this))
{
    // Setup auto-save timer
    connect(m_autoSaveTimer, &QTimer::timeout, this, &AutoSaveManager::performAutoSave);
    
    // Default backup directory
    m_backupDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/backups";
    QDir().mkpath(m_backupDir);
    
    // Load existing backup metadata
    loadBackupMetadata();
    
    // Start timer
    if (m_enabled) {
        m_autoSaveTimer->start(m_intervalMs);
    }
}

AutoSaveManager::~AutoSaveManager()
{
    // Save any pending data
    performAutoSave();
    saveBackupMetadata();
}

void AutoSaveManager::setEnabled(bool enabled)
{
    QMutexLocker locker(&m_mutex);
    m_enabled = enabled;
    
    if (enabled) {
        m_autoSaveTimer->start(m_intervalMs);
    } else {
        m_autoSaveTimer->stop();
    }
}

void AutoSaveManager::setInterval(int intervalMs)
{
    QMutexLocker locker(&m_mutex);
    m_intervalMs = intervalMs;
    
    if (m_enabled) {
        m_autoSaveTimer->setInterval(intervalMs);
    }
}

void AutoSaveManager::setBackupDirectory(const QString& backupDir)
{
    QMutexLocker locker(&m_mutex);
    m_backupDir = backupDir;
    QDir().mkpath(m_backupDir);
}

void AutoSaveManager::markDirty(const QString& filePath)
{
    QMutexLocker locker(&m_mutex);
    m_dirtyFiles.insert(filePath);
    
    if (!m_lastSaved.contains(filePath)) {
        m_lastSaved[filePath] = QDateTime::currentDateTime();
    }
    
    emit fileContentChanged(filePath);
}

void AutoSaveManager::markClean(const QString& filePath)
{
    QMutexLocker locker(&m_mutex);
    m_dirtyFiles.remove(filePath);
    m_lastSaved[filePath] = QDateTime::currentDateTime();
}

bool AutoSaveManager::isDirty(const QString& filePath) const
{
    QMutexLocker locker(&m_mutex);
    return m_dirtyFiles.contains(filePath);
}

QSet<QString> AutoSaveManager::getDirtyFiles() const
{
    QMutexLocker locker(&m_mutex);
    return m_dirtyFiles;
}

void AutoSaveManager::saveNow()
{
    performAutoSave();
}

void AutoSaveManager::performAutoSave()
{
    QMutexLocker locker(&m_mutex);
    
    if (m_dirtyFiles.isEmpty()) {
        return;
    }
    
    QSet<QString> filesToSave = m_dirtyFiles;
    
    locker.unlock();
    
    // Emit signal before save
    emit aboutToAutoSave(filesToSave);
    
    // Perform backups
    bool allSuccess = true;
    for (const QString& filePath : filesToSave) {
        if (!createBackup(filePath)) {
            allSuccess = false;
            qWarning() << "Failed to backup:" << filePath;
        }
    }
    
    locker.relock();
    
    // Mark as clean if successful
    if (allSuccess) {
        for (const QString& filePath : filesToSave) {
            m_dirtyFiles.remove(filePath);
            m_lastSaved[filePath] = QDateTime::currentDateTime();
        }
    }
    
    locker.unlock();
    
    // Clean up old backups
    deleteOldBackups();
    
    // Emit completion signal
    emit autoSaveCompleted(filesToSave, allSuccess);
}

void AutoSaveManager::onFileSaved(const QString& filePath)
{
    markClean(filePath);
}

void AutoSaveManager::onApplicationQuitting()
{
    performAutoSave();
    saveBackupMetadata();
}

bool AutoSaveManager::createBackup(const QString& filePath)
{
    if (!QFileInfo::exists(filePath)) {
        return false;
    }
    
    QString backupPath = getBackupPath(filePath);
    
    // Create backup directory if needed
    QFileInfo backupInfo(backupPath);
    QDir().mkpath(backupInfo.absolutePath());
    
    // Copy file to backup location
    if (QFile::exists(backupPath)) {
        QFile::remove(backupPath);
    }
    
    if (!QFile::copy(filePath, backupPath)) {
        return false;
    }
    
    // Update metadata
    m_backupMetadata[filePath] = QDateTime::currentDateTime();
    
    return true;
}

void AutoSaveManager::deleteOldBackups()
{
    QDateTime cutoffTime = QDateTime::currentDateTime().addSecs(-MAX_BACKUP_AGE_HOURS * 3600);
    qint64 totalSize = 0;
    
    QDir backupDir(m_backupDir);
    QFileInfoList entries = backupDir.entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot);
    
    for (const QFileInfo& info : entries) {
        totalSize += info.size();
        
        // Delete if older than retention period
        if (info.lastModified() < cutoffTime) {
            if (info.isFile()) {
                QFile::remove(info.absoluteFilePath());
            } else {
                QDir(info.absoluteFilePath()).removeRecursively();
            }
        }
    }
    
    // Also delete if total size exceeds limit
    if (totalSize > MAX_BACKUP_SIZE_MB * 1024 * 1024) {
        // Sort by modification time and delete oldest
        QList<QFileInfo> files;
        for (const QFileInfo& info : entries) {
            if (info.isFile()) {
                files.append(info);
            }
        }
        
        std::sort(files.begin(), files.end(),
            [](const QFileInfo& a, const QFileInfo& b) {
                return a.lastModified() < b.lastModified();
            });
        
        qint64 currentSize = totalSize;
        for (const QFileInfo& info : files) {
            if (currentSize <= MAX_BACKUP_SIZE_MB * 1024 * 1024) {
                break;
            }
            
            currentSize -= info.size();
            QFile::remove(info.absoluteFilePath());
        }
    }
}

QString AutoSaveManager::getBackupPath(const QString& filePath) const
{
    QFileInfo info(filePath);
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(filePath.toUtf8());
    QString hashStr = hash.result().toHex().left(16);
    
    return m_backupDir + "/" + hashStr + "_" + info.fileName();
}

QString AutoSaveManager::getBackupMetadataPath() const
{
    return m_backupDir + "/metadata.json";
}

void AutoSaveManager::saveBackupMetadata()
{
    QMutexLocker locker(&m_mutex);
    
    QJsonObject root;
    QJsonArray backups;
    
    for (auto it = m_backupMetadata.begin(); it != m_backupMetadata.end(); ++it) {
        QJsonObject backup;
        backup["filePath"] = it.key();
        backup["timestamp"] = it.value().toString(Qt::ISODate);
        backups.append(backup);
    }
    
    root["backups"] = backups;
    root["lastSaved"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    
    QJsonDocument doc(root);
    QFile file(getBackupMetadataPath());
    if (file.open(QIODevice::WriteOnly)) {
        file.write(doc.toJson());
        file.close();
    }
}

void AutoSaveManager::loadBackupMetadata()
{
    QMutexLocker locker(&m_mutex);
    
    QFile file(getBackupMetadataPath());
    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }
    
    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    
    if (!doc.isObject()) {
        return;
    }
    
    QJsonObject root = doc.object();
    QJsonArray backups = root["backups"].toArray();
    
    for (const QJsonValue& value : backups) {
        QJsonObject backup = value.toObject();
        QString filePath = backup["filePath"].toString();
        QString timestamp = backup["timestamp"].toString();
        
        QDateTime dateTime = QDateTime::fromString(timestamp, Qt::ISODate);
        if (dateTime.isValid()) {
            m_backupMetadata[filePath] = dateTime;
        }
    }
}

void AutoSaveManager::restoreFromBackup()
{
    QMutexLocker locker(&m_mutex);
    
    qDebug() << "Restoring from backups...";
    
    for (auto it = m_backupMetadata.begin(); it != m_backupMetadata.end(); ++it) {
        QString filePath = it.key();
        QString backupPath = getBackupPath(filePath);
        
        if (QFileInfo::exists(backupPath)) {
            // Restore only if original file doesn't exist or is newer than backup
            if (!QFileInfo::exists(filePath) || 
                QFileInfo(filePath).lastModified() < QFileInfo(backupPath).lastModified()) {
                
                if (QFile::copy(backupPath, filePath)) {
                    qDebug() << "Restored:" << filePath;
                }
            }
        }
    }
}

void AutoSaveManager::clearBackups()
{
    QMutexLocker locker(&m_mutex);
    
    QDir backupDir(m_backupDir);
    backupDir.removeRecursively();
    
    m_backupMetadata.clear();
    m_lastSaved.clear();
    
    QDir().mkpath(m_backupDir);
}
