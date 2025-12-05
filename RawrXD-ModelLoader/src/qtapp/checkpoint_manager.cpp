#include "checkpoint_manager.h"
#include <QDebug>
#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonArray>
#ifdef HAVE_ZLIB
#include <zlib.h>
#endif
#include <algorithm>
#include <numeric>

/**
 * @brief CheckpointManager::CheckpointManager - Constructor
 */
CheckpointManager::CheckpointManager(QObject* parent)
    : QObject(parent), m_checkpointDir(""), m_maxCheckpoints(10),
      m_autoCheckpointInterval(100), m_bestValidationLoss(std::numeric_limits<float>::max()),
      m_compressionLevel(CompressionLevel::Medium), m_lastCheckpointStep(-1)
{
    qDebug() << "[CheckpointManager] Initializing checkpoint manager";
    
    // Set default checkpoint directory
    QString dataPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    m_checkpointDir = dataPath + "/checkpoints";
    QDir().mkpath(m_checkpointDir);
    
    loadCheckpointHistory();
}

/**
 * @brief CheckpointManager::~CheckpointManager - Destructor
 */
CheckpointManager::~CheckpointManager()
{
    qDebug() << "[CheckpointManager] Checkpoint manager destroyed";
}

/**
 * @brief CheckpointManager::saveCheckpoint - Save model checkpoint
 */
bool CheckpointManager::saveCheckpoint(const CheckpointMetadata& metadata,
                                       const QByteArray& modelState,
                                       const QByteArray& optimizerState,
                                       const QByteArray& trainingState)
{
    qDebug() << "[CheckpointManager] Saving checkpoint at step" << metadata.step;
    
    try {
        // Generate checkpoint ID
        QString checkpointId = QString("ckpt_%1_%2")
            .arg(metadata.step)
            .arg(QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss"));
        
        // Create checkpoint directory
        QString ckptPath = m_checkpointDir + "/" + checkpointId;
        QDir().mkpath(ckptPath);
        
        // Compress and save model state
        QString modelFile = ckptPath + "/model.bin.gz";
        if (!saveCompressedData(modelFile, modelState)) {
            qCritical() << "[CheckpointManager] Failed to save model state";
            return false;
        }
        
        // Compress and save optimizer state
        QString optimizerFile = ckptPath + "/optimizer.bin.gz";
        if (!saveCompressedData(optimizerFile, optimizerState)) {
            qCritical() << "[CheckpointManager] Failed to save optimizer state";
            return false;
        }
        
        // Compress and save training state
        QString trainingFile = ckptPath + "/training.bin.gz";
        if (!saveCompressedData(trainingFile, trainingState)) {
            qCritical() << "[CheckpointManager] Failed to save training state";
            return false;
        }
        
        // Save metadata
        CheckpointMetadata saveMeta = metadata;
        saveMeta.checkpointId = checkpointId;
        QString metaFile = ckptPath + "/metadata.json";
        if (!saveMetadata(metaFile, saveMeta)) {
            qCritical() << "[CheckpointManager] Failed to save metadata";
            return false;
        }
        
        // Add to history
        m_checkpointHistory.push_back(saveMeta);
        
        // Track best model
        if (metadata.validationLoss < m_bestValidationLoss) {
            m_bestValidationLoss = metadata.validationLoss;
            m_bestCheckpointId = checkpointId;
            qDebug() << "[CheckpointManager] New best model found with validation loss:" << m_bestValidationLoss;
        }
        
        // Prune old checkpoints
        pruneOldCheckpoints();
        
        m_lastCheckpointStep = metadata.step;
        
        emit checkpointSaved(checkpointId, metadata.step);
        
        qDebug() << "[CheckpointManager] Checkpoint saved:" << checkpointId;
        return true;
    }
    catch (const std::exception& e) {
        qCritical() << "[CheckpointManager] Failed to save checkpoint:" << e.what();
        return false;
    }
}

/**
 * @brief CheckpointManager::loadCheckpoint - Load checkpoint
 */
bool CheckpointManager::loadCheckpoint(const QString& checkpointId,
                                       QByteArray& modelState,
                                       QByteArray& optimizerState,
                                       QByteArray& trainingState,
                                       CheckpointMetadata& metadata)
{
    qDebug() << "[CheckpointManager] Loading checkpoint:" << checkpointId;
    
    try {
        QString ckptPath = m_checkpointDir + "/" + checkpointId;
        
        // Load metadata
        QString metaFile = ckptPath + "/metadata.json";
        if (!loadMetadata(metaFile, metadata)) {
            qCritical() << "[CheckpointManager] Failed to load metadata";
            return false;
        }
        
        // Load model state
        QString modelFile = ckptPath + "/model.bin.gz";
        if (!loadCompressedData(modelFile, modelState)) {
            qCritical() << "[CheckpointManager] Failed to load model state";
            return false;
        }
        
        // Load optimizer state
        QString optimizerFile = ckptPath + "/optimizer.bin.gz";
        if (!loadCompressedData(optimizerFile, optimizerState)) {
            qCritical() << "[CheckpointManager] Failed to load optimizer state";
            return false;
        }
        
        // Load training state
        QString trainingFile = ckptPath + "/training.bin.gz";
        if (!loadCompressedData(trainingFile, trainingState)) {
            qCritical() << "[CheckpointManager] Failed to load training state";
            return false;
        }
        
        emit checkpointLoaded(checkpointId, metadata.step);
        
        qDebug() << "[CheckpointManager] Checkpoint loaded successfully";
        return true;
    }
    catch (const std::exception& e) {
        qCritical() << "[CheckpointManager] Failed to load checkpoint:" << e.what();
        return false;
    }
}

/**
 * @brief CheckpointManager::saveCompressedData - Save data with zlib compression (or uncompressed fallback)
 */
bool CheckpointManager::saveCompressedData(const QString& filepath, const QByteArray& data)
{
    try {
#ifdef HAVE_ZLIB
        // Get compression level
        int zlibLevel = Z_DEFAULT_COMPRESSION;
        switch (m_compressionLevel) {
            case CompressionLevel::None:
                zlibLevel = Z_NO_COMPRESSION;
                break;
            case CompressionLevel::Low:
                zlibLevel = 1;
                break;
            case CompressionLevel::Medium:
                zlibLevel = 6;
                break;
            case CompressionLevel::High:
                zlibLevel = 9;
                break;
            case CompressionLevel::Maximum:
                zlibLevel = 9;
                break;
        }
        
        // Compress data
        uLongf compressedSize = compressBound(data.size());
        QByteArray compressed(compressedSize, 0);
        
        int ret = compress2(
            reinterpret_cast<unsigned char*>(compressed.data()),
            &compressedSize,
            reinterpret_cast<const unsigned char*>(data.data()),
            data.size(),
            zlibLevel
        );
        
        if (ret != Z_OK) {
            qCritical() << "[CheckpointManager] Compression failed with code:" << ret;
            return false;
        }
        
        compressed.truncate(compressedSize);
        
        // Write to file
        QFile file(filepath);
        if (!file.open(QIODevice::WriteOnly)) {
            qCritical() << "[CheckpointManager] Failed to open file for writing:" << filepath;
            return false;
        }
        
        qint64 written = file.write(compressed);
        file.close();
        
        if (written != compressed.size()) {
            qCritical() << "[CheckpointManager] Failed to write all data to file";
            return false;
        }
        
        qDebug() << "[CheckpointManager] Saved compressed data:" << filepath
                 << "Original:" << data.size() << "bytes, Compressed:" << compressedSize << "bytes";
        
        return true;
#else
        // Fallback: Save uncompressed
        qWarning() << "[CheckpointManager] ZLIB not available - saving uncompressed";
        
        QFile file(filepath);
        if (!file.open(QIODevice::WriteOnly)) {
            qCritical() << "[CheckpointManager] Failed to open file for writing:" << filepath;
            return false;
        }
        
        qint64 written = file.write(data);
        file.close();
        
        if (written != data.size()) {
            qCritical() << "[CheckpointManager] Failed to write all data to file";
            return false;
        }
        
        qDebug() << "[CheckpointManager] Saved uncompressed data:" << filepath << "Size:" << data.size() << "bytes";
        return true;
#endif
    }
    catch (const std::exception& e) {
        qCritical() << "[CheckpointManager] Save failed:" << e.what();
        return false;
    }
}

/**
 * @brief CheckpointManager::loadCompressedData - Load and decompress data (or load uncompressed fallback)
 */
bool CheckpointManager::loadCompressedData(const QString& filepath, QByteArray& data)
{
    try {
        // Read file
        QFile file(filepath);
        if (!file.open(QIODevice::ReadOnly)) {
            qCritical() << "[CheckpointManager] Failed to open file for reading:" << filepath;
            return false;
        }
        
        QByteArray fileData = file.readAll();
        file.close();
        
#ifdef HAVE_ZLIB
        // Try to decompress data (estimate 10x expansion)
        uLongf decompressedSize = fileData.size() * 10;
        data.resize(decompressedSize);
        
        int ret = uncompress(
            reinterpret_cast<unsigned char*>(data.data()),
            &decompressedSize,
            reinterpret_cast<const unsigned char*>(fileData.data()),
            fileData.size()
        );
        
        if (ret != Z_OK) {
            qCritical() << "[CheckpointManager] Decompression failed with code:" << ret;
            return false;
        }
        
        data.truncate(decompressedSize);
        
        qDebug() << "[CheckpointManager] Loaded compressed data:" << filepath
                 << "Decompressed:" << decompressedSize << "bytes";
        
        return true;
#else
        // Fallback: Treat as uncompressed
        qWarning() << "[CheckpointManager] ZLIB not available - loading as uncompressed";
        data = fileData;
        qDebug() << "[CheckpointManager] Loaded uncompressed data:" << filepath << "Size:" << fileData.size() << "bytes";
        return true;
#endif
    }
    catch (const std::exception& e) {
        qCritical() << "[CheckpointManager] Load failed:" << e.what();
        return false;
    }
}

/**
 * @brief CheckpointManager::saveMetadata - Save checkpoint metadata as JSON
 */
bool CheckpointManager::saveMetadata(const QString& filepath, const CheckpointMetadata& metadata)
{
    try {
        QJsonObject obj;
        obj["checkpointId"] = metadata.checkpointId;
        obj["epoch"] = metadata.epoch;
        obj["step"] = metadata.step;
        obj["timestamp"] = metadata.timestamp;
        obj["validationLoss"] = metadata.validationLoss;
        obj["trainLoss"] = metadata.trainLoss;
        obj["accuracy"] = metadata.accuracy;
        obj["wallclockTime"] = metadata.wallclockTime;
        obj["modelSize"] = metadata.modelSize;
        obj["modelArchitecture"] = metadata.modelArchitecture;
        obj["hyperparameters"] = metadata.hyperparameters;
        
        QJsonDocument doc(obj);
        QFile file(filepath);
        
        if (!file.open(QIODevice::WriteOnly)) {
            qCritical() << "[CheckpointManager] Failed to open metadata file for writing";
            return false;
        }
        
        file.write(doc.toJson());
        file.close();
        
        return true;
    }
    catch (const std::exception& e) {
        qCritical() << "[CheckpointManager] Failed to save metadata:" << e.what();
        return false;
    }
}

/**
 * @brief CheckpointManager::loadMetadata - Load checkpoint metadata from JSON
 */
bool CheckpointManager::loadMetadata(const QString& filepath, CheckpointMetadata& metadata)
{
    try {
        QFile file(filepath);
        if (!file.open(QIODevice::ReadOnly)) {
            qCritical() << "[CheckpointManager] Failed to open metadata file for reading";
            return false;
        }
        
        QByteArray data = file.readAll();
        file.close();
        
        QJsonDocument doc = QJsonDocument::fromJson(data);
        QJsonObject obj = doc.object();
        
        metadata.checkpointId = obj["checkpointId"].toString();
        metadata.epoch = obj["epoch"].toInt();
        metadata.step = obj["step"].toInt();
        metadata.timestamp = obj["timestamp"].toString();
        metadata.validationLoss = static_cast<float>(obj["validationLoss"].toDouble());
        metadata.trainLoss = static_cast<float>(obj["trainLoss"].toDouble());
        metadata.accuracy = static_cast<float>(obj["accuracy"].toDouble());
        metadata.wallclockTime = static_cast<float>(obj["wallclockTime"].toDouble());
        metadata.modelSize = obj["modelSize"].toInt();
        metadata.modelArchitecture = obj["modelArchitecture"].toString();
        metadata.hyperparameters = obj["hyperparameters"].toString();
        
        return true;
    }
    catch (const std::exception& e) {
        qCritical() << "[CheckpointManager] Failed to load metadata:" << e.what();
        return false;
    }
}

/**
 * @brief CheckpointManager::pruneOldCheckpoints - Remove old checkpoints to save disk space
 */
void CheckpointManager::pruneOldCheckpoints()
{
    qDebug() << "[CheckpointManager] Pruning old checkpoints";
    
    try {
        // Sort by step (descending)
        std::sort(m_checkpointHistory.begin(), m_checkpointHistory.end(),
                 [](const CheckpointMetadata& a, const CheckpointMetadata& b) {
                     return a.step > b.step;
                 });
        
        // Keep only maxCheckpoints
        while (m_checkpointHistory.size() > static_cast<size_t>(m_maxCheckpoints)) {
            const auto& oldCkpt = m_checkpointHistory.back();
            
            // Don't delete best checkpoint
            if (oldCkpt.checkpointId != m_bestCheckpointId) {
                QString ckptPath = m_checkpointDir + "/" + oldCkpt.checkpointId;
                QDir(ckptPath).removeRecursively();
                qDebug() << "[CheckpointManager] Deleted old checkpoint:" << oldCkpt.checkpointId;
            }
            
            m_checkpointHistory.pop_back();
        }
    }
    catch (const std::exception& e) {
        qWarning() << "[CheckpointManager] Pruning failed:" << e.what();
    }
}

/**
 * @brief CheckpointManager::loadCheckpointHistory - Load checkpoint history from disk
 */
void CheckpointManager::loadCheckpointHistory()
{
    qDebug() << "[CheckpointManager] Loading checkpoint history";
    
    try {
        QDir ckptDir(m_checkpointDir);
        QStringList checkpoints = ckptDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
        
        for (const auto& ckpt : checkpoints) {
            QString metaFile = m_checkpointDir + "/" + ckpt + "/metadata.json";
            CheckpointMetadata metadata;
            
            if (loadMetadata(metaFile, metadata)) {
                m_checkpointHistory.push_back(metadata);
            }
        }
        
        qDebug() << "[CheckpointManager] Loaded" << m_checkpointHistory.size() << "checkpoints";
    }
    catch (const std::exception& e) {
        qWarning() << "[CheckpointManager] Failed to load checkpoint history:" << e.what();
    }
}

/**
 * @brief CheckpointManager::shouldAutoCheckpoint - Check if should auto-checkpoint
 */
bool CheckpointManager::shouldAutoCheckpoint(int currentStep)
{
    return (currentStep - m_lastCheckpointStep) >= m_autoCheckpointInterval;
}

/**
 * @brief CheckpointManager::getCheckpointList - Get list of all checkpoints
 */
std::vector<CheckpointMetadata> CheckpointManager::getCheckpointList()
{
    return m_checkpointHistory;
}

/**
 * @brief CheckpointManager::getBestCheckpointId - Get ID of best checkpoint
 */
QString CheckpointManager::getBestCheckpointId()
{
    return m_bestCheckpointId;
}

/**
 * @brief CheckpointManager::deleteCheckpoint - Delete a checkpoint
 */
bool CheckpointManager::deleteCheckpoint(const QString& checkpointId)
{
    qDebug() << "[CheckpointManager] Deleting checkpoint:" << checkpointId;
    
    try {
        if (checkpointId == m_bestCheckpointId) {
            qWarning() << "[CheckpointManager] Cannot delete best checkpoint";
            return false;
        }
        
        QString ckptPath = m_checkpointDir + "/" + checkpointId;
        QDir dir(ckptPath);
        
        if (!dir.removeRecursively()) {
            qCritical() << "[CheckpointManager] Failed to delete checkpoint directory";
            return false;
        }
        
        // Remove from history
        m_checkpointHistory.erase(
            std::remove_if(m_checkpointHistory.begin(), m_checkpointHistory.end(),
                         [&checkpointId](const CheckpointMetadata& m) {
                             return m.checkpointId == checkpointId;
                         }),
            m_checkpointHistory.end()
        );
        
        return true;
    }
    catch (const std::exception& e) {
        qCritical() << "[CheckpointManager] Failed to delete checkpoint:" << e.what();
        return false;
    }
}

/**
 * @brief CheckpointManager::setCompressionLevel - Set compression level
 */
void CheckpointManager::setCompressionLevel(CompressionLevel level)
{
    m_compressionLevel = level;
    qDebug() << "[CheckpointManager] Compression level set to:" << static_cast<int>(level);
}

/**
 * @brief CheckpointManager::setAutoCheckpointInterval - Set auto-checkpoint interval
 */
void CheckpointManager::setAutoCheckpointInterval(int interval)
{
    m_autoCheckpointInterval = interval;
    qDebug() << "[CheckpointManager] Auto-checkpoint interval set to:" << interval << "steps";
}

/**
 * @brief CheckpointManager::getCheckpointSize - Get size of checkpoint
 */
qint64 CheckpointManager::getCheckpointSize(const QString& checkpointId)
{
    QString ckptPath = m_checkpointDir + "/" + checkpointId;
    QDir dir(ckptPath);
    
    qint64 size = 0;
    QFileInfoList files = dir.entryInfoList(QDir::Files | QDir::Recursive);
    
    for (const auto& file : files) {
        size += file.size();
    }
    
    return size;
}
