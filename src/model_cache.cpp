#include "model_cache.h"
#include "logging/structured_logger.h"
#include "error_handler.h"
#include <QDir>
#include <QCoreApplication>
#include <QSaveFile>
#include <zlib.h>
#include <QJsonDocument>
#include <QJsonObject>

namespace RawrXD {

ModelCache& ModelCache::instance() {
    static ModelCache instance;
    return instance;
}

void ModelCache::initialize(const QString& cacheDir, qint64 maxSizeGB) {
    QMutexLocker lock(&mutex_);
    
    if (initialized_) {
        return;
    }
    
    // Determine cache directory
    if (cacheDir.isEmpty()) {
        QDir appDir(QCoreApplication::applicationDirPath());
        cacheDir_ = appDir.filePath("model_cache");
    } else {
        cacheDir_ = cacheDir;
    }
    
    // Create cache directory
    QDir dir(cacheDir_);
    if (!dir.exists()) {
        if (!dir.mkpath(".")) {
            ERROR_HANDLE("Failed to create model cache directory", ErrorContext()
                .setSeverity(ErrorSeverity::HIGH)
                .setCategory(ErrorCategory::FILE_SYSTEM)
                .setOperation("ModelCache initialization")
                .addMetadata("cache_dir", cacheDir_));
            return;
        }
    }
    
    maxSizeBytes_ = maxSizeGB * 1024LL * 1024LL * 1024LL;
    
    // Load existing cache index
    if (!loadCacheIndex()) {
        LOG_WARN("Failed to load cache index, starting with empty cache");
    }
    
    initialized_ = true;
    
    LOG_INFO("Model cache initialized", {
        {"cache_dir", cacheDir_},
        {"max_size_gb", maxSizeGB},
        {"entry_count", cache_.size()}
    });
}

void ModelCache::shutdown() {
    QMutexLocker lock(&mutex_);
    
    if (initialized_) {
        saveCacheIndex();
        cache_.clear();
        initialized_ = false;
        
        LOG_INFO("Model cache shut down");
    }
}

bool ModelCache::storeModel(const QString& modelId, const QByteArray& modelData, bool compress) {
    QMutexLocker lock(&mutex_);
    
    if (!initialized_) {
        ERROR_HANDLE("Model cache not initialized", ErrorContext()
            .setSeverity(ErrorSeverity::MEDIUM)
            .setCategory(ErrorCategory::CONFIGURATION)
            .setOperation("ModelCache storeModel"));
        return false;
    }
    
    if (modelData.isEmpty()) {
        ERROR_HANDLE("Attempt to store empty model data", ErrorContext()
            .setSeverity(ErrorSeverity::LOW)
            .setCategory(ErrorCategory::MODEL)
            .setOperation("ModelCache storeModel")
            .addMetadata("model_id", modelId));
        return false;
    }
    
    // Check if cache is full and evict if necessary
    while (isCacheFull()) {
        evictLRU();
    }
    
    QString filePath = getCacheFilePath(modelId);
    
    // Store to file
    if (!storeToFile(filePath, modelData, compress)) {
        ERROR_HANDLE("Failed to store model to file", ErrorContext()
            .setSeverity(ErrorSeverity::HIGH)
            .setCategory(ErrorCategory::FILE_SYSTEM)
            .setOperation("ModelCache storeModel")
            .addMetadata("model_id", modelId)
            .addMetadata("file_path", filePath));
        return false;
    }
    
    // Create cache entry
    QSharedPointer<ModelCacheEntry> entry(new ModelCacheEntry(modelId, filePath, modelData));
    entry->compressed = compress;
    
    cache_[modelId] = entry;
    
    LOG_INFO("Model stored in cache", {
        {"model_id", modelId},
        {"size_bytes", modelData.size()},
        {"compressed", compress},
        {"file_path", filePath}
    });
    
    return true;
}

QSharedPointer<ModelCacheEntry> ModelCache::getModel(const QString& modelId) {
    QMutexLocker lock(&mutex_);
    
    if (!initialized_) {
        ERROR_HANDLE("Model cache not initialized", ErrorContext()
            .setSeverity(ErrorSeverity::MEDIUM)
            .setCategory(ErrorCategory::CONFIGURATION)
            .setOperation("ModelCache getModel"));
        return QSharedPointer<ModelCacheEntry>();
    }
    
    if (!cache_.contains(modelId)) {
        return QSharedPointer<ModelCacheEntry>();
    }
    
    QSharedPointer<ModelCacheEntry> entry = cache_[modelId];
    
    // Validate entry
    if (!entry->isValid()) {
        LOG_WARN("Invalid cache entry detected, removing", {{"model_id", modelId}});
        cache_.remove(modelId);
        return QSharedPointer<ModelCacheEntry>();
    }
    
    // Update last accessed time
    entry->touch();
    
    LOG_DEBUG("Model retrieved from cache", {{"model_id", modelId}});
    
    return entry;
}

bool ModelCache::removeModel(const QString& modelId) {
    QMutexLocker lock(&mutex_);
    
    if (!initialized_) {
        return false;
    }
    
    if (!cache_.contains(modelId)) {
        return false;
    }
    
    QSharedPointer<ModelCacheEntry> entry = cache_[modelId];
    
    // Remove file
    if (!entry->filePath.isEmpty()) {
        QFile::remove(entry->filePath);
    }
    
    cache_.remove(modelId);
    
    LOG_INFO("Model removed from cache", {{"model_id", modelId}});
    
    return true;
}

bool ModelCache::containsModel(const QString& modelId) {
    QMutexLocker lock(&mutex_);
    return cache_.contains(modelId);
}

void ModelCache::cleanup() {
    QMutexLocker lock(&mutex_);
    
    if (!initialized_) {
        return;
    }
    
    QList<QString> toRemove;
    
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
        QSharedPointer<ModelCacheEntry> entry = it.value();
        
        // Check TTL
        if (entry->getAgeSeconds() > TTL_HOURS * 3600) {
            toRemove.append(it.key());
            continue;
        }
        
        // Check validity
        if (!entry->isValid()) {
            toRemove.append(it.key());
        }
    }
    
    for (const QString& modelId : toRemove) {
        removeModel(modelId);
    }
    
    if (!toRemove.isEmpty()) {
        LOG_INFO("Cache cleanup completed", {{"removed_entries", toRemove.size()}});
    }
}

void ModelCache::compressCache() {
    QMutexLocker lock(&mutex_);
    
    if (!initialized_) {
        return;
    }
    
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
        QSharedPointer<ModelCacheEntry> entry = it.value();
        
        if (!entry->compressed && entry->size > 10 * 1024 * 1024) { // Compress if > 10MB
            QByteArray compressed = compressData(entry->data);
            if (compressed.size() < entry->size * 0.8) { // Only if compression saves space
                entry->data = compressed;
                entry->compressed = true;
                entry->size = compressed.size();
                entry->updateChecksum();
                
                LOG_DEBUG("Model compressed", {{"model_id", it.key()}, {"compression_ratio", static_cast<double>(compressed.size()) / entry->size}});
            }
        }
    }
}

qint64 ModelCache::getCurrentSize() const {
    QMutexLocker lock(&mutex_);
    
    qint64 total = 0;
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
        total += it.value()->size;
    }
    
    return total;
}

qint64 ModelCache::getMaxSize() const {
    return maxSizeBytes_;
}

int ModelCache::getEntryCount() const {
    QMutexLocker lock(&mutex_);
    return cache_.size();
}

bool ModelCache::validateCache() {
    QMutexLocker lock(&mutex_);
    
    if (!initialized_) {
        return false;
    }
    
    bool valid = true;
    
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
        if (!it.value()->isValid()) {
            valid = false;
            LOG_WARN("Invalid cache entry found", {{"model_id", it.key()}});
        }
    }
    
    return valid;
}

bool ModelCache::validateModel(const QString& modelId) {
    QMutexLocker lock(&mutex_);
    
    if (!cache_.contains(modelId)) {
        return false;
    }
    
    return cache_[modelId]->isValid();
}

bool ModelCache::saveCacheIndex() {
    QJsonObject index;
    
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
        QSharedPointer<ModelCacheEntry> entry = it.value();
        
        QJsonObject entryInfo;
        entryInfo["file_path"] = entry->filePath;
        entryInfo["size"] = static_cast<qint64>(entry->size);
        entryInfo["created"] = entry->created.toString(Qt::ISODate);
        entryInfo["last_accessed"] = entry->lastAccessed.toString(Qt::ISODate);
        entryInfo["checksum"] = entry->checksum;
        entryInfo["compressed"] = entry->compressed;
        
        index[it.key()] = entryInfo;
    }
    
    QFile indexFile(QDir(cacheDir_).filePath("cache_index.json"));
    if (!indexFile.open(QIODevice::WriteOnly)) {
        return false;
    }
    
    QJsonDocument doc(index);
    indexFile.write(doc.toJson());
    indexFile.close();
    
    return true;
}

bool ModelCache::loadCacheIndex() {
    QFile indexFile(QDir(cacheDir_).filePath("cache_index.json"));
    if (!indexFile.exists()) {
        return true; // No index file is okay
    }
    
    if (!indexFile.open(QIODevice::ReadOnly)) {
        return false;
    }
    
    QByteArray data = indexFile.readAll();
    indexFile.close();
    
    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject()) {
        return false;
    }
    
    QJsonObject index = doc.object();
    
    for (auto it = index.begin(); it != index.end(); ++it) {
        QJsonObject entryInfo = it.value().toObject();
        
        QSharedPointer<ModelCacheEntry> entry(new ModelCacheEntry());
        entry->modelId = it.key();
        entry->filePath = entryInfo["file_path"].toString();
        entry->size = entryInfo["size"].toVariant().toLongLong();
        entry->created = QDateTime::fromString(entryInfo["created"].toString(), Qt::ISODate);
        entry->lastAccessed = QDateTime::fromString(entryInfo["last_accessed"].toString(), Qt::ISODate);
        entry->checksum = entryInfo["checksum"].toString();
        entry->compressed = entryInfo["compressed"].toBool();
        entry->valid = true;
        
        cache_[it.key()] = entry;
    }
    
    return true;
}

QString ModelCache::getCacheFilePath(const QString& modelId) {
    // Create a safe filename from modelId
    QString safeId = modelId;
    safeId.replace(QRegExp("[^a-zA-Z0-9_.-]"), "_");
    
    return QDir(cacheDir_).filePath(safeId + ".model");
}

bool ModelCache::storeToFile(const QString& filePath, const QByteArray& data, bool compress) {
    QSaveFile file(filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }
    
    QByteArray dataToWrite = compress ? compressData(data) : data;
    
    if (file.write(dataToWrite) != dataToWrite.size()) {
        return false;
    }
    
    return file.commit();
}

QByteArray ModelCache::loadFromFile(const QString& filePath, bool decompress) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return QByteArray();
    }
    
    QByteArray data = file.readAll();
    file.close();
    
    return decompress ? decompressData(data) : data;
}

QByteArray ModelCache::compressData(const QByteArray& data) {
    // Simple zlib compression
    QByteArray compressed = qCompress(data);
    return compressed;
}

QByteArray ModelCache::decompressData(const QByteArray& data) {
    // Simple zlib decompression
    return qUncompress(data);
}

void ModelCache::evictLRU() {
    QString lruKey;
    QDateTime lruTime = QDateTime::currentDateTime();
    
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
        if (it.value()->lastAccessed < lruTime) {
            lruTime = it.value()->lastAccessed;
            lruKey = it.key();
        }
    }
    
    if (!lruKey.isEmpty()) {
        removeModel(lruKey);
    }
}

bool ModelCache::isCacheFull() const {
    return getCurrentSize() > maxSizeBytes_;
}

ModelCache::~ModelCache() {
    shutdown();
}

} // namespace RawrXD
