#pragma once

#include "gguf_loader.hpp"
#include "deflate_brutal_qt.hpp"
#include <QString>
#include <QByteArray>
#include <QHash>
#include <QFile>
#include <QDir>
#include <QDebug>
#include <memory>

/**
 * @brief ModelLoaderWithCompression - Loads GGUF models with brutal MASM compression support
 * 
 * This class provides:
 * - GGUF model loading with Qt interface
 * - Brutal MASM compression/decompression for tensor caching
 * - Model metadata extraction and validation
 * - Automatic model conversion detection
 */
class ModelLoaderWithCompression {
public:
    explicit ModelLoaderWithCompression(const QString& modelPath);
    ~ModelLoaderWithCompression();

    // Model loading and validation
    bool loadModel();
    bool isLoaded() const { return m_loaded; }
    QString getModelPath() const { return m_modelPath; }
    
    // Compression operations
    QByteArray compressTensor(const QString& tensorName);
    QByteArray decompressTensor(const QByteArray& compressedData);
    
    // Model metadata
    QHash<QString, QVariant> getModelMetadata() const;
    QStringList getTensorNames() const;
    qint64 getModelSize() const;
    
    // Tensor operations
    QByteArray loadTensor(const QString& tensorName, bool useCache = true);
    bool cacheTensor(const QString& tensorName, const QByteArray& data);
    QByteArray loadCachedTensor(const QString& tensorName);
    
    // Model validation
    bool validateModel() const;
    QStringList getValidationErrors() const;
    
    // Compression statistics
    struct CompressionStats {
        qint64 originalSize = 0;
        qint64 compressedSize = 0;
        double compressionRatio = 0.0;
        qint64 compressionTimeMs = 0;
        qint64 decompressionTimeMs = 0;
    };
    
    CompressionStats getCompressionStats(const QString& tensorName) const;

private:
    QString m_modelPath;
    std::unique_ptr<GGUFLoaderQt> m_loader;
    bool m_loaded = false;
    
    // Compression cache
    QHash<QString, QByteArray> m_compressedCache;
    QHash<QString, CompressionStats> m_compressionStats;
    
    // Cache directory management
    QString getCacheDir() const;
    QString getCacheFilePath(const QString& tensorName) const;
    bool ensureCacheDir() const;
    
    // Internal helpers
    bool loadModelInternal();
    void updateCompressionStats(const QString& tensorName, 
                               qint64 originalSize, qint64 compressedSize,
                               qint64 compressTime, qint64 decompressTime);
};
