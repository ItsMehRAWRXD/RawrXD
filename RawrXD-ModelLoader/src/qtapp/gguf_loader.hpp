#pragma once
#include <QFile>
#include <QDataStream>
#include <QVector>
#include <QSharedMemory>
#include <QHash>
#include <QString>
#include <QStringList>
#include <QVariant>

struct GGUFHeader {
    char magic[4];      // "GGUF"
    quint32 version;
    quint64 tensorCount;
    quint64 metadataSize;
};

struct GGUFLoader {
    explicit GGUFLoader(const QString& path);
    ~GGUFLoader();
    bool  isOpen() const { return file.isOpen(); }
    QByteArray inflateWeight(const QString& tensorName);
    QStringList tensorNames() const { return offsetMap.keys(); }

    /**
     * @brief Retrieve a scalar parameter from GGUF metadata.
     * @param key Metadata key (e.g., "n_layer")
     * @param defaultValue Value to return if key not present
     * @return QVariant containing the value or defaultValue
     */
    QVariant getParam(const QString& key, const QVariant& defaultValue = QVariant()) const;

    /**
     * @brief Retrieve tokenizer‑specific metadata blobs.
     * @return Map of metadata keys to raw QByteArray values.
     */
    QHash<QString, QByteArray> getTokenizerMetadata() const;

private:
    mutable QFile file;  // mutable for lazy metadata parsing
    GGUFHeader head{};
    QSharedMemory shm;          // holds the *inflated* blob
    QHash<QString, quint64> offsetMap; // tensor → file offset
    mutable QHash<QString, QVariant> metadataCache; // scalar metadata cache
    mutable bool metadataParsed = false; // lazy‑parse flag
    // Helper to lazily parse metadata section
    void parseMetadataIfNeeded() const;
};
