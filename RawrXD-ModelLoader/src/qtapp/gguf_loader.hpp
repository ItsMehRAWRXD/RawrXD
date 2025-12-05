#pragma once
#include <QString>
#include <QVariant>
#include <QByteArray>
#include <QHash>
#include <QFile>
#include <QDataStream>
#include <QVector>
#include <QSharedMemory>
#include <QStringList>

struct GGUFHeader {
    char magic[4];      // "GGUF"
    quint32 version;
    quint64 tensorCount;
    quint64 metadataSize;
};

class GGUFLoader {
public:
    explicit GGUFLoader(const QString& path);
    ~GGUFLoader();

    bool isOpen() const { return file.isOpen(); }
    QVariant getParam(const QString& key, const QVariant& defaultValue) const;
    QByteArray inflateWeight(const QString& tensorName);
    QHash<QString, QByteArray> getTokenizerMetadata() const;
    QStringList tensorNames() const { return offsetMap.keys(); }

    /**
     * @brief Retrieve a scalar parameter from GGUF metadata.
     * @param key Metadata key (e.g., "n_layer")
     * @param defaultValue Value to return if key not present
     * @return QVariant containing the value or defaultValue
     */

private:
    QString m_path;
    bool m_open{false};
    QFile file;
    QHash<QString, quint64> offsetMap;
    QHash<QString, QVariant> metadataCache;
    bool metadataParsed{false};
};
