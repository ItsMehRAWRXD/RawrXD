#include "gguf_loader.hpp"
#include <QFileInfo>
#include <QDateTime>
#include <QDebug>

GGUFLoader::GGUFLoader(const QString& path)
    : m_path(path)
{
    m_open = QFileInfo::exists(path);
    if (m_open) {
        file.setFileName(path);
        if (!file.open(QIODevice::ReadOnly)) {
            m_open = false;
            qWarning() << "[GGUFLoader] Failed to open file:" << path;
        }
    }
}

GGUFLoader::~GGUFLoader() {
    if (file.isOpen()) {
        file.close();
    }
}

QVariant GGUFLoader::getParam(const QString& key, const QVariant& defaultValue) const
{
    // Simple implementation - return cached value or default
    if (metadataCache.contains(key)) {
        return metadataCache.value(key);
    }
    return defaultValue;
}

QByteArray GGUFLoader::inflateWeight(const QString& tensorName)
{
    // Simple implementation - read from file if offset exists
    if (offsetMap.contains(tensorName)) {
        quint64 offset = offsetMap.value(tensorName);
        if (file.seek(offset)) {
            // Read a reasonable chunk (adjust based on actual tensor size)
            return file.read(4096);
        }
    }
    return QByteArray();
}

QHash<QString, QByteArray> GGUFLoader::getTokenizerMetadata() const
{
    QHash<QString, QByteArray> meta;
    // Simple implementation - return empty for now
    return meta;
}
