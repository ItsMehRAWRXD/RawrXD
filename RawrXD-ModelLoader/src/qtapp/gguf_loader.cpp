#include "gguf_loader.hpp"
#include "codec.h"
#include <cstring>
#include <QDebug>
#include <QMetaType>
#include <QDataStream>

/**
 * Helper to lazily parse the GGUF metadata section.
 * The GGUF spec stores metadata as a sequence of key/value pairs after the
 * tensor offset table. For Phase 4 we only need scalar values (int, float, bool)
 * and raw binary blobs for tokenizer metadata. This implementation reads the
 * metadata once and caches the results in metadataCache.
 */
void GGUFLoader::parseMetadataIfNeeded() const {
    if (metadataParsed) return;

    // Seek to the start of metadata (after tensor offset table)
    qint64 metadataPos = file.pos(); // after reading offsets we are at correct position
    QDataStream ds(&file);
    ds.setByteOrder(QDataStream::LittleEndian);

    // The metadata size is stored in head.metadataSize (bytes)
    qint64 endPos = metadataPos + static_cast<qint64>(head.metadataSize);
    while (file.pos() < endPos) {
        // Read key length (uint32)
        quint32 keyLen;
        ds >> keyLen;
        if (keyLen == 0 || keyLen > 1024) break; // sanity
        QByteArray keyBytes(keyLen, Qt::Uninitialized);
        ds.readRawData(keyBytes.data(), keyLen);
        QString key = QString::fromUtf8(keyBytes);

        // Read value type (uint8)
        quint8 type;
        ds >> type;
        // Types: 0=uint8,1=int8,2=uint16,3=int16,4=uint32,5=int32,6=float32,7=bool,8=string,9=uint64,10=int64,11=float64,12=byte array
        switch (type) {
            case 0: { quint8 v; ds >> v; metadataCache.insert(key, v); break; }
            case 1: { qint8 v; ds >> v; metadataCache.insert(key, v); break; }
            case 2: { quint16 v; ds >> v; metadataCache.insert(key, v); break; }
            case 3: { qint16 v; ds >> v; metadataCache.insert(key, v); break; }
            case 4: { quint32 v; ds >> v; metadataCache.insert(key, v); break; }
            case 5: { qint32 v; ds >> v; metadataCache.insert(key, v); break; }
            case 6: { float v; ds >> v; metadataCache.insert(key, v); break; }
            case 7: { quint8 v; ds >> v; metadataCache.insert(key, v != 0); break; }
            case 8: { // string
                quint64 strLen; ds >> strLen;
                QByteArray strBytes(strLen, Qt::Uninitialized);
                ds.readRawData(strBytes.data(), static_cast<int>(strLen));
                metadataCache.insert(key, QString::fromUtf8(strBytes));
                break; }
            case 9: { quint64 v; ds >> v; metadataCache.insert(key, v); break; }
            case 10: { qint64 v; ds >> v; metadataCache.insert(key, v); break; }
            case 11: { double v; ds >> v; metadataCache.insert(key, v); break; }
            case 12: { // byte array
                quint64 arrLen; ds >> arrLen;
                QByteArray arr(arrLen, Qt::Uninitialized);
                ds.readRawData(arr.data(), static_cast<int>(arrLen));
                metadataCache.insert(key, arr);
                break; }
            default:
                // Unknown type – skip safely
                break;
        }
    }
    metadataParsed = true;
    // Reset file position to after metadata for future reads
    file.seek(endPos);
}

QVariant GGUFLoader::getParam(const QString& key, const QVariant& defaultValue) const {
    parseMetadataIfNeeded();
    auto it = metadataCache.find(key);
    if (it != metadataCache.end()) {
        return it.value();
    }
    return defaultValue;
}

QHash<QString, QByteArray> GGUFLoader::getTokenizerMetadata() const {
    parseMetadataIfNeeded();
    QHash<QString, QByteArray> result;
    // Tokenizer metadata keys are conventionally prefixed with "tokenizer."
    for (auto it = metadataCache.constBegin(); it != metadataCache.constEnd(); ++it) {
        if (it.key().startsWith("tokenizer.")) {
            // Expect stored as QByteArray (type 12). If not, convert to string bytes.
            if (it.value().type() == QMetaType::QByteArray) {
                result.insert(it.key(), it.value().toByteArray());
            } else {
                // Convert any other type to its string representation
                result.insert(it.key(), it.value().toString().toUtf8());
            }
        }
    }
    return result;
}

GGUFLoader::GGUFLoader(const QString& path)
{
    file.setFileName(path);
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "Failed to open GGUF file:" << path;
        return;
    }
    
    QDataStream ds(&file);
    ds.setByteOrder(QDataStream::LittleEndian);
    
    ds.readRawData(head.magic, 4);
    if (memcmp(head.magic, "GGUF", 4) != 0) {
        qWarning() << "Invalid GGUF magic:" << QByteArray(head.magic, 4).toHex();
        file.close();
        return;
    }
    
    ds >> head.version >> head.tensorCount >> head.metadataSize;
    qDebug() << "GGUF version:" << head.version << "tensors:" << head.tensorCount;

    /* Simplified offset map - replace with real GGUF parser */
    for (quint64 i = 0; i < head.tensorCount; ++i) {
        quint32 nameLen;
        ds >> nameLen;
        if (nameLen > 1024) { // Sanity check
            qWarning() << "Suspicious tensor name length:" << nameLen;
            break;
        }
        QByteArray name(nameLen, Qt::Uninitialized);
        ds.readRawData(name.data(), nameLen);
        quint64 offset;
        ds >> offset;
        offsetMap[QString::fromUtf8(name)] = offset;
    }
    qDebug() << "Loaded" << offsetMap.size() << "tensor offsets";
}

GGUFLoader::~GGUFLoader() = default;

QByteArray GGUFLoader::inflateWeight(const QString& tensor)
{
    auto it = offsetMap.constFind(tensor);
    if (it == offsetMap.constEnd()) {
        qWarning() << "Tensor not found:" << tensor;
        return {};
    }
    
    file.seek(*it);
    quint32 packedSz;
    file.read(reinterpret_cast<char*>(&packedSz), 4);
    
    QByteArray packed = file.read(packedSz);
    if (packed.size() != static_cast<int>(packedSz)) {
        qWarning() << "Read mismatch: expected" << packedSz << "got" << packed.size();
        return {};
    }
    
    // === FIX: Use MASM-accelerated brutal inflation ===
    // The GGUF format uses a custom brutal compression. This fix delegates
    // the decompression to a highly optimized MASM implementation.
    QByteArray inflated = inflate_brutal_masm(packed);
    
    if (inflated.isEmpty()) {
        qWarning() << "MASM inflation failed for tensor:" << tensor;
        return {};
    }
    
    return inflated;
}
