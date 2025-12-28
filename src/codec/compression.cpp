#include "codec/compression.h"
#include <QDebug>
#include "deflate_brutal_qt.hpp"

namespace codec {

QByteArray deflate(const QByteArray& data, bool* success) {
    if (data.isEmpty()) {
        if (success) *success = true;
        return QByteArray();
    }
    
    // Use our MASM brutal compression instead of zlib
    QByteArray compressed = brutal::compress(data);
    
    if (!compressed.isEmpty()) {
        if (success) *success = true;
        qDebug() << "[codec] MASM compression:" << data.size() << "→" << compressed.size() << "bytes";
        return compressed;
    } else {
        if (success) *success = false;
        qWarning() << "MASM compression failed";
        return QByteArray();
    }
}

QByteArray inflate(const QByteArray& data, bool* success) {
    if (data.isEmpty()) {
        if (success) *success = true;
        return QByteArray();
    }
    
    // Use our MASM brutal decompression
    QByteArray decompressed = brutal::decompress(data);
    
    if (!decompressed.isEmpty()) {
        if (success) *success = true;
        qDebug() << "[codec] MASM decompression:" << data.size() << "→" << decompressed.size() << "bytes";
        return decompressed;
    } else {
        if (success) *success = false;
        qWarning() << "MASM decompression failed";
        return QByteArray();
    }
}

QByteArray deflate_brutal_masm(const QByteArray& data, bool* success) {
    if (data.isEmpty()) {
        if (success) *success = true;
        return QByteArray();
    }
    
    // Use our MASM brutal compression
    QByteArray compressed = brutal::compress(data);
    
    if (!compressed.isEmpty()) {
        if (success) *success = true;
        qDebug() << "[codec] MASM brutal compression:" << data.size() << "→" << compressed.size() << "bytes";
        return compressed;
    } else {
        if (success) *success = false;
        qWarning() << "MASM brutal compression failed";
        return QByteArray();
    }
}

} // namespace codec
