// CompactUtils.cpp — Compact wire protocol implementation
// Phase 5.5: Bandwidth optimization for client-server communication
// Target: ≥3× compression, ≤5ms latency

#include "compact_wire.h"
#include <QDebug>
#include <QJsonDocument>
#include <QJsonObject>

namespace CompactWire {

QByteArray compactWithHeader(const QJsonObject& obj) {
    // Add metadata header for versioning
    QJsonObject wrapped;
    wrapped["v"] = 1;  // Protocol version
    wrapped["data"] = obj;
    
    QByteArray json = QJsonDocument(wrapped).toJson(QJsonDocument::Compact);
    return qCompress(json, 9);
}

QJsonObject expandWithHeader(const QByteArray& compressed) {
    QByteArray json = qUncompress(compressed);
    QJsonObject wrapped = QJsonDocument::fromJson(json).object();
    
    int version = wrapped["v"].toInt();
    if (version != 1) {
        qWarning() << "Unsupported compact wire protocol version:" << version;
        return QJsonObject();
    }
    
    return wrapped["data"].toObject();
}

void printStats(const CompressionStats& stats) {
    qDebug() << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
    qDebug() << "Compact Wire Protocol Benchmark";
    qDebug() << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
    qDebug() << "Original size:   " << stats.original_bytes << "bytes";
    qDebug() << "Compressed size: " << stats.compressed_bytes << "bytes";
    qDebug() << "Compression:     " << QString::number(stats.compression_ratio, 'f', 2) << "×";
    qDebug() << "Compress time:   " << QString::number(stats.compress_ms, 'f', 3) << "ms";
    qDebug() << "Decompress time: " << QString::number(stats.decompress_ms, 'f', 3) << "ms";
    qDebug() << "Total latency:   " << QString::number(stats.compress_ms + stats.decompress_ms, 'f', 3) << "ms";
    
    if (stats.compression_ratio >= 3.0 && (stats.compress_ms + stats.decompress_ms) <= 5.0) {
        qDebug() << "✅ Gate PASS: ≥3× compression, ≤5ms latency";
    } else {
        qDebug() << "❌ Gate FAIL: Target 3× / 5ms not met";
    }
}

} // namespace CompactWire
