#include "codec/compression.h"
#include <zlib.h>
#include <QDebug>

namespace codec {

QByteArray deflate(const QByteArray& data, bool* success) {
    if (data.isEmpty()) {
        if (success) *success = true;
        return QByteArray();
    }
    
    // Use zlib for basic deflate compression
    uLongf compressedSize = compressBound(data.size());
    QByteArray compressed(compressedSize, Qt::Uninitialized);
    
    int result = compress2(reinterpret_cast<Bytef*>(compressed.data()), &compressedSize,
                          reinterpret_cast<const Bytef*>(data.constData()), data.size(),
                          Z_DEFAULT_COMPRESSION);
    
    if (result == Z_OK) {
        compressed.resize(compressedSize);
        if (success) *success = true;
        return compressed;
    } else {
        if (success) *success = false;
        qWarning() << "Deflate compression failed with error:" << result;
        return QByteArray();
    }
}

QByteArray inflate(const QByteArray& data, bool* success) {
    if (success) *success = false;
    if (data.isEmpty()) {
        if (success) *success = true;
        return {};
    }

    z_stream stream{};
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.constData()));
    stream.avail_in = static_cast<uInt>(data.size());
    if (inflateInit(&stream) != Z_OK) return {};

    QByteArray output;
    constexpr int chunkSize = 64 * 1024;
    int status = Z_OK;
    do {
        const auto offset = output.size();
        output.resize(offset + chunkSize);
        stream.next_out = reinterpret_cast<Bytef*>(output.data() + offset);
        stream.avail_out = chunkSize;
        status = ::inflate(&stream, Z_NO_FLUSH);
        output.resize(offset + chunkSize - static_cast<int>(stream.avail_out));
        if (status != Z_OK && status != Z_STREAM_END) break;
    } while (status != Z_STREAM_END);

    inflateEnd(&stream);
    if (status != Z_STREAM_END) {
        qWarning() << "Inflate failed with error:" << status;
        return {};
    }
    if (success) *success = true;
    return output;
}

QByteArray deflate_brutal_masm(const QByteArray& data, bool* success) {
    if (data.isEmpty()) {
        if (success) *success = true;
        return QByteArray();
    }
    
    // Maximum compression with zlib (\"brutal\" mode)
    uLongf compressedSize = compressBound(data.size());
    QByteArray compressed(compressedSize, Qt::Uninitialized);
    
    int result = compress2(reinterpret_cast<Bytef*>(compressed.data()), &compressedSize,
                          reinterpret_cast<const Bytef*>(data.constData()), data.size(),
                          Z_BEST_COMPRESSION);  // Level 9
    
    if (result == Z_OK) {
        compressed.resize(compressedSize);
        if (success) *success = true;
        qDebug() << \"[codec] Brutal compression:\" << data.size() << \"→\" << compressedSize << \"bytes\";\n        return compressed;
    } else {
        if (success) *success = false;
        qWarning() << \"Brutal compression failed with error:\" << result;
        return QByteArray();
    }
}

} // namespace codec