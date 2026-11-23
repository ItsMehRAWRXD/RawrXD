#include "codec/compression.h"
#include <zlib.h>
#include <QDebug>
#include <algorithm>
#include <limits>

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
        return QByteArray();
    }

    z_stream stream{};
    if (inflateInit(&stream) != Z_OK) {
        qWarning() << "zlib inflateInit failed";
        return QByteArray();
    }

    QByteArray output;
    char chunk[64 * 1024];
    auto inputOffset = decltype(data.size()){0};
    int status = Z_OK;
    bool failed = false;
    const auto maxArraySize = (std::numeric_limits<decltype(data.size())>::max)();

    while (status != Z_STREAM_END) {
        if (stream.avail_in == 0 && inputOffset < data.size()) {
            const auto remaining = data.size() - inputOffset;
            const auto inputCount = std::min<decltype(data.size())>(
                remaining, static_cast<decltype(data.size())>(
                    (std::numeric_limits<uInt>::max)()));
            stream.next_in = reinterpret_cast<Bytef*>(
                const_cast<char*>(data.constData() + inputOffset));
            stream.avail_in = static_cast<uInt>(inputCount);
            inputOffset += inputCount;
        }

        stream.next_out = reinterpret_cast<Bytef*>(chunk);
        stream.avail_out = static_cast<uInt>(sizeof(chunk));
        const auto beforeInput = stream.avail_in;
        status = ::inflate(&stream, Z_NO_FLUSH);

        const auto produced = sizeof(chunk) - stream.avail_out;
        if (produced > static_cast<std::size_t>(maxArraySize - output.size())) {
            qWarning() << "zlib output exceeds QByteArray capacity";
            failed = true;
            break;
        }
        if (produced)
            output.append(chunk, static_cast<decltype(data.size())>(produced));

        if (status == Z_STREAM_END) break;
        if (status != Z_OK) {
            qWarning() << "Inflate decompression failed with error:" << status;
            failed = true;
            break;
        }
        if (beforeInput == stream.avail_in && produced == 0 &&
            inputOffset >= data.size()) {
            qWarning() << "Inflate decompression made no progress";
            failed = true;
            break;
        }
    }

    inflateEnd(&stream);
    if (failed || status != Z_STREAM_END)
        return QByteArray();
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
        qDebug() << "[codec] Brutal compression:" << data.size() << "->" << compressedSize;
        return compressed;
    } else {
        if (success) *success = false;
        qWarning() << "Brutal compression failed with error:" << result;
        return QByteArray();
    }
}

} // namespace codec