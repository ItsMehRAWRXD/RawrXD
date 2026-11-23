#include "codec/compression.h"

#include <QDebug>
#include <zlib.h>

#include <algorithm>
#include <cstdint>
#include <limits>

namespace codec {
namespace {

QByteArray compressWithLevel(const QByteArray& data, int level, bool* success) {
    if (success) *success = false;
    if (data.isEmpty()) {
        if (success) *success = true;
        return QByteArray();
    }

    using ArraySize = decltype(data.size());
    const auto maxArraySize = (std::numeric_limits<ArraySize>::max)();
    if (static_cast<std::uint64_t>(data.size()) >
        static_cast<std::uint64_t>((std::numeric_limits<uLong>::max)())) {
        qWarning() << "[codec] input exceeds zlib uLong capacity";
        return QByteArray();
    }

    const uLong sourceSize = static_cast<uLong>(data.size());
    const uLong bound = compressBound(sourceSize);
    if (bound < sourceSize ||
        static_cast<std::uint64_t>(bound) >
            static_cast<std::uint64_t>(maxArraySize)) {
        qWarning() << "[codec] compressed output exceeds QByteArray capacity";
        return QByteArray();
    }

    QByteArray output(static_cast<ArraySize>(bound), Qt::Uninitialized);
    uLongf outputSize = bound;
    const int result = compress2(
        reinterpret_cast<Bytef*>(output.data()), &outputSize,
        reinterpret_cast<const Bytef*>(data.constData()), sourceSize, level);
    if (result != Z_OK ||
        static_cast<std::uint64_t>(outputSize) >
            static_cast<std::uint64_t>(maxArraySize)) {
        qWarning() << "[codec] deflate failed:" << result;
        return QByteArray();
    }

    output.resize(static_cast<ArraySize>(outputSize));
    if (success) *success = true;
    return output;
}

} // namespace

QByteArray deflate(const QByteArray& data, bool* success) {
    return compressWithLevel(data, Z_DEFAULT_COMPRESSION, success);
}

QByteArray inflate(const QByteArray& data, bool* success) {
    if (success) *success = false;
    if (data.isEmpty()) {
        if (success) *success = true;
        return QByteArray();
    }

    using ArraySize = decltype(data.size());
    const auto maxArraySize = (std::numeric_limits<ArraySize>::max)();
    z_stream stream{};
    const int initResult = inflateInit(&stream);
    if (initResult != Z_OK) {
        qWarning() << "[codec] inflateInit failed:" << initResult;
        return QByteArray();
    }

    QByteArray output;
    constexpr std::size_t kMaxInflatedBytes = 512u * 1024u * 1024u;
    char chunk[64 * 1024];
    ArraySize inputOffset = 0;
    int status = Z_OK;
    bool valid = true;

    while (status != Z_STREAM_END) {
        if (stream.avail_in == 0 && inputOffset < data.size()) {
            const ArraySize remaining = data.size() - inputOffset;
            const ArraySize inputCount = std::min<ArraySize>(
                remaining, static_cast<ArraySize>((std::numeric_limits<uInt>::max)()));
            stream.next_in = reinterpret_cast<Bytef*>(
                const_cast<char*>(data.constData() + inputOffset));
            stream.avail_in = static_cast<uInt>(inputCount);
            inputOffset += inputCount;
        }

        stream.next_out = reinterpret_cast<Bytef*>(chunk);
        stream.avail_out = static_cast<uInt>(sizeof(chunk));
        const uInt inputBefore = stream.avail_in;
        const int result = ::inflate(&stream, Z_NO_FLUSH);
        status = result;
        const std::size_t produced = sizeof(chunk) - stream.avail_out;
        const auto currentOutput = static_cast<std::size_t>(output.size());

        if (currentOutput > kMaxInflatedBytes ||
            produced > kMaxInflatedBytes - currentOutput) {
            qWarning() << "[codec] inflated output exceeds configured 512 MiB safety ceiling";
            valid = false;
            break;
        }
        if (produced > static_cast<std::uint64_t>(maxArraySize - output.size())) {
            qWarning() << "[codec] inflated output exceeds QByteArray capacity";
            valid = false;
            break;
        }
        if (produced)
            output.append(chunk, static_cast<ArraySize>(produced));

        if (result == Z_STREAM_END) {
            // This API represents exactly one zlib stream. Do not silently
            // accept concatenated streams or arbitrary trailing bytes.
            if (stream.avail_in != 0 || inputOffset != data.size()) {
                qWarning() << "[codec] trailing bytes after zlib stream";
                valid = false;
            }
            break;
        }
        if (result != Z_OK) {
            qWarning() << "[codec] inflate failed:" << result << stream.msg;
            valid = false;
            break;
        }
        if (inputBefore == stream.avail_in && produced == 0 &&
            inputOffset == data.size()) {
            qWarning() << "[codec] truncated or stalled zlib stream";
            valid = false;
            break;
        }
    }

    const int endResult = inflateEnd(&stream);
    if (!valid || status != Z_STREAM_END || endResult != Z_OK) {
        if (endResult != Z_OK)
            qWarning() << "[codec] inflateEnd failed:" << endResult;
        return QByteArray();
    }

    if (success) *success = true;
    return output;
}

QByteArray deflate_brutal_masm(const QByteArray& data, bool* success) {
    // Compatibility name only: this translation unit currently uses zlib
    // level 9. A MASM implementation must be selected explicitly elsewhere.
    QByteArray output = compressWithLevel(data, Z_BEST_COMPRESSION, success);
    if (success && *success)
        qDebug() << "[codec] maximum compression:" << data.size()
                 << "->" << output.size() << "bytes";
    return output;
}

} // namespace codec
