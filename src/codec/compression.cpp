#include "codec/compression.h"

#include <QDebug>
#include <zlib.h>

#include <climits>
#include <cstdint>
#include <limits>

namespace codec {
namespace {

QByteArray CompressWithLevel(const QByteArray& data, int level, bool* success) {
    if (success) *success = false;
    if (data.isEmpty()) {
        if (success) *success = true;
        return QByteArray();
    }

    // zlib's uLong is 32-bit on Win64. Do not truncate a Qt 6 QByteArray
    // length before handing it to the zlib ABI.
    if (static_cast<std::uint64_t>(data.size()) >
        static_cast<std::uint64_t>(std::numeric_limits<uLong>::max())) {
        qWarning() << "[codec] input exceeds zlib uLong capacity";
        return QByteArray();
    }
    const uLong sourceSize = static_cast<uLong>(data.size());
    // Guard compressBound's uLong arithmetic before calling into zlib. This
    // matters on Win64, where uLong is still 32-bit even though QByteArray's
    // qsizetype is 64-bit.
    const uLong maxULong = std::numeric_limits<uLong>::max();
    const uLong overhead = (sourceSize >> 12) + (sourceSize >> 14) +
                           (sourceSize >> 25) + 13u;
    if (sourceSize > maxULong - overhead) {
        qWarning() << "[codec] zlib compressBound arithmetic would overflow";
        return QByteArray();
    }
    const uLong bound = compressBound(sourceSize);
    if (bound > static_cast<uLong>(INT_MAX)) {
        qWarning() << "[codec] compressed output exceeds QByteArray capacity";
        return QByteArray();
    }

    QByteArray output(static_cast<int>(bound), Qt::Uninitialized);
    uLongf outputSize = bound;
    const int result = compress2(
        reinterpret_cast<Bytef*>(output.data()), &outputSize,
        reinterpret_cast<const Bytef*>(data.constData()), sourceSize, level);
    if (result != Z_OK || outputSize > static_cast<uLongf>(INT_MAX)) {
        qWarning() << "[codec] deflate failed:" << result;
        return QByteArray();
    }

    output.resize(static_cast<int>(outputSize));
    if (success) *success = true;
    return output;
}

} // namespace

QByteArray deflate(const QByteArray& data, bool* success) {
    return CompressWithLevel(data, Z_DEFAULT_COMPRESSION, success);
}

QByteArray inflate(const QByteArray& data, bool* success) {
    if (success) *success = false;
    if (data.isEmpty()) {
        if (success) *success = true;
        return QByteArray();
    }

    // z_stream::avail_in is uInt even when Qt 6 uses a wider qsizetype.
    // Reject oversized input rather than silently truncating the stream.
    if (static_cast<std::uint64_t>(data.size()) >
        static_cast<std::uint64_t>(std::numeric_limits<uInt>::max())) {
        qWarning() << "[codec] input exceeds zlib avail_in capacity";
        return QByteArray();
    }

    // Stream into bounded chunks. The old 4x/10x guesses rejected valid
    // highly-compressible inputs and could overflow size calculations.
    z_stream stream{};
    const int initResult = inflateInit(&stream);
    if (initResult != Z_OK) {
        qWarning() << "[codec] inflateInit failed:" << initResult;
        return QByteArray();
    }

    stream.next_in = reinterpret_cast<Bytef*>(
        const_cast<char*>(data.constData()));
    stream.avail_in = static_cast<uInt>(data.size());

    QByteArray output;
    char chunk[64 * 1024];
    bool complete = false;
    bool valid = true;

    for (;;) {
        stream.next_out = reinterpret_cast<Bytef*>(chunk);
        stream.avail_out = static_cast<uInt>(sizeof(chunk));

        const uInt inputBefore = stream.avail_in;
        const int result = ::inflate(&stream, Z_NO_FLUSH);
        const size_t produced = sizeof(chunk) - stream.avail_out;

        if (produced > static_cast<size_t>(INT_MAX - output.size())) {
            qWarning() << "[codec] inflated output exceeds QByteArray capacity";
            valid = false;
            break;
        }
        if (produced)
            output.append(chunk, static_cast<int>(produced));

        if (result == Z_STREAM_END) {
            // This API represents exactly one zlib stream; reject trailing
            // bytes rather than silently accepting concatenated/corrupt data.
            complete = (stream.avail_in == 0);
            if (!complete)
                qWarning() << "[codec] trailing bytes after zlib stream";
            break;
        }
        if (result != Z_OK) {
            qWarning() << "[codec] inflate failed:" << result << stream.msg;
            valid = false;
            break;
        }

        // No input consumed and no output produced means a truncated or
        // otherwise stalled stream, not a successful empty decode.
        if (inputBefore == stream.avail_in && produced == 0) {
            qWarning() << "[codec] truncated or stalled zlib stream";
            valid = false;
            break;
        }
    }

    const int endResult = inflateEnd(&stream);
    if (!valid || !complete || endResult != Z_OK) {
        if (endResult != Z_OK)
            qWarning() << "[codec] inflateEnd failed:" << endResult;
        return QByteArray();
    }

    if (success) *success = true;
    return output;
}

QByteArray deflate_brutal_masm(const QByteArray& data, bool* success) {
    // Compatibility entry point: use zlib's maximum-compression path when
    // the optional MASM implementation is not linked into this translation
    // unit. This function does not claim to execute an assembly kernel.
    QByteArray output = CompressWithLevel(data, Z_BEST_COMPRESSION, success);
    if (success && *success)
        qDebug() << "[codec] maximum compression:" << data.size()
                 << "->" << output.size() << "bytes";
    return output;
}

} // namespace codec
