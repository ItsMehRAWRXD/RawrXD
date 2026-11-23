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

    // Stream into bounded stack chunks rather than reserving compressBound()
    // bytes up front. For large inputs, that bound can be substantially larger
    // than the final compressed payload and inflate peak working-set memory.
    using ArraySize = decltype(data.size());
    const auto maxArraySize = (std::numeric_limits<ArraySize>::max)();
    z_stream stream{};
    const int initResult = deflateInit(&stream, level);
    if (initResult != Z_OK) {
        qWarning() << "[codec] deflateInit failed:" << initResult;
        return QByteArray();
    }

    QByteArray output;
    char chunk[64 * 1024];
    ArraySize inputOffset = 0;
    int status = Z_OK;
    bool valid = true;
    while (status != Z_STREAM_END) {
        if (stream.avail_in == 0 && inputOffset < data.size()) {
            const std::uint64_t remaining =
                static_cast<std::uint64_t>(data.size() - inputOffset);
            const uInt count = static_cast<uInt>(std::min<std::uint64_t>(
                remaining, (std::numeric_limits<uInt>::max)()));
            stream.next_in = reinterpret_cast<Bytef*>(
                const_cast<char*>(data.constData() + inputOffset));
            stream.avail_in = count;
            inputOffset += static_cast<ArraySize>(count);
        }
        const int flush = (inputOffset == data.size()) ? Z_FINISH : Z_NO_FLUSH;
        stream.next_out = reinterpret_cast<Bytef*>(chunk);
        stream.avail_out = static_cast<uInt>(sizeof(chunk));
        const uInt inputBefore = stream.avail_in;
        status = ::deflate(&stream, flush);
        const std::size_t produced = sizeof(chunk) - stream.avail_out;
        if (status != Z_OK && status != Z_STREAM_END) {
            qWarning() << "[codec] streaming deflate failed:" << status;
            valid = false;
            break;
        }
        if (static_cast<std::uint64_t>(produced) >
            static_cast<std::uint64_t>(maxArraySize) -
                static_cast<std::uint64_t>(output.size())) {
            qWarning() << "[codec] compressed output exceeds QByteArray capacity";
            valid = false;
            break;
        }
        if (produced)
            output.append(chunk, static_cast<ArraySize>(produced));
        // Avoid a nonterminating loop if the compressor stops making
        // progress, including when a future zlib provider behaves differently.
        if (status == Z_OK && produced == 0 &&
            inputBefore == stream.avail_in) {
            qWarning() << "[codec] streaming deflate stalled";
            valid = false;
            break;
        }
    }
    const int endResult = deflateEnd(&stream);
    if (!valid || status != Z_STREAM_END || endResult != Z_OK)
        return QByteArray();
    if (success) *success = true;
    return output;
}

} // namespace

QByteArray deflate(const QByteArray& data, bool* success) {
    return compressWithLevel(data, Z_DEFAULT_COMPRESSION, success);
}

QByteArray inflate(const QByteArray& data, bool* success,
                   qint64 maxOutputBytes) {
    if (success) *success = false;
    if (maxOutputBytes < 0) {
        qWarning() << "[codec] negative inflate output ceiling";
        return QByteArray();
    }
    if (data.isEmpty()) {
        if (success) *success = true;
        return QByteArray();
    }

    using ArraySize = decltype(data.size());
    const auto maxArraySize = (std::numeric_limits<ArraySize>::max)();
    const std::uint64_t outputCeiling = std::min<std::uint64_t>(
        static_cast<std::uint64_t>(maxArraySize),
        static_cast<std::uint64_t>(maxOutputBytes));

    z_stream stream{};
    const int initResult = inflateInit(&stream);
    if (initResult != Z_OK) {
        qWarning() << "[codec] inflateInit failed:" << initResult;
        return QByteArray();
    }

    QByteArray output;
    char chunk[64 * 1024];
    ArraySize inputOffset = 0;
    int status = Z_OK;
    bool valid = true;

    while (status != Z_STREAM_END) {
        if (stream.avail_in == 0 && inputOffset < data.size()) {
            const ArraySize remaining = data.size() - inputOffset;
            // Compute the min in an unsigned wide type. Casting UINT_MAX to
            // Qt5's 32-bit signed int would otherwise produce -1.
            const std::uint64_t inputCount64 = std::min<std::uint64_t>(
                static_cast<std::uint64_t>(remaining),
                static_cast<std::uint64_t>((std::numeric_limits<uInt>::max)()));
            const ArraySize inputCount = static_cast<ArraySize>(inputCount64);
            stream.next_in = reinterpret_cast<Bytef*>(
                const_cast<char*>(data.constData() + inputOffset));
            stream.avail_in = static_cast<uInt>(inputCount);
            inputOffset += inputCount;
        }

        stream.next_out = reinterpret_cast<Bytef*>(chunk);
        stream.avail_out = static_cast<uInt>(sizeof(chunk));
        const uInt inputBefore = stream.avail_in;
        status = ::inflate(&stream, Z_NO_FLUSH);
        const std::size_t produced = sizeof(chunk) - stream.avail_out;

        if (produced > outputCeiling -
                static_cast<std::uint64_t>(output.size())) {
            qWarning() << "[codec] inflated output exceeds configured ceiling";
            valid = false;
            break;
        }
        if (produced)
            output.append(chunk, static_cast<ArraySize>(produced));

        if (status == Z_STREAM_END) {
            if (stream.avail_in != 0 || inputOffset != data.size()) {
                qWarning() << "[codec] trailing bytes after zlib stream";
                valid = false;
            }
            break;
        }
        if (status != Z_OK) {
            qWarning() << "[codec] inflate failed:" << status << stream.msg;
            valid = false;
            break;
        }
        if (inputBefore == stream.avail_in && produced == 0) {
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
    // Compatibility entry point: this translation unit uses zlib level 9.
    // A MASM implementation is selected by a separate platform provider.
    QByteArray output = compressWithLevel(data, Z_BEST_COMPRESSION, success);
    if (success && *success)
        qDebug() << "[codec] maximum compression:" << data.size()
                 << "->" << output.size() << "bytes";
    return output;
}

} // namespace codec
