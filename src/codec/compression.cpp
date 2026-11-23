#include "codec/compression.h"
#include <zlib.h>
#include <QDebug>
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace codec {
namespace {
constexpr std::size_t kInflateChunk = 64u * 1024u;
constexpr std::size_t kMaxInflatedBytes = 512u * 1024u * 1024u;

QByteArray compressData(const QByteArray& data, int level, bool* success) {
    if (success) *success = false;
    if (data.isEmpty()) {
        if (success) *success = true;
        return {};
    }
    const auto sourceLength = static_cast<std::size_t>(data.size());
    if (sourceLength > (std::numeric_limits<uLong>::max)()) return {};
    const uLong bound = compressBound(static_cast<uLong>(sourceLength));
    if (bound > static_cast<uLong>((std::numeric_limits<qsizetype>::max)())) return {};
    QByteArray output(static_cast<qsizetype>(bound), Qt::Uninitialized);
    uLongf length = bound;
    const int rc = compress2(reinterpret_cast<Bytef*>(output.data()), &length,
        reinterpret_cast<const Bytef*>(data.constData()),
        static_cast<uLong>(sourceLength), level);
    if (rc != Z_OK) {
        qWarning() << "zlib compression failed:" << rc;
        return {};
    }
    output.resize(static_cast<qsizetype>(length));
    if (success) *success = true;
    return output;
}
} // namespace

QByteArray deflate(const QByteArray& data, bool* success) {
    return compressData(data, Z_DEFAULT_COMPRESSION, success);
}

QByteArray deflate_brutal_masm(const QByteArray& data, bool* success) {
    // Compatibility Qt/zlib implementation. This is NOT the native ml64 backend.
    return compressData(data, Z_BEST_COMPRESSION, success);
}

QByteArray inflate(const QByteArray& data, bool* success) {
    if (success) *success = false;
    if (data.isEmpty()) {
        if (success) *success = true;
        return {};
    }
    z_stream stream{};
    const int init = inflateInit(&stream);
    if (init != Z_OK) return {};

    QByteArray output;
    std::array<unsigned char, kInflateChunk> chunk{};
    std::size_t inputOffset = 0;
    int rc = Z_OK;
    bool complete = false;
    do {
        if (stream.avail_in == 0 && inputOffset < static_cast<std::size_t>(data.size())) {
            const auto remaining = static_cast<std::size_t>(data.size()) - inputOffset;
            const auto take = std::min(remaining,
                static_cast<std::size_t>((std::numeric_limits<uInt>::max)()));
            stream.next_in = reinterpret_cast<Bytef*>(
                const_cast<char*>(data.constData() + inputOffset));
            stream.avail_in = static_cast<uInt>(take);
            inputOffset += take;
        }
        stream.next_out = chunk.data();
        stream.avail_out = static_cast<uInt>(chunk.size());
        const uInt inputBefore = stream.avail_in;
        rc = ::inflate(&stream, Z_NO_FLUSH);
        const std::size_t produced = chunk.size() - stream.avail_out;
        if (produced > kMaxInflatedBytes - static_cast<std::size_t>(output.size())) break;
        if (produced) output.append(reinterpret_cast<const char*>(chunk.data()),
                                    static_cast<qsizetype>(produced));
        if (rc == Z_STREAM_END) {
            // Reject trailing bytes: callers expect exactly one zlib stream.
            complete = (stream.avail_in == 0 &&
                        inputOffset == static_cast<std::size_t>(data.size()));
            break;
        }
        if (rc != Z_OK) break;
        if (produced == 0 && inputBefore == stream.avail_in &&
            inputOffset == static_cast<std::size_t>(data.size())) break;
    } while (true);
    inflateEnd(&stream);
    if (!complete) {
        qWarning() << "zlib inflate failed, truncated, oversized or trailing input:" << rc;
        return {};
    }
    if (success) *success = true;
    return output;
}
} // namespace codec
