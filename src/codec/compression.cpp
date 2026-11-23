#include "codec/compression.h"
#include <zlib.h>
#include <QDebug>
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>

namespace codec {
namespace {
constexpr std::size_t kChunk = 64 * 1024;
// Hard safety ceiling for legacy callers without an explicit output budget.
constexpr std::uint64_t kMaxInflatedBytes = 1024ULL * 1024 * 1024;

QByteArray compressStream(const QByteArray& input, int level, bool* success) {
    if (success) *success = false;
    if (input.isEmpty()) {
        if (success) *success = true;
        return {};
    }
    z_stream stream{};
    if (deflateInit(&stream, level) != Z_OK) return {};
    QByteArray output;
    std::array<unsigned char, kChunk> buffer{};
    std::size_t offset = 0;
    int status = Z_OK;
    do {
        const std::size_t remaining = static_cast<std::size_t>(input.size()) - offset;
        const auto count = static_cast<uInt>(std::min(remaining, kChunk));
        stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.constData() + offset));
        stream.avail_in = count;
        offset += count;
        const int flush = offset == static_cast<std::size_t>(input.size()) ? Z_FINISH : Z_NO_FLUSH;
        do {
            stream.next_out = buffer.data();
            stream.avail_out = static_cast<uInt>(buffer.size());
            status = ::deflate(&stream, flush);
            if (status != Z_OK && status != Z_STREAM_END) {
                deflateEnd(&stream);
                return {};
            }
            const auto produced = buffer.size() - stream.avail_out;
            if (produced > static_cast<std::size_t>(std::numeric_limits<int>::max() - output.size())) {
                deflateEnd(&stream);
                return {};
            }
            output.append(reinterpret_cast<const char*>(buffer.data()), static_cast<int>(produced));
        } while (stream.avail_out == 0 || (flush == Z_FINISH && status != Z_STREAM_END));
    } while (status != Z_STREAM_END);
    deflateEnd(&stream);
    if (success) *success = true;
    return output;
}
} // namespace

QByteArray deflate(const QByteArray& data, bool* success) {
    return compressStream(data, Z_DEFAULT_COMPRESSION, success);
}

QByteArray inflate(const QByteArray& data, bool* success) {
    if (success) *success = false;
    if (data.isEmpty()) {
        if (success) *success = true;
        return {};
    }
    z_stream stream{};
    if (inflateInit(&stream) != Z_OK) return {};
    QByteArray output;
    std::array<unsigned char, kChunk> buffer{};
    std::size_t offset = 0;
    int status = Z_OK;
    do {
        if (stream.avail_in == 0 && offset < static_cast<std::size_t>(data.size())) {
            const auto count = static_cast<uInt>(std::min(kChunk, static_cast<std::size_t>(data.size()) - offset));
            stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.constData() + offset));
            stream.avail_in = count;
            offset += count;
        }
        stream.next_out = buffer.data();
        stream.avail_out = static_cast<uInt>(buffer.size());
        status = ::inflate(&stream, Z_NO_FLUSH);
        const auto produced = buffer.size() - stream.avail_out;
        if (status != Z_OK && status != Z_STREAM_END) {
            inflateEnd(&stream);
            return {};
        }
        if (produced > kMaxInflatedBytes - static_cast<std::uint64_t>(output.size()) ||
            produced > static_cast<std::size_t>(std::numeric_limits<int>::max() - output.size())) {
            inflateEnd(&stream);
            return {};
        }
        output.append(reinterpret_cast<const char*>(buffer.data()), static_cast<int>(produced));
        if (status == Z_OK && produced == 0 && stream.avail_in == 0 &&
            offset == static_cast<std::size_t>(data.size())) {
            inflateEnd(&stream);
            return {}; // truncated stream
        }
    } while (status != Z_STREAM_END);
    const bool consumedAll = offset == static_cast<std::size_t>(data.size()) && stream.avail_in == 0;
    inflateEnd(&stream);
    if (!consumedAll) return {}; // reject trailing data / concatenated streams
    if (success) *success = true;
    return output;
}

QByteArray deflate_brutal_masm(const QByteArray& data, bool* success) {
    // Historical API name: implementation is portable zlib level 9, not MASM.
    return compressStream(data, Z_BEST_COMPRESSION, success);
}
} // namespace codec
