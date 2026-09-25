#include "Compression.hpp"
#include <zlib.h>
#include <lz4.h>
#include <stdexcept>
#include <map>

namespace rawrxd::codec {

class Compression::Impl {
public:
    std::map<CompressionCodec, CodecCapabilities> caps_;
    Impl() {
        caps_[CompressionCodec::Gzip] = { true, false, 0xFFFFFFFF, 1, 9, 0.25f };
        caps_[CompressionCodec::LZ4] = { true, true, LZ4_MAX_INPUT_SIZE, 1, 1, 0.50f };
        caps_[CompressionCodec::ZSTD] = { true, true, 0xFFFFFFFF, 1, 22, 0.30f };
    }
};

Compression::Compression() : impl_(std::make_unique<Impl>()) {}
Compression::~Compression() = default;

CompressionResult Compression::Compress(std::span<const uint8_t> input,
                                          CompressionCodec codec,
                                          CompressionLevel level) {
    CompressionResult result;
    result.original_size = input.size();
    result.codec = codec;
    switch (codec) {
        case CompressionCodec::Gzip:
            return GzipCompress(input, static_cast<int>(level));
        case CompressionCodec::LZ4:
            return LZ4Compress(input, 1);
        case CompressionCodec::None:
            result.data.assign(input.begin(), input.end());
            result.success = true;
            return result;
        default:
            result.error_message = "Codec not implemented";
            return result;
    }
}

CompressionResult Compression::Decompress(std::span<const uint8_t> input,
                                            CompressionCodec codec,
                                            size_t expected_original_size) {
    CompressionResult result;
    result.original_size = expected_original_size;
    result.codec = codec;
    switch (codec) {
        case CompressionCodec::Gzip:
            return GzipDecompress(input);
        case CompressionCodec::LZ4:
            return LZ4Decompress(input, expected_original_size);
        case CompressionCodec::None:
            result.data.assign(input.begin(), input.end());
            result.success = true;
            return result;
        default:
            result.error_message = "Codec not implemented";
            return result;
    }
}

bool Compression::IsCodecAvailable(CompressionCodec codec) {
    switch (codec) {
        case CompressionCodec::None:
        case CompressionCodec::Gzip:
        case CompressionCodec::LZ4:
            return true;
        default:
            return false;
    }
}

CodecCapabilities Compression::GetCapabilities(CompressionCodec codec) {
    Compression inst;
    auto it = inst.impl_->caps_.find(codec);
    if (it != inst.impl_->caps_.end()) return it->second;
    return {};
}

std::vector<CompressionCodec> Compression::ListAvailableCodecs() {
    return { CompressionCodec::None, CompressionCodec::Gzip, CompressionCodec::LZ4 };
}

const char* Compression::CodecName(CompressionCodec codec) {
    switch (codec) {
        case CompressionCodec::None: return "none";
        case CompressionCodec::Gzip: return "gzip";
        case CompressionCodec::Deflate: return "deflate";
        case CompressionCodec::LZ4: return "lz4";
        case CompressionCodec::ZSTD: return "zstd";
        case CompressionCodec::Brotli: return "brotli";
        case CompressionCodec::BrutalGzip: return "brutal_gzip";
        default: return "unknown";
    }
}

std::optional<CompressionCodec> Compression::CodecFromExtension(const std::string& ext) {
    if (ext == ".gz" || ext == ".gzip") return CompressionCodec::Gzip;
    if (ext == ".lz4") return CompressionCodec::LZ4;
    if (ext == ".zst") return CompressionCodec::ZSTD;
    if (ext == ".br") return CompressionCodec::Brotli;
    return std::nullopt;
}

std::optional<CompressionCodec> Compression::DetectCodec(const std::vector<uint8_t>& header) {
    if (header.size() >= 2 && header[0] == 0x1f && header[1] == 0x8b) return CompressionCodec::Gzip;
    if (header.size() >= 4 && header[0] == 0x04 && header[1] == 0x22 && header[2] == 0x4d && header[3] == 0x18) return CompressionCodec::LZ4;
    if (header.size() >= 4 && header[0] == 0x28 && header[1] == 0xb5 && header[2] == 0x2f && header[3] == 0xfd) return CompressionCodec::ZSTD;
    return std::nullopt;
}

CompressionResult Compression::GzipCompress(std::span<const uint8_t> input, int level) {
    CompressionResult result;
    result.original_size = input.size();
    result.codec = CompressionCodec::Gzip;
    z_stream zs = {};
    if (deflateInit2(&zs, level, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        result.error_message = "gzip init failed";
        return result;
    }
    zs.next_in = const_cast<Bytef*>(input.data());
    zs.avail_in = static_cast<uInt>(input.size());
    size_t out_pos = 0;
    result.data.resize(input.size() + 256);
    do {
        zs.next_out = result.data.data() + out_pos;
        zs.avail_out = static_cast<uInt>(result.data.size() - out_pos);
        int ret = deflate(&zs, Z_FINISH);
        if (ret == Z_STREAM_ERROR) {
            deflateEnd(&zs);
            result.error_message = "gzip stream error";
            result.data.clear();
            return result;
        }
        out_pos = zs.total_out;
        if (zs.avail_out == 0) {
            result.data.resize(result.data.size() * 2);
        }
    } while (zs.avail_out == 0);
    deflateEnd(&zs);
    result.data.resize(out_pos);
    result.success = true;
    return result;
}

CompressionResult Compression::GzipDecompress(std::span<const uint8_t> input) {
    CompressionResult result;
    result.codec = CompressionCodec::Gzip;
    z_stream zs = {};
    if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) {
        result.error_message = "gzip init failed";
        return result;
    }
    zs.next_in = const_cast<Bytef*>(input.data());
    zs.avail_in = static_cast<uInt>(input.size());
    size_t out_pos = 0;
    result.data.resize(input.size() * 4 + 1024);
    do {
        zs.next_out = result.data.data() + out_pos;
        zs.avail_out = static_cast<uInt>(result.data.size() - out_pos);
        int ret = inflate(&zs, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            inflateEnd(&zs);
            result.error_message = "gzip inflate error";
            result.data.clear();
            return result;
        }
        out_pos = zs.total_out;
        if (zs.avail_out == 0) {
            result.data.resize(result.data.size() * 2);
        }
        if (ret == Z_STREAM_END) break;
    } while (true);
    inflateEnd(&zs);
    result.data.resize(out_pos);
    result.success = true;
    return result;
}

CompressionResult Compression::LZ4Compress(std::span<const uint8_t> input, int acceleration) {
    CompressionResult result;
    result.original_size = input.size();
    result.codec = CompressionCodec::LZ4;
    int max_size = LZ4_compressBound(static_cast<int>(input.size()));
    if (max_size <= 0) {
        result.error_message = "lz4 compress bound failed";
        return result;
    }
    result.data.resize(max_size);
    int compressed = LZ4_compress_fast(
        reinterpret_cast<const char*>(input.data()),
        reinterpret_cast<char*>(result.data.data()),
        static_cast<int>(input.size()),
        max_size,
        acceleration);
    if (compressed <= 0) {
        result.error_message = "lz4 compression failed";
        result.data.clear();
        return result;
    }
    result.data.resize(compressed);
    result.success = true;
    return result;
}

CompressionResult Compression::LZ4Decompress(std::span<const uint8_t> input, size_t original_size) {
    CompressionResult result;
    result.original_size = original_size;
    result.codec = CompressionCodec::LZ4;
    result.data.resize(original_size);
    int decompressed = LZ4_decompress_safe(
        reinterpret_cast<const char*>(input.data()),
        reinterpret_cast<char*>(result.data.data()),
        static_cast<int>(input.size()),
        static_cast<int>(original_size));
    if (decompressed < 0) {
        result.error_message = "lz4 decompression failed";
        result.data.clear();
        return result;
    }
    result.data.resize(decompressed);
    result.success = true;
    return result;
}

} // namespace rawrxd::codec
