#pragma once
#include <string>
#include <vector>
#include <span>
#include <optional>
#include <memory>
#include <stdint.h>

namespace rawrxd::codec {

// ───────────────────────────────────────────────────────────────
// Supported compression codecs
// ───────────────────────────────────────────────────────────────
enum class CompressionCodec {
    None,
    Gzip,
    Deflate,
    LZ4,
    ZSTD,
    Brotli,
    BrutalGzip // high-ratio streaming gzip variant
};

// ───────────────────────────────────────────────────────────────
// Compression level (codec-agnostic abstraction)
// ───────────────────────────────────────────────────────────────
enum class CompressionLevel {
    Min = 1,    // fastest
    Default = 6,
    Max = 22    // best ratio (codec permitting)
};

// ───────────────────────────────────────────────────────────────
// Compression result
// ───────────────────────────────────────────────────────────────
struct CompressionResult {
    std::vector<uint8_t> data;
    size_t original_size = 0;
    CompressionCodec codec = CompressionCodec::None;
    bool success = false;
    std::string error_message;
};

// ───────────────────────────────────────────────────────────────
// Codec capabilities
// ───────────────────────────────────────────────────────────────
struct CodecCapabilities {
    bool supports_streaming = false;
    bool supports_dict = false;
    size_t max_block_size = 0;
    uint32_t min_level = 1;
    uint32_t max_level = 9;
    float typical_ratio = 0.0f;
};

// ───────────────────────────────────────────────────────────────
// Compression — codec abstraction layer
// ───────────────────────────────────────────────────────────────
class Compression {
public:
    Compression();
    ~Compression();

    // One-shot compress / decompress
    CompressionResult Compress(std::span<const uint8_t> input,
                                CompressionCodec codec,
                                CompressionLevel level = CompressionLevel::Default);
    CompressionResult Decompress(std::span<const uint8_t> input,
                                   CompressionCodec codec,
                                   size_t expected_original_size = 0);

    // Codec introspection
    static bool IsCodecAvailable(CompressionCodec codec);
    static CodecCapabilities GetCapabilities(CompressionCodec codec);
    static std::vector<CompressionCodec> ListAvailableCodecs();
    static const char* CodecName(CompressionCodec codec);

    // Helpers
    static std::optional<CompressionCodec> CodecFromExtension(const std::string& ext);
    static std::optional<CompressionCodec> DetectCodec(const std::vector<uint8_t>& header);

    // Direct gzip helpers
    CompressionResult GzipCompress(std::span<const uint8_t> input, int level = 6);
    CompressionResult GzipDecompress(std::span<const uint8_t> input);

    // LZ4 helpers
    CompressionResult LZ4Compress(std::span<const uint8_t> input, int acceleration = 1);
    CompressionResult LZ4Decompress(std::span<const uint8_t> input, size_t original_size);

    // Streaming interface (placeholder for future)
    struct StreamContext;
    std::unique_ptr<StreamContext> CreateStreamCompressor(CompressionCodec codec);
    std::unique_ptr<StreamContext> CreateStreamDecompressor(CompressionCodec codec);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::codec
