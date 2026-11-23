#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
namespace RawrXD { namespace Compression {
// GGML Q4_0 = FP16 scale + 16 packed bytes; Q8_0 = FP16 scale + 32 int8.
enum class GGUFBlockFormat : uint8_t { Q4_0, Q8_0 };
struct GGUFDecoderContext { GGUFBlockFormat format; };
inline float binary16ToFloat(uint16_t h) {
    const uint32_t sign = uint32_t(h & 0x8000u) << 16;
    const uint32_t exp = (h >> 10) & 31u, mant = h & 1023u;
    uint32_t bits;
    if (exp == 31) bits = sign | 0x7f800000u | (mant << 13);
    else if (exp) bits = sign | ((exp + 112u) << 23) | (mant << 13);
    else if (!mant) bits = sign;
    else {
        uint32_t m = mant, e = 113;
        while ((m & 1024u) == 0) { m <<= 1; --e; }
        bits = sign | (e << 23) | ((m & 1023u) << 13);
    }
    float f; std::memcpy(&f, &bits, sizeof f); return f;
}
inline bool decodeGGUFBlockSlice(const uint8_t* encoded, size_t encodedBytes,
                                  size_t decodedBytes, size_t offset, size_t length,
                                  uint8_t* output, void* context) {
    if (!encoded || !output || !context || offset % 4 || length % 4 ||
        decodedBytes % 128 || offset > decodedBytes ||
        length > decodedBytes - offset) return false;
    const auto format = static_cast<const GGUFDecoderContext*>(context)->format;
    if (format != GGUFBlockFormat::Q4_0 && format != GGUFBlockFormat::Q8_0) return false;
    const size_t blockBytes = format == GGUFBlockFormat::Q4_0 ? 18 : 34;
    const size_t blockCount = decodedBytes / 128;
    if (blockCount > encodedBytes / blockBytes || encodedBytes % blockBytes ||
        encodedBytes / blockBytes != blockCount) return false;
    const size_t first = offset / 4, count = length / 4;
    for (size_t i = 0; i < count; ++i) {
        const size_t element = first + i, block = element / 32, lane = element % 32;
        const uint8_t* p = encoded + block * blockBytes;
        const uint16_t half = uint16_t(p[0]) | (uint16_t(p[1]) << 8);
        const float scale = binary16ToFloat(half);
        float result;
        if (format == GGUFBlockFormat::Q8_0)
            result = scale * static_cast<float>(static_cast<int8_t>(p[2 + lane]));
        else {
            const uint8_t packed = p[2 + (lane % 16)];
            const int q = int(lane < 16 ? packed & 15u : packed >> 4) - 8;
            result = scale * static_cast<float>(q);
        }
        std::memcpy(output + i * 4, &result, 4);
    }
    return true;
}
}} // namespace RawrXD::Compression
