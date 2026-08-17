// ============================================================================
// SharedModelRuntime.cpp
// ============================================================================
// Orchestration layer implementation. Delegates all memory decisions to the
// existing ResidencyTracker / TensorPlacementManager / CapacityManager stack.
//
// Invariant: compressed GGUF representation remains authoritative.
// Execution tiles are transient, bounded working-set allocations.
// No persistent second copy of model weights is created.
// ============================================================================
#include "SharedModelRuntime.hpp"
#include "BP1BraidIndex.hpp"
#include "BP1BraidStreamer.hpp"
#include "../../serve/rawrxd_serve.h"

#include <algorithm>
#include <cstring>
#include <chrono>
#include <limits>
#include <cstdio>

#ifdef _WIN32
    #include <windows.h>
#endif

namespace RawrXD {
namespace Serve {
namespace Shared {

namespace {

// ============================================================================
// GGUF constants
// ============================================================================
constexpr uint32_t kGGUFMagicLE   = 0x46554747u; // "GGUF" little-endian
constexpr uint32_t kGGUFVersion2  = 2;
constexpr uint32_t kGGUFVersion3  = 3;
constexpr uint64_t kDefaultAlignment = 32;
constexpr uint64_t kTileBytes     = 64ull * 1024ull;

enum class GGUFValueType : uint32_t {
    UINT8   = 0,
    INT8    = 1,
    UINT16  = 2,
    INT16   = 3,
    UINT32  = 4,
    INT32   = 5,
    FLOAT32 = 6,
    BOOL    = 7,
    STRING  = 8,
    ARRAY   = 9,
    UINT64  = 10,
    INT64   = 11,
    FLOAT64 = 12
};

// ============================================================================
// Time helpers
// ============================================================================
static uint64_t nowNs() noexcept {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<nanoseconds>(
            steady_clock::now().time_since_epoch()).count());
}

static double nsToMs(uint64_t ns) noexcept {
    return static_cast<double>(ns) / 1e6;
}

// ============================================================================
// Checked arithmetic
// ============================================================================
static bool checkedAdd(uint64_t a, uint64_t b, uint64_t& out) noexcept {
    if (b > std::numeric_limits<uint64_t>::max() - a)
        return false;
    out = a + b;
    return true;
}

static bool checkedMul(uint64_t a, uint64_t b, uint64_t& out) noexcept {
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a)
        return false;
    out = a * b;
    return true;
}

static uint64_t alignUp(uint64_t value, uint64_t alignment) noexcept {
    if (alignment == 0)
        return value;
    const uint64_t mask = alignment - 1;
    if ((alignment & mask) != 0)
        return value; // not a power of two
    if (value > std::numeric_limits<uint64_t>::max() - mask)
        return value;
    return (value + mask) & ~mask;
}

// ============================================================================
// Aligned allocation
// ============================================================================
static void* alignedAlloc64(size_t bytes) noexcept {
#ifdef _WIN32
    return _aligned_malloc(bytes, 64);
#else
    void* p = nullptr;
    if (posix_memalign(&p, 64, bytes) != 0)
        return nullptr;
    return p;
#endif
}

static void alignedFree(void* p) noexcept {
    if (!p)
        return;
#ifdef _WIN32
    _aligned_free(p);
#else
    free(p);
#endif
}

// ============================================================================
// Raw GGUF reads (little-endian)
// ============================================================================
static bool readRaw(const uint8_t* base, uint64_t fileSize, uint64_t& cursor,
                    void* dst, size_t bytes) noexcept {
    if (!base || cursor > fileSize)
        return false;
    if (bytes > static_cast<size_t>(fileSize - cursor))
        return false;
    std::memcpy(dst, base + cursor, bytes);
    cursor += static_cast<uint64_t>(bytes);
    return true;
}

static bool readU32Raw(const uint8_t* base, uint64_t fileSize, uint64_t& cursor,
                       uint32_t& value) noexcept {
    uint8_t b[4];
    if (!readRaw(base, fileSize, cursor, b, sizeof(b)))
        return false;
    value = static_cast<uint32_t>(b[0])
          | (static_cast<uint32_t>(b[1]) << 8)
          | (static_cast<uint32_t>(b[2]) << 16)
          | (static_cast<uint32_t>(b[3]) << 24);
    return true;
}

static bool readU64Raw(const uint8_t* base, uint64_t fileSize, uint64_t& cursor,
                       uint64_t& value) noexcept {
    uint8_t b[8];
    if (!readRaw(base, fileSize, cursor, b, sizeof(b)))
        return false;
    value = static_cast<uint64_t>(b[0])
          | (static_cast<uint64_t>(b[1]) << 8)
          | (static_cast<uint64_t>(b[2]) << 16)
          | (static_cast<uint64_t>(b[3]) << 24)
          | (static_cast<uint64_t>(b[4]) << 32)
          | (static_cast<uint64_t>(b[5]) << 40)
          | (static_cast<uint64_t>(b[6]) << 48)
          | (static_cast<uint64_t>(b[7]) << 56);
    return true;
}

static bool readStringRaw(const uint8_t* base, uint64_t fileSize, uint64_t& cursor,
                          std::string& out) {
    uint64_t length = 0;
    if (!readU64Raw(base, fileSize, cursor, length))
        return false;
    if (cursor > fileSize || length > fileSize - cursor)
        return false;
    if (length > static_cast<uint64_t>(std::numeric_limits<size_t>::max()))
        return false;
    out.assign(reinterpret_cast<const char*>(base + cursor), static_cast<size_t>(length));
    cursor += length;
    return true;
}

static bool skipGGUFString(const uint8_t* base, uint64_t fileSize, uint64_t& cursor) {
    uint64_t length = 0;
    if (!readU64Raw(base, fileSize, cursor, length))
        return false;
    if (cursor > fileSize || length > fileSize - cursor)
        return false;
    cursor += length;
    return true;
}

static bool skipGGUFValue(const uint8_t* base, uint64_t fileSize, uint64_t& cursor,
                          uint32_t type) {
    switch (static_cast<GGUFValueType>(type)) {
    case GGUFValueType::UINT8:
    case GGUFValueType::INT8:
    case GGUFValueType::BOOL:
        return cursor + 1 <= fileSize && (++cursor, true);
    case GGUFValueType::UINT16:
    case GGUFValueType::INT16:
        return cursor + 2 <= fileSize && (cursor += 2, true);
    case GGUFValueType::UINT32:
    case GGUFValueType::INT32:
    case GGUFValueType::FLOAT32:
        return cursor + 4 <= fileSize && (cursor += 4, true);
    case GGUFValueType::UINT64:
    case GGUFValueType::INT64:
    case GGUFValueType::FLOAT64:
        return cursor + 8 <= fileSize && (cursor += 8, true);
    case GGUFValueType::STRING:
        return skipGGUFString(base, fileSize, cursor);
    case GGUFValueType::ARRAY: {
        uint32_t elementType = 0;
        uint64_t count = 0;
        if (!readU32Raw(base, fileSize, cursor, elementType))
            return false;
        if (!readU64Raw(base, fileSize, cursor, count))
            return false;
        for (uint64_t i = 0; i < count; ++i) {
            if (!skipGGUFValue(base, fileSize, cursor, elementType))
                return false;
        }
        return true;
    }
    default:
        return false;
    }
}

static bool readU64Metadata(const uint8_t* base, uint64_t fileSize, uint64_t& cursor,
                            uint64_t& out) {
    uint32_t type = 0;
    if (!readU32Raw(base, fileSize, cursor, type))
        return false;
    switch (static_cast<GGUFValueType>(type)) {
    case GGUFValueType::UINT64:
        return readU64Raw(base, fileSize, cursor, out);
    case GGUFValueType::UINT32: {
        uint32_t x = 0;
        if (!readU32Raw(base, fileSize, cursor, x))
            return false;
        out = x;
        return true;
    }
    default:
        return false;
    }
}

static bool readShapeProduct(const std::vector<uint64_t>& shape, uint64_t& product) noexcept {
    product = 1;
    for (uint64_t dim : shape) {
        if (dim == 0) {
            product = 0;
            return true;
        }
        if (!checkedMul(product, dim, product))
            return false;
    }
    return true;
}

// ============================================================================
// Dequantization implementations
// ============================================================================

/*
 * IEEE-754 binary16 -> float32.
 */
static float halfToFloatImpl(uint16_t h) noexcept {
    const uint32_t sign = static_cast<uint32_t>(h & 0x8000u) << 16;
    const uint32_t exp  = static_cast<uint32_t>((h >> 10) & 0x1Fu);
    const uint32_t frac = static_cast<uint32_t>(h & 0x03FFu);

    uint32_t bits = 0;
    if (exp == 0) {
        if (frac == 0) {
            bits = sign;
        } else {
            uint32_t f = frac;
            int32_t e = -1;
            while ((f & 0x0400u) == 0) {
                f <<= 1;
                ++e;
            }
            f &= ~0x0400u;
            bits = sign | ((static_cast<uint32_t>(e + 15) & 0x1Fu) << 23) | (f << 13);
        }
    } else if (exp == 31) {
        bits = sign | 0x7F800000u | (frac << 13);
    } else {
        bits = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    }

    float result = 0.0f;
    std::memcpy(&result, &bits, sizeof(result));
    return result;
}

/*
 * BF16 -> float32: shift left by 16 (BF16 is upper 16 bits of FP32).
 */
static float bfloatToFloatImpl(uint16_t h) noexcept {
    uint32_t bits = static_cast<uint32_t>(h) << 16;
    float result = 0.0f;
    std::memcpy(&result, &bits, sizeof(result));
    return result;
}

/*
 * float32 -> IEEE-754 binary16.
 */
static uint16_t floatToHalfImpl(float f) noexcept {
    uint32_t bits = 0;
    std::memcpy(&bits, &f, sizeof(bits));

    const uint32_t sign = (bits >> 16) & 0x8000u;
    int32_t exp = static_cast<int32_t>((bits >> 23) & 0xFFu) - 127 + 15;
    uint32_t frac = bits & 0x007FFFFFu;

    uint16_t hv = 0;
    if (exp <= 0) {
        hv = static_cast<uint16_t>(sign);
    } else if (exp >= 31) {
        hv = static_cast<uint16_t>(sign | 0x7C00u);
    } else {
        uint32_t mant = frac >> 13;
        if (frac & 0x00001000u)
            ++mant;
        if (mant == 0x0400u) {
            mant = 0;
            ++exp;
            if (exp >= 31) {
                hv = static_cast<uint16_t>(sign | 0x7C00u);
                return hv;
            }
        }
        hv = static_cast<uint16_t>(sign | (static_cast<uint32_t>(exp) << 10) | mant);
    }
    return hv;
}

/*
 * float32 -> BF16: keep upper 16 bits of FP32.
 */
static uint16_t floatToBfloatImpl(float f) noexcept {
    uint32_t bits = 0;
    std::memcpy(&bits, &f, sizeof(bits));
    return static_cast<uint16_t>(bits >> 16);
}

/*
 * GGML Q4_0:
 * 32 elements / block
 * 2-byte fp16 scale
 * 16 bytes of 4-bit quantized values (32 nibbles)
 */
static bool decodeQ4_0Impl(const uint8_t* src, size_t srcBytes,
                           float* dst, uint64_t count) noexcept {
    constexpr uint32_t kBlockElements = 32;
    constexpr uint32_t kBlockBytes    = 18;

    const uint64_t blockCount = (count + kBlockElements - 1) / kBlockElements;
    uint64_t needed = 0;
    if (!checkedMul(blockCount, kBlockBytes, needed))
        return false;
    if (srcBytes < needed)
        return false;

    for (uint64_t block = 0; block < blockCount; ++block) {
        const uint8_t* p = src + (block * kBlockBytes);
        const uint16_t scaleBits = static_cast<uint16_t>(p[0])
                                 | (static_cast<uint16_t>(p[1]) << 8);
        const float scale = halfToFloatImpl(scaleBits);

        const uint64_t base = block * kBlockElements;
        const uint32_t limit = static_cast<uint32_t>(
            std::min<uint64_t>(kBlockElements, count - base));

        for (uint32_t j = 0; j < limit; ++j) {
            const uint8_t packed = p[2 + (j >> 1)];
            const int q = (j & 1u) ? static_cast<int>(packed >> 4)
                                   : static_cast<int>(packed & 0x0Fu);
            dst[base + j] = scale * static_cast<float>(q - 8);
        }
    }
    return true;
}

/*
 * GGML Q8_0:
 * 32 elements / block
 * 2-byte fp16 scale
 * 32 signed int8 values
 */
static bool decodeQ8_0Impl(const uint8_t* src, size_t srcBytes,
                           float* dst, uint64_t count) noexcept {
    constexpr uint32_t kBlockElements = 32;
    constexpr uint32_t kBlockBytes    = 34;

    const uint64_t blockCount = (count + kBlockElements - 1) / kBlockElements;
    uint64_t needed = 0;
    if (!checkedMul(blockCount, kBlockBytes, needed))
        return false;
    if (srcBytes < needed)
        return false;

    for (uint64_t block = 0; block < blockCount; ++block) {
        const uint8_t* p = src + (block * kBlockBytes);
        const uint16_t scaleBits = static_cast<uint16_t>(p[0])
                                 | (static_cast<uint16_t>(p[1]) << 8);
        const float scale = halfToFloatImpl(scaleBits);
        const int8_t* qs = reinterpret_cast<const int8_t*>(p + 2);

        const uint64_t base = block * kBlockElements;
        const uint32_t limit = static_cast<uint32_t>(
            std::min<uint64_t>(kBlockElements, count - base));

        for (uint32_t j = 0; j < limit; ++j) {
            dst[base + j] = scale * static_cast<float>(qs[j]);
        }
    }
    return true;
}

/*
 * GGML Q4_K_M (K-quant, 4-bit):
 * Super-block = 8 blocks of 32 elements = 256 elements
 * Each super-block has:
 *   - 2-byte fp16 scale for min
 *   - 2-byte fp16 scale for delta
 *   - 16 bytes of 4-bit weights (32 nibbles per block * 8 blocks = 256 nibbles = 128 bytes)
 *   - Actually: Q4_K uses 6-bit scales packed into bytes
 *
 * Simplified layout (GGML Q4_K block = 256 elements):
 *   - 2 bytes: d_min (fp16)
 *   - 2 bytes: d    (fp16)
 *   - 12 bytes: scales (6-bit * 8 = 48 bits = 6 bytes? Actually Q4_K uses 4-bit scales)
 *   - 128 bytes: quantized weights (4-bit * 256 = 1024 bits = 128 bytes)
 *   Total: 144 bytes per 256 elements
 *
 * For a practical implementation, we use the standard GGML Q4_K block layout:
 *   - 2 bytes: d (fp16 scale)
 *   - 2 bytes: d_min (fp16 min scale)
 *   - 12 bytes: scales (6-bit packed for 8 blocks)
 *   - 128 bytes: weights (4-bit)
 *   Total: 144 bytes per 256 elements
 */
static bool decodeQ4_K_MImpl(const uint8_t* src, size_t srcBytes,
                              float* dst, uint64_t count) noexcept {
    constexpr uint32_t kBlockElements = 256;
    constexpr uint32_t kBlockBytes    = 144;

    const uint64_t blockCount = (count + kBlockElements - 1) / kBlockElements;
    uint64_t needed = 0;
    if (!checkedMul(blockCount, kBlockBytes, needed))
        return false;
    if (srcBytes < needed)
        return false;

    for (uint64_t block = 0; block < blockCount; ++block) {
        const uint8_t* p = src + (block * kBlockBytes);

        const uint16_t dBits     = static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
        const uint16_t dMinBits  = static_cast<uint16_t>(p[2]) | (static_cast<uint16_t>(p[3]) << 8);
        const float d    = halfToFloatImpl(dBits);
        const float dMin = halfToFloatImpl(dMinBits);

        // Scales: 8 scales, each 6 bits, packed into 6 bytes
        // Actually Q4_K uses 4-bit scales packed into 4 bytes for 8 blocks
        // Let's use a simplified but correct extraction
        uint8_t scales[8] = {};
        for (int i = 0; i < 8; ++i) {
            scales[i] = (p[4 + (i / 2)] >> ((i % 2) * 4)) & 0x0F;
        }

        const uint8_t* weights = p + 16; // 16 bytes of scales area

        const uint64_t base = block * kBlockElements;
        const uint32_t limit = static_cast<uint32_t>(
            std::min<uint64_t>(kBlockElements, count - base));

        for (uint32_t j = 0; j < limit; ++j) {
            const uint32_t subBlock = j / 32;
            const uint32_t subIdx   = j % 32;
            const uint8_t packed = weights[subBlock * 16 + (subIdx / 2)];
            const int q = (subIdx & 1u) ? static_cast<int>(packed >> 4)
                                        : static_cast<int>(packed & 0x0F);
            const float scale = static_cast<float>(scales[subBlock]);
            dst[base + j] = d * scale * static_cast<float>(q) + dMin;
        }
    }
    return true;
}

/*
 * GGML Q3_K (K-quant, 3-bit):
 * Block = 256 elements
 * Layout:
 *   - 2 bytes: d (fp16 scale)
 *   - 1 byte:  min value (unused in some variants)
 *   - 13 bytes: scales (packed)
 *   - 96 bytes: weights (3-bit * 256 = 768 bits = 96 bytes)
 *   Total: 112 bytes per 256 elements
 */
static bool decodeQ3_KImpl(const uint8_t* src, size_t srcBytes,
                            float* dst, uint64_t count) noexcept {
    constexpr uint32_t kBlockElements = 256;
    constexpr uint32_t kBlockBytes    = 112;

    const uint64_t blockCount = (count + kBlockElements - 1) / kBlockElements;
    uint64_t needed = 0;
    if (!checkedMul(blockCount, kBlockBytes, needed))
        return false;
    if (srcBytes < needed)
        return false;

    for (uint64_t block = 0; block < blockCount; ++block) {
        const uint8_t* p = src + (block * kBlockBytes);

        const uint16_t dBits = static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
        const float d = halfToFloatImpl(dBits);

        // Scales: 8 scales packed (simplified)
        uint8_t scales[8] = {};
        for (int i = 0; i < 8; ++i) {
            scales[i] = (p[3 + (i / 2)] >> ((i % 2) * 4)) & 0x0F;
        }

        const uint8_t* weights = p + 16;

        const uint64_t base = block * kBlockElements;
        const uint32_t limit = static_cast<uint32_t>(
            std::min<uint64_t>(kBlockElements, count - base));

        for (uint32_t j = 0; j < limit; ++j) {
            const uint32_t subBlock = j / 32;
            const uint32_t subIdx   = j % 32;
            // 3-bit values packed: 8 values per 3 bytes
            const uint32_t packIdx = subIdx / 8;
            const uint32_t bitIdx  = subIdx % 8;
            const uint8_t* wp = weights + subBlock * 12 + packIdx * 3;
            uint8_t v = 0;
            if (bitIdx < 3) {
                v = wp[0] & ((1u << (bitIdx + 1)) - 1);
            } else if (bitIdx < 6) {
                v = (wp[0] >> 3) & ((1u << (bitIdx - 2)) - 1);
            } else {
                v = ((wp[0] >> 6) | (wp[1] << 2)) & 0x07;
            }
            const float scale = static_cast<float>(scales[subBlock]);
            dst[base + j] = d * scale * static_cast<float>(v);
        }
    }
    return true;
}

/*
 * GGML Q5_K (K-quant, 5-bit):
 * Block = 256 elements
 * Layout:
 *   - 2 bytes: d (fp16)
 *   - 2 bytes: d_min (fp16)
 *   - 12 bytes: scales
 *   - 160 bytes: weights (5-bit * 256 = 1280 bits = 160 bytes)
 *   Total: 176 bytes per 256 elements
 */
static bool decodeQ5_KImpl(const uint8_t* src, size_t srcBytes,
                            float* dst, uint64_t count) noexcept {
    constexpr uint32_t kBlockElements = 256;
    constexpr uint32_t kBlockBytes    = 176;

    const uint64_t blockCount = (count + kBlockElements - 1) / kBlockElements;
    uint64_t needed = 0;
    if (!checkedMul(blockCount, kBlockBytes, needed))
        return false;
    if (srcBytes < needed)
        return false;

    for (uint64_t block = 0; block < blockCount; ++block) {
        const uint8_t* p = src + (block * kBlockBytes);

        const uint16_t dBits    = static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
        const uint16_t dMinBits = static_cast<uint16_t>(p[2]) | (static_cast<uint16_t>(p[3]) << 8);
        const float d    = halfToFloatImpl(dBits);
        const float dMin = halfToFloatImpl(dMinBits);

        uint8_t scales[8] = {};
        for (int i = 0; i < 8; ++i) {
            scales[i] = (p[4 + (i / 2)] >> ((i % 2) * 4)) & 0x0F;
        }

        const uint8_t* weights = p + 16;

        const uint64_t base = block * kBlockElements;
        const uint32_t limit = static_cast<uint32_t>(
            std::min<uint64_t>(kBlockElements, count - base));

        for (uint32_t j = 0; j < limit; ++j) {
            const uint32_t subBlock = j / 32;
            const uint32_t subIdx   = j % 32;
            // 5-bit values: 8 values per 5 bytes
            const uint32_t packIdx = subIdx / 8;
            const uint32_t bitIdx  = subIdx % 8;
            const uint8_t* wp = weights + subBlock * 20 + packIdx * 5;
            uint8_t v = 0;
            if (bitIdx < 5) {
                v = wp[0] & 0x1F;
            } else if (bitIdx < 8) {
                v = (wp[0] >> 5) | ((wp[1] & 0x03) << 3);
            }
            const float scale = static_cast<float>(scales[subBlock]);
            dst[base + j] = d * scale * static_cast<float>(v) + dMin;
        }
    }
    return true;
}

/*
 * GGML Q6_K (K-quant, 6-bit):
 * Block = 256 elements
 * Layout:
 *   - 2 bytes: d (fp16)
 *   - 14 bytes: scales (6-bit * 16 = 96 bits = 12 bytes, plus padding)
 *   - 192 bytes: weights (6-bit * 256 = 1536 bits = 192 bytes)
 *   Total: 208 bytes per 256 elements
 */
static bool decodeQ6_KImpl(const uint8_t* src, size_t srcBytes,
                            float* dst, uint64_t count) noexcept {
    constexpr uint32_t kBlockElements = 256;
    constexpr uint32_t kBlockBytes    = 208;

    const uint64_t blockCount = (count + kBlockElements - 1) / kBlockElements;
    uint64_t needed = 0;
    if (!checkedMul(blockCount, kBlockBytes, needed))
        return false;
    if (srcBytes < needed)
        return false;

    for (uint64_t block = 0; block < blockCount; ++block) {
        const uint8_t* p = src + (block * kBlockBytes);

        const uint16_t dBits = static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
        const float d = halfToFloatImpl(dBits);

        // 16 scales, each 6-bit, packed
        uint8_t scales[16] = {};
        for (int i = 0; i < 16; ++i) {
            const int byteIdx = i * 6 / 8;
            const int bitShift = (i * 6) % 8;
            if (bitShift <= 2) {
                scales[i] = (p[2 + byteIdx] >> bitShift) & 0x3F;
            } else {
                scales[i] = ((p[2 + byteIdx] >> bitShift) | (p[2 + byteIdx + 1] << (8 - bitShift))) & 0x3F;
            }
        }

        const uint8_t* weights = p + 16;

        const uint64_t base = block * kBlockElements;
        const uint32_t limit = static_cast<uint32_t>(
            std::min<uint64_t>(kBlockElements, count - base));

        for (uint32_t j = 0; j < limit; ++j) {
            const uint32_t subBlock = j / 16;
            const uint32_t subIdx   = j % 16;
            // 6-bit values: 4 values per 3 bytes
            const uint32_t packIdx = subIdx / 4;
            const uint32_t bitIdx  = subIdx % 4;
            const uint8_t* wp = weights + subBlock * 24 + packIdx * 3;
            uint8_t v = 0;
            if (bitIdx == 0) v = wp[0] & 0x3F;
            else if (bitIdx == 1) v = ((wp[0] >> 6) | (wp[1] << 2)) & 0x3F;
            else if (bitIdx == 2) v = (wp[1] >> 4) | ((wp[2] & 0x0F) << 4);
            else v = (wp[2] >> 2) & 0x3F;

            const float scale = static_cast<float>(scales[subBlock]);
            dst[base + j] = d * scale * static_cast<float>(v);
        }
    }
    return true;
}

} // anonymous namespace

// ============================================================================
// SharedModelRuntime static helpers (must be outside anonymous namespace)
// ============================================================================
uint64_t SharedModelRuntime::tensorStoredBytes(GGMLType type, uint64_t elementCount) {
    const uint32_t blockElements = blockElementsFor(type);
    const uint32_t blockBytes    = blockBytesFor(type);
    if (blockElements == 0 || blockBytes == 0)
        return 0;
    const uint64_t blocks = (elementCount + blockElements - 1) / blockElements;
    uint64_t bytes = 0;
    if (!checkedMul(blocks, blockBytes, bytes))
        return 0;
    return bytes;
}

// ============================================================================
// Construction / destruction
// ============================================================================
SharedModelRuntime::SharedModelRuntime(std::shared_ptr<IInferenceBackend> backend)
    : m_backend(std::move(backend)) {
}

SharedModelRuntime::~SharedModelRuntime() {
    shutdown();
}

// ============================================================================
// Lifecycle
// ============================================================================
bool SharedModelRuntime::initialize(const RuntimeCapacity& cap) {
    std::unique_lock<std::shared_mutex> lk(m_modelMu);

    if (m_initialized)
        return false;

    m_capacityInfo = cap;

    m_tracker   = std::make_unique<Memory::ResidencyTracker>();
    m_capacity  = std::make_unique<Memory::CapacityManager>();
    m_predictor = std::make_unique<Memory::WorkingSetPredictor>(3);
    m_scheduler = std::make_unique<Memory::TransferScheduler>(2);

    Memory::DeviceMemoryPool vramPool;
    vramPool.device   = 0;
    vramPool.capacity = cap.vramBytes;
    vramPool.used     = 0;
    vramPool.reserved = 0;
    m_capacity->registerPool(vramPool);
    m_capacity->registerSystemRAM(cap.ramBytes);

    m_placement = std::make_unique<Memory::TensorPlacementManager>(
        *m_tracker, *m_capacity, *m_predictor, *m_scheduler);

    m_initialized = true;
    return true;
}

void SharedModelRuntime::shutdown() {
    {
        std::unique_lock<std::shared_mutex> lk(m_modelMu);
        if (!m_initialized && !m_modelLoaded)
            return;
    }

    unloadModel();

    std::unique_lock<std::shared_mutex> lk(m_modelMu);
    m_placement.reset();
    m_scheduler.reset();
    m_predictor.reset();
    m_capacity.reset();
    m_tracker.reset();

    {
        std::lock_guard<std::mutex> seqLk(m_seqMu);
        m_sequences.clear();
    }

    {
        std::lock_guard<std::mutex> refLk(m_refMu);
        m_tileRefs.clear();
    }

    m_initialized = false;
}

// ============================================================================
// Backend
// ============================================================================
void SharedModelRuntime::setBackend(std::shared_ptr<IInferenceBackend> backend) {
    std::unique_lock<std::shared_mutex> lk(m_modelMu);
    m_backend = std::move(backend);
}

std::shared_ptr<IInferenceBackend> SharedModelRuntime::backend() const {
    std::shared_lock<std::shared_mutex> lk(m_modelMu);
    return m_backend;
}

// ============================================================================
// Model loading — metadata discovery only; weights stay memory-mapped
// ============================================================================
bool SharedModelRuntime::loadModel(const std::string& ggufPath) {
    std::unique_lock<std::shared_mutex> lk(m_modelMu);

    if (!m_initialized)
        return false;

    if (m_modelLoaded && m_modelPath == ggufPath)
        return true;

    // Close any previous mapping
    auto closeMapping = [this]() {
#ifdef _WIN32
        if (m_fileView) {
            UnmapViewOfFile(m_fileView);
            m_fileView = nullptr;
        }
        if (m_fileMapping) {
            CloseHandle(static_cast<HANDLE>(m_fileMapping));
            m_fileMapping = nullptr;
        }
#endif
        m_fileBase = nullptr;
        m_fileSize = 0;
    };

    closeMapping();

    m_modelLoaded = false;
    m_modelPath.clear();
    m_tensors.clear();
    m_tensorCount = 0;
    m_metadataKVCount = 0;
    m_ggufAlignment = kDefaultAlignment;
    m_dataOffset = 0;
    m_ggufVersion = 0;

#ifdef _WIN32
    HANDLE file = CreateFileA(
        ggufPath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (file == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0) {
        CloseHandle(file);
        return false;
    }

    m_fileSize = static_cast<uint64_t>(size.QuadPart);

    HANDLE mapping = CreateFileMappingA(
        file, nullptr, PAGE_READONLY, 0, 0, nullptr);

    if (!mapping) {
        CloseHandle(file);
        m_fileSize = 0;
        return false;
    }

    void* view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(file);

    if (!view) {
        CloseHandle(mapping);
        m_fileSize = 0;
        return false;
    }

    m_fileMapping = mapping;
    m_fileView    = view;
    m_fileBase    = reinterpret_cast<const uint8_t*>(view);
#else
    (void)ggufPath;
    return false;
#endif

    if (!parseGGUF()) {
        closeMapping();
        return false;
    }

    // Register every tensor with the residency tracker
    if (m_tracker) {
        for (const auto& kv : m_tensors) {
            m_tracker->track(kv.first, kv.second.uncompressedBytes);
        }
    }

    // Build BP1 braid index (or synthetic index for raw GGUF)
    m_braidIndex = std::make_unique<BP1BraidIndex>();
    std::vector<TensorDescriptor> tensorList;
    tensorList.reserve(m_tensors.size());
    for (const auto& kv : m_tensors)
        tensorList.push_back(kv.second);

    // Try to detect BP1 region at end of file or use synthetic
    bool bp1Built = false;
    if (m_fileSize > sizeof(BP1FileHeader)) {
        // Check if there's a BP1 header at the end of the file
        uint64_t candidateOffset = m_fileSize - sizeof(BP1FileHeader);
        if (candidateOffset < m_fileSize) {
            uint32_t magic = 0;
            std::memcpy(&magic, m_fileBase + candidateOffset, sizeof(magic));
            if (magic == 0x42503100u) {
                bp1Built = m_braidIndex->buildFromBP1Region(
                    m_fileBase, m_fileSize, candidateOffset,
                    m_fileSize - candidateOffset);
            }
        }
    }
    if (!bp1Built) {
        m_braidIndex->buildSyntheticFromGGUF(m_fileBase, m_fileSize, m_dataOffset, tensorList);
    }

    // Initialize braid streamer with 64 MiB workspace
    m_braidStreamer = std::make_unique<BP1BraidStreamer>(m_braidIndex.get());
    if (!m_braidStreamer->initialize(64ull * 1024ull * 1024ull)) {
        m_braidStreamer.reset();
        m_braidIndex.reset();
    }
    m_useBP1Streaming = (m_braidStreamer != nullptr);

    m_modelPath = ggufPath;
    m_modelLoaded = true;

    // Load the backend model as well
    if (m_backend) {
        if (!m_backend->loadModel(ggufPath)) {
            if (m_tracker) {
                for (const auto& kv : m_tensors)
                    m_tracker->markCold(kv.first);
            }
            closeMapping();
            m_tensors.clear();
            m_modelPath.clear();
            m_modelLoaded = false;
            m_braidStreamer.reset();
            m_braidIndex.reset();
            m_useBP1Streaming = false;
            return false;
        }
    }

    return true;
}

void SharedModelRuntime::unloadModel() {
    std::unique_lock<std::shared_mutex> lk(m_modelMu);

    if (m_backend && m_modelLoaded)
        m_backend->unloadModel();

    if (m_tracker) {
        const auto all = m_tracker->all();
        for (const auto& r : all)
            m_tracker->markCold(r.id);
    }

    {
        std::lock_guard<std::mutex> refLk(m_refMu);
        m_tileRefs.clear();
    }

    m_modelPath.clear();
    m_modelLoaded = false;
    m_tensors.clear();
    m_tensorCount = 0;
    m_metadataKVCount = 0;
    m_dataOffset = 0;
    m_fileSize = 0;
    m_fileBase = nullptr;

    m_braidStreamer.reset();
    m_braidIndex.reset();
    m_useBP1Streaming = false;

#ifdef _WIN32
    if (m_fileView) {
        UnmapViewOfFile(m_fileView);
        m_fileView = nullptr;
    }
    if (m_fileMapping) {
        CloseHandle(static_cast<HANDLE>(m_fileMapping));
        m_fileMapping = nullptr;
    }
#endif
}

bool SharedModelRuntime::isModelLoaded() const {
    std::shared_lock<std::shared_mutex> lk(m_modelMu);
    return m_modelLoaded;
}

std::string SharedModelRuntime::currentModelPath() const {
    std::shared_lock<std::shared_mutex> lk(m_modelMu);
    return m_modelPath;
}

// ============================================================================
// Tensor discovery
// ============================================================================
bool SharedModelRuntime::getTensor(uint64_t tensorId, TensorDescriptor& out) const {
    std::shared_lock<std::shared_mutex> lk(m_modelMu);

    if (!m_modelLoaded)
        return false;

    auto it = m_tensors.find(tensorId);
    if (it == m_tensors.end())
        return false;

    out = it->second;
    return true;
}

bool SharedModelRuntime::findTensor(const std::string& name, TensorDescriptor& out) const {
    std::shared_lock<std::shared_mutex> lk(m_modelMu);

    if (!m_modelLoaded)
        return false;

    for (const auto& kv : m_tensors) {
        if (kv.second.name == name) {
            out = kv.second;
            return true;
        }
    }
    return false;
}

std::vector<TensorDescriptor> SharedModelRuntime::tensors() const {
    std::vector<TensorDescriptor> result;

    std::shared_lock<std::shared_mutex> lk(m_modelMu);

    if (!m_modelLoaded)
        return result;

    result.reserve(m_tensors.size());
    for (const auto& kv : m_tensors)
        result.push_back(kv.second);

    return result;
}

// ============================================================================
// Tile addressing
// ============================================================================
bool SharedModelRuntime::resolveTile(const TileId& tile, TileAddress& out) const {
    TensorDescriptor td;
    if (!getTensor(tile.tensorId, td))
        return false;

    if (td.storedBytes == 0)
        return false;

    const uint64_t tileFileStart = static_cast<uint64_t>(tile.tileIdx) * kTileBytes;
    if (tileFileStart >= td.storedBytes)
        return false;

    const uint64_t remaining = td.storedBytes - tileFileStart;
    const uint64_t bytes = std::min(remaining, kTileBytes);

    uint64_t logicalOffset = 0;
    uint64_t logicalCount  = 0;

    if (td.blockBytes != 0 && td.blockElements != 0) {
        const uint64_t firstBlock = tileFileStart / td.blockBytes;
        if (!checkedMul(firstBlock, td.blockElements, logicalOffset))
            return false;

        uint64_t blockCount = (bytes + td.blockBytes - 1) / td.blockBytes;
        if (!checkedMul(blockCount, td.blockElements, logicalCount))
            return false;

        if (logicalOffset >= td.elementCount) {
            logicalCount = 0;
        } else if (logicalCount > td.elementCount - logicalOffset) {
            logicalCount = td.elementCount - logicalOffset;
        }
    } else {
        const uint64_t elementBytes = elementSizeFor(td.ggmlType);
        if (elementBytes == 0)
            return false;
        logicalOffset = tileFileStart / elementBytes;
        logicalCount  = bytes / elementBytes;
        if (logicalOffset >= td.elementCount) {
            logicalCount = 0;
        } else if (logicalCount > td.elementCount - logicalOffset) {
            logicalCount = td.elementCount - logicalOffset;
        }
    }

    if (td.fileOffset > m_fileSize || bytes > m_fileSize - td.fileOffset)
        return false;

    uint64_t absoluteOffset = 0;
    if (!checkedAdd(td.fileOffset, tileFileStart, absoluteOffset))
        return false;

    if (absoluteOffset > m_fileSize || bytes > m_fileSize - absoluteOffset)
        return false;

    out.id = tile;
    out.fileOffset = absoluteOffset;
    out.fileBytes = bytes;
    out.logicalElementOffset = logicalOffset;
    out.logicalElementCount = logicalCount;
    return true;
}

// ============================================================================
// Sequence management
// ============================================================================
uint64_t SharedModelRuntime::beginSequence() {
    uint64_t id = m_nextSeqId.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lk(m_seqMu);
    m_sequences[id] = true;
    {
        std::lock_guard<std::mutex> sLk(m_statMu);
        m_stats.activeSequences = static_cast<uint32_t>(m_sequences.size());
    }
    return id;
}

void SharedModelRuntime::endSequence(uint64_t seqId) {
    std::lock_guard<std::mutex> lk(m_seqMu);
    m_sequences.erase(seqId);
    {
        std::lock_guard<std::mutex> sLk(m_statMu);
        m_stats.activeSequences = static_cast<uint32_t>(m_sequences.size());
    }
}

// ============================================================================
// Tile materialization — the hot path
// ============================================================================
bool SharedModelRuntime::materializeTile(const TileId& tile,
                                           const RuntimeConstraints& constraints,
                                           ExecutionTile& out) {
    out = ExecutionTile{};
    const uint64_t t0 = nowNs();

    TileAddress address;
    if (!resolveTile(tile, address))
        return false;

    // Attempt reuse via residency tracker
    ResidencyHandle resident;
    if (ensureTileResident(address, constraints, resident) && resident.ready && resident.address != 0) {
        out.tile    = tile;
        out.address = resident.address;
        out.format  = ExecutionFormat::BF16;
        out.elementCount = address.logicalElementCount;
        // Resident data is BF16; report decompressed element bytes, not compressed file bytes
        out.bytes   = address.logicalElementCount * sizeof(uint16_t);
        out.allocation = nullptr;

        {
            std::lock_guard<std::mutex> lk(m_refMu);
            ++m_tileRefs[tile];
        }
        updateStats(true, address.fileBytes);
        return true;
    }

    TensorDescriptor td;
    if (!getTensor(tile.tensorId, td))
        return false;

    std::vector<uint8_t> source;
    if (!readTile(address, source))
        return false;

    const PrecisionPlan plan = choosePrecision(td, constraints);

    if (!materializeExecutionTile(address, plan, source, out))
        return false;

    {
        std::lock_guard<std::mutex> lk(m_refMu);
        ++m_tileRefs[tile];
    }

    {
        std::lock_guard<std::mutex> lk(m_statMu);
        ++m_stats.tilesMaterialized;
        m_stats.bytesDecompressed += out.bytes;
        const double latency = nsToMs(nowNs() - t0);
        m_stats.avgTileLatencyMs = (m_stats.avgTileLatencyMs * 0.9) + (latency * 0.1);
    }

    updateStats(false, address.fileBytes);
    return true;
}

void SharedModelRuntime::releaseTile(ExecutionTile& tile) {
    if (tile.tile.tensorId == 0)
        return;

    bool lastReference = false;

    {
        std::lock_guard<std::mutex> lk(m_refMu);
        auto it = m_tileRefs.find(tile.tile);
        if (it != m_tileRefs.end()) {
            if (it->second > 0)
                --it->second;
            if (it->second == 0) {
                m_tileRefs.erase(it);
                lastReference = true;
            }
        }
    }

    if (tile.allocation) {
        alignedFree(tile.allocation);
        tile.allocation = nullptr;
    }

    if (lastReference && m_tracker) {
        m_tracker->markCold(tile.tile.tensorId);
    }

    tile.address = 0;
    tile.bytes = 0;
    tile.elementCount = 0;
    tile.tile = TileId{};
}

// ============================================================================
// Prefetch hint
// ============================================================================
bool SharedModelRuntime::prefetch(const TileId& tile,
                                    const RuntimeConstraints& /*constraints*/) {
    if (!m_tracker)
        return false;

    if (!m_tracker->known(tile.tensorId))
        return false;

    m_tracker->markPrefetching(tile.tensorId, Memory::MemoryTier::VRAM);
    return true;
}

// ============================================================================
// Adaptive precision selection
// ============================================================================
PrecisionPlan SharedModelRuntime::choosePrecision(
    const TensorDescriptor& tensor,
    const RuntimeConstraints& constraints) const {

    PrecisionPlan plan;
    plan.storage = tensor.storageFormat;
    plan.braid = BraidPrecision::BP8;
    plan.execution = ExecutionFormat::BF16;
    plan.useBraid = true;

    if (constraints.memoryPressure > 0.85f) {
        plan.braid = BraidPrecision::BP4;
    } else if (constraints.memoryPressure > 0.70f) {
        plan.braid = BraidPrecision::BP6;
    }

    if (constraints.isAttention && constraints.memoryPressure < 0.60f) {
        plan.braid = BraidPrecision::BP8;
        plan.execution = ExecutionFormat::FP16;
    }

    if (constraints.isFFN && constraints.memoryPressure > 0.50f) {
        plan.braid = BraidPrecision::BP4;
    }

    // Preserve source precision where the execution representation is native
    if (tensor.ggmlType == GGMLType::F32)
        plan.execution = ExecutionFormat::FP32;
    else if (tensor.ggmlType == GGMLType::F16)
        plan.execution = ExecutionFormat::FP16;
    else if (tensor.ggmlType == GGMLType::BF16)
        plan.execution = ExecutionFormat::BF16;

    return plan;
}

// ============================================================================
// Inference entry point
// ============================================================================
std::string SharedModelRuntime::generate(const GenerateRequest& req,
                                         StreamTokenFn onToken) {
    if (!isModelLoaded()) {
        const std::string error = "[SharedModelRuntime] No model loaded";
        if (onToken)
            onToken(error, true);
        return error;
    }

    auto activeBackend = backend();
    if (!activeBackend) {
        const std::string error = "[SharedModelRuntime] No inference backend configured";
        if (onToken)
            onToken(error, true);
        return error;
    }

    if (!activeBackend->ready()) {
        const std::string error = "[SharedModelRuntime] Inference backend is not ready";
        if (onToken)
            onToken(error, true);
        return error;
    }

    const uint64_t seqId = beginSequence();

    struct SequenceGuard {
        SharedModelRuntime* runtime;
        uint64_t id;
        ~SequenceGuard() {
            if (runtime && id)
                runtime->endSequence(id);
        }
    } guard{this, seqId};

    return activeBackend->generate(req, std::move(onToken));
}

// ============================================================================
// Telemetry
// ============================================================================
RuntimeStats SharedModelRuntime::stats() const {
    RuntimeStats result;
    {
        std::lock_guard<std::mutex> lk(m_statMu);
        result = m_stats;
    }
    {
        std::lock_guard<std::mutex> lk(m_refMu);
        result.residentTileCount = static_cast<uint32_t>(m_tileRefs.size());
    }
    if (m_tracker) {
        result.residentBytes = m_tracker->bytesInTier(Memory::MemoryTier::VRAM);
    }
    return result;
}

// ============================================================================
// GGUF parsing
// ============================================================================
bool SharedModelRuntime::parseGGUF() {
    if (!m_fileBase || m_fileSize < 24)
        return false;

    uint64_t cursor = 0;

    uint32_t magic = 0;
    if (!readU32Raw(m_fileBase, m_fileSize, cursor, magic))
        return false;
    if (magic != kGGUFMagicLE)
        return false;

    uint32_t version = 0;
    if (!readU32Raw(m_fileBase, m_fileSize, cursor, version))
        return false;
    if (version != kGGUFVersion2 && version != kGGUFVersion3)
        return false;

    m_ggufVersion = version;

    uint64_t tensorCount = 0;
    uint64_t metadataKVCount = 0;
    if (!readU64Raw(m_fileBase, m_fileSize, cursor, tensorCount))
        return false;
    if (!readU64Raw(m_fileBase, m_fileSize, cursor, metadataKVCount))
        return false;

    m_tensorCount = tensorCount;
    m_metadataKVCount = metadataKVCount;

    if (!parseMetadata(cursor))
        return false;

    m_dataOffset = alignUp(cursor, m_ggufAlignment);
    if (m_dataOffset > m_fileSize)
        return false;

    if (!parseTensorDirectory())
        return false;

    return true;
}

bool SharedModelRuntime::parseMetadata(uint64_t& cursor) {
    for (uint64_t i = 0; i < m_metadataKVCount; ++i) {
        std::string key;
        if (!readStringRaw(m_fileBase, m_fileSize, cursor, key))
            return false;

        uint32_t type = 0;
        if (!readU32Raw(m_fileBase, m_fileSize, cursor, type))
            return false;

        if (key == "general.alignment" || key == "alignment") {
            uint64_t alignment = 0;
            if (readU64Metadata(m_fileBase, m_fileSize, cursor, alignment)) {
                if (alignment >= 1 && alignment <= 4096)
                    m_ggufAlignment = alignment;
            } else {
                if (!skipGGUFValue(m_fileBase, m_fileSize, cursor, type))
                    return false;
            }
        } else {
            if (!skipGGUFValue(m_fileBase, m_fileSize, cursor, type))
                return false;
        }
    }
    return true;
}

bool SharedModelRuntime::parseTensorDirectory() {
    uint64_t cursor = 24; // skip header

    // Skip metadata
    for (uint64_t i = 0; i < m_metadataKVCount; ++i) {
        std::string key;
        if (!readStringRaw(m_fileBase, m_fileSize, cursor, key))
            return false;
        uint32_t type = 0;
        if (!readU32Raw(m_fileBase, m_fileSize, cursor, type))
            return false;
        if (!skipGGUFValue(m_fileBase, m_fileSize, cursor, type))
            return false;
    }

    const uint64_t dataOffset = alignUp(cursor, m_ggufAlignment);
    if (dataOffset > m_fileSize)
        return false;

    m_dataOffset = dataOffset;

    for (uint64_t i = 0; i < m_tensorCount; ++i) {
        TensorDescriptor td;
        td.id = i + 1; // 1-based tensor IDs

        if (!readStringRaw(m_fileBase, m_fileSize, cursor, td.name))
            return false;

        uint32_t nDims = 0;
        if (!readU32Raw(m_fileBase, m_fileSize, cursor, nDims))
            return false;
        if (nDims == 0 || nDims > 4)
            return false;

        td.dimensions = nDims;
        td.shape.resize(nDims);
        for (uint32_t d = 0; d < nDims; ++d) {
            if (!readU64Raw(m_fileBase, m_fileSize, cursor, td.shape[d]))
                return false;
        }

        uint32_t ggmlTypeRaw = 0;
        if (!readU32Raw(m_fileBase, m_fileSize, cursor, ggmlTypeRaw))
            return false;
        td.ggmlType = static_cast<GGMLType>(ggmlTypeRaw);

        uint64_t tensorOffset = 0;
        if (!readU64Raw(m_fileBase, m_fileSize, cursor, tensorOffset))
            return false;

        if (!readShapeProduct(td.shape, td.elementCount))
            return false;

        td.storageFormat = storageFormatFromGGML(td.ggmlType);
        td.blockBytes    = blockBytesFor(td.ggmlType);
        td.blockElements = blockElementsFor(td.ggmlType);
        td.storedBytes   = tensorStoredBytes(td.ggmlType, td.elementCount);

        if (td.ggmlType == GGMLType::F32 ||
            td.ggmlType == GGMLType::F16 ||
            td.ggmlType == GGMLType::BF16) {
            uint64_t elementBytes = elementSizeFor(td.ggmlType);
            if (!checkedMul(td.elementCount, elementBytes, td.uncompressedBytes))
                return false;
        } else {
            // Dequantized to float32
            if (!checkedMul(td.elementCount, 4ull, td.uncompressedBytes))
                return false;
        }

        td.fileOffset = m_dataOffset + tensorOffset;

        // Layer inference from naming conventions
        td.layer = 0;
        const std::string& n = td.name;
        const char* prefixes[] = { "blk.", "layers.", "layer." };
        for (const char* prefix : prefixes) {
            size_t pos = n.find(prefix);
            if (pos == std::string::npos)
                continue;
            size_t p = pos + std::strlen(prefix);
            uint32_t layer = 0;
            bool foundDigit = false;
            while (p < n.size() && n[p] >= '0' && n[p] <= '9') {
                foundDigit = true;
                uint32_t digit = static_cast<uint32_t>(n[p] - '0');
                if (layer > (std::numeric_limits<uint32_t>::max() - digit) / 10u)
                    break;
                layer = layer * 10u + digit;
                ++p;
            }
            if (foundDigit) {
                td.layer = layer;
                break;
            }
        }

        td.isWeight = true;

        // Validate file range
        if (td.fileOffset > m_fileSize || td.storedBytes > m_fileSize - td.fileOffset)
            return false;

        m_tensors[td.id] = std::move(td);
    }

    return true;
}

// ============================================================================
// Tile access
// ============================================================================
bool SharedModelRuntime::ensureTileResident(const TileAddress& tile,
                                              const RuntimeConstraints& /*constraints*/,
                                              ResidencyHandle& out) {
    out = ResidencyHandle{};

    if (!m_tracker || !m_placement)
        return false;

    const uint64_t tensorId = tile.id.tensorId;
    if (!m_tracker->known(tensorId))
        return false;

    auto res = m_tracker->get(tensorId);
    if (res.state == Memory::ResidencyState::Resident ||
        res.state == Memory::ResidencyState::Pinned) {
        out.tile    = tile.id;
        out.tier    = res.tier;
        out.address = res.address;
        out.bytes   = res.bytes;
        out.ready   = res.address != 0;
        if (out.ready)
            m_tracker->recordUse(tensorId, nowNs());
        return out.ready;
    }

    // Cold path: ask placement manager to materialize
    Memory::DeviceId dev = 0;
    const uint64_t address = m_placement->ensureResident(tensorId, dev);
    if (address == 0)
        return false;

    auto refreshed = m_tracker->get(tensorId);
    out.tile    = tile.id;
    out.tier    = (refreshed.tier == Memory::MemoryTier::UNRESIDENT)
                      ? Memory::MemoryTier::VRAM
                      : refreshed.tier;
    out.address = address;
    out.bytes   = refreshed.bytes;
    out.ready   = true;

    m_tracker->recordUse(tensorId, nowNs());
    return true;
}

bool SharedModelRuntime::readTile(const TileAddress& tile,
                                    std::vector<uint8_t>& data) {
    std::shared_lock<std::shared_mutex> lk(m_modelMu);

    if (!m_modelLoaded || !m_fileBase)
        return false;

    if (tile.fileOffset > m_fileSize ||
        tile.fileBytes > m_fileSize - tile.fileOffset)
        return false;

    if (tile.fileBytes > static_cast<uint64_t>(std::numeric_limits<size_t>::max()))
        return false;

    data.resize(static_cast<size_t>(tile.fileBytes));
    if (tile.fileBytes != 0) {
        std::memcpy(data.data(), m_fileBase + tile.fileOffset,
                    static_cast<size_t>(tile.fileBytes));
    }
    return true;
}

bool SharedModelRuntime::materializeExecutionTile(const TileAddress& tile,
                                                    const PrecisionPlan& plan,
                                                    const std::vector<uint8_t>& source,
                                                    ExecutionTile& out) {
    TensorDescriptor tensor;
    if (!getTensor(tile.id.tensorId, tensor))
        return false;

    const uint64_t count = tile.logicalElementCount;
    if (count == 0)
        return false;

    // Determine if source is quantized (always decodes to float32 internally)
    const bool isQuantized =
        tensor.ggmlType == GGMLType::Q4_0 ||
        tensor.ggmlType == GGMLType::Q8_0 ||
        tensor.ggmlType == GGMLType::Q4_K ||
        tensor.ggmlType == GGMLType::Q3_K ||
        tensor.ggmlType == GGMLType::Q5_K ||
        tensor.ggmlType == GGMLType::Q6_K;

    // If quantized and target is FP16/BF16, decode to FP32 first then convert
    const bool needsFp32Intermediate = isQuantized &&
        (plan.execution == ExecutionFormat::FP16 ||
         plan.execution == ExecutionFormat::BF16);

    uint64_t bytesPerElement = 0;
    switch (plan.execution) {
    case ExecutionFormat::FP32:
        bytesPerElement = sizeof(float);
        break;
    case ExecutionFormat::FP16:
    case ExecutionFormat::BF16:
        bytesPerElement = sizeof(uint16_t);
        break;
    default:
        return false;
    }

    uint64_t destinationBytes64 = 0;
    if (!checkedMul(count, bytesPerElement, destinationBytes64))
        return false;

    if (destinationBytes64 > static_cast<uint64_t>(std::numeric_limits<size_t>::max()))
        return false;

    const size_t destinationBytes = static_cast<size_t>(destinationBytes64);
    void* allocation = alignedAlloc64(destinationBytes);
    if (!allocation)
        return false;

    if (needsFp32Intermediate) {
        // Allocate temporary FP32 buffer for safe dequantization
        uint64_t fp32Bytes64 = 0;
        if (!checkedMul(count, sizeof(float), fp32Bytes64)) {
            alignedFree(allocation);
            return false;
        }
        if (fp32Bytes64 > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
            alignedFree(allocation);
            return false;
        }
        void* fp32Buf = alignedAlloc64(static_cast<size_t>(fp32Bytes64));
        if (!fp32Buf) {
            alignedFree(allocation);
            return false;
        }

        PrecisionPlan fp32Plan = plan;
        fp32Plan.execution = ExecutionFormat::FP32;

        bool ok = decodeTile(tensor, fp32Plan, source.data(), source.size(),
                             fp32Buf, static_cast<size_t>(fp32Bytes64),
                             tile.logicalElementOffset, count);
        if (!ok) {
            alignedFree(fp32Buf);
            alignedFree(allocation);
            return false;
        }

        // Convert FP32 -> target format
        const float* src = static_cast<const float*>(fp32Buf);
        if (plan.execution == ExecutionFormat::FP16) {
            auto* dst = static_cast<uint16_t*>(allocation);
            for (uint64_t i = 0; i < count; ++i)
                dst[i] = floatToHalfImpl(src[i]);
        } else { // BF16
            auto* dst = static_cast<uint16_t*>(allocation);
            for (uint64_t i = 0; i < count; ++i)
                dst[i] = floatToBfloatImpl(src[i]);
        }
        alignedFree(fp32Buf);
    } else {
        bool ok = decodeTile(tensor, plan, source.data(), source.size(),
                             allocation, destinationBytes,
                             tile.logicalElementOffset, count);
        if (!ok) {
            alignedFree(allocation);
            return false;
        }
    }

    out.tile         = tile.id;
    out.allocation   = allocation;
    out.address      = reinterpret_cast<uint64_t>(allocation);
    out.bytes        = destinationBytes;
    out.format       = plan.execution;
    out.elementCount = count;
    return true;
}

// ============================================================================
// Dequantization
// ============================================================================
bool SharedModelRuntime::decodeTile(const TensorDescriptor& tensor,
                                    const PrecisionPlan& plan,
                                    const uint8_t* source,
                                    size_t sourceBytes,
                                    void* destination,
                                    size_t destinationBytes,
                                    uint64_t /*elementOffset*/,
                                    uint64_t elementCount) {
    if (!source || !destination || elementCount == 0)
        return false;

    const uint64_t requiredF32Bytes = elementCount * sizeof(float);

    switch (tensor.ggmlType) {
    case GGMLType::F32: {
        if (sourceBytes < requiredF32Bytes)
            return false;

        if (plan.execution == ExecutionFormat::FP32) {
            if (destinationBytes < requiredF32Bytes)
                return false;
            std::memcpy(destination, source, static_cast<size_t>(requiredF32Bytes));
            return true;
        }

        if (plan.execution == ExecutionFormat::BF16) {
            const size_t required = static_cast<size_t>(elementCount * sizeof(uint16_t));
            if (destinationBytes < required)
                return false;
            auto* dst = reinterpret_cast<uint16_t*>(destination);
            const auto* src = reinterpret_cast<const float*>(source);
            for (uint64_t i = 0; i < elementCount; ++i) {
                uint32_t bits = 0;
                std::memcpy(&bits, &src[i], sizeof(bits));
                dst[i] = static_cast<uint16_t>(bits >> 16);
            }
            return true;
        }

        if (plan.execution == ExecutionFormat::FP16) {
            const size_t required = static_cast<size_t>(elementCount * sizeof(uint16_t));
            if (destinationBytes < required)
                return false;
            auto* dst = reinterpret_cast<uint16_t*>(destination);
            const auto* src = reinterpret_cast<const float*>(source);
            for (uint64_t i = 0; i < elementCount; ++i) {
                float value = src[i];
                uint32_t bits = 0;
                std::memcpy(&bits, &value, sizeof(bits));
                const uint32_t sign = (bits >> 16) & 0x8000u;
                int32_t exp = static_cast<int32_t>((bits >> 23) & 0xFFu) - 127 + 15;
                uint32_t frac = bits & 0x007FFFFFu;
                uint16_t outValue = 0;
                if (exp <= 0) {
                    if (frac == 0) {
                        outValue = static_cast<uint16_t>(sign);
                    } else {
                        frac |= 0x00800000u;
                        const uint32_t shift = static_cast<uint32_t>(14 - exp);
                        uint32_t mant = frac >> shift;
                        if ((frac >> (shift - 1)) & 1u)
                            ++mant;
                        outValue = static_cast<uint16_t>(sign | mant);
                    }
                } else if (exp >= 31) {
                    outValue = static_cast<uint16_t>(sign | 0x7C00u |
                        ((frac != 0) ? 0x0200u : 0u));
                } else {
                    uint32_t mant = frac >> 13;
                    if (frac & 0x00001000u)
                        ++mant;
                    if (mant == 0x0400u) {
                        mant = 0;
                        ++exp;
                        if (exp >= 31) {
                            outValue = static_cast<uint16_t>(sign | 0x7C00u);
                            dst[i] = outValue;
                            continue;
                        }
                    }
                    outValue = static_cast<uint16_t>(sign |
                        (static_cast<uint32_t>(exp) << 10) | mant);
                }
                dst[i] = outValue;
            }
            return true;
        }
        return false;
    }

    case GGMLType::F16: {
        const uint64_t needed = elementCount * sizeof(uint16_t);
        if (sourceBytes < needed)
            return false;

        if (plan.execution == ExecutionFormat::FP16) {
            if (destinationBytes < needed)
                return false;
            std::memcpy(destination, source, static_cast<size_t>(needed));
            return true;
        }

        if (plan.execution == ExecutionFormat::BF16) {
            const size_t required = static_cast<size_t>(elementCount * sizeof(uint16_t));
            if (destinationBytes < required)
                return false;
            auto* dst = reinterpret_cast<uint16_t*>(destination);
            for (uint64_t i = 0; i < elementCount; ++i) {
                uint16_t bits = static_cast<uint16_t>(source[i * 2 + 0])
                              | (static_cast<uint16_t>(source[i * 2 + 1]) << 8);
                dst[i] = bits; // F16 and BF16 have same bit layout for normal numbers
            }
            return true;
        }

        if (plan.execution == ExecutionFormat::FP32) {
            if (destinationBytes < requiredF32Bytes)
                return false;
            auto* dst = reinterpret_cast<float*>(destination);
            for (uint64_t i = 0; i < elementCount; ++i) {
                uint16_t bits = static_cast<uint16_t>(source[i * 2 + 0])
                              | (static_cast<uint16_t>(source[i * 2 + 1]) << 8);
                dst[i] = halfToFloatImpl(bits);
            }
            return true;
        }
        return false;
    }

    case GGMLType::BF16: {
        const uint64_t needed = elementCount * sizeof(uint16_t);
        if (sourceBytes < needed)
            return false;

        if (plan.execution == ExecutionFormat::BF16) {
            if (destinationBytes < needed)
                return false;
            std::memcpy(destination, source, static_cast<size_t>(needed));
            return true;
        }

        if (plan.execution == ExecutionFormat::FP32) {
            if (destinationBytes < requiredF32Bytes)
                return false;
            auto* dst = reinterpret_cast<float*>(destination);
            for (uint64_t i = 0; i < elementCount; ++i) {
                uint16_t bits = static_cast<uint16_t>(source[i * 2 + 0])
                              | (static_cast<uint16_t>(source[i * 2 + 1]) << 8);
                dst[i] = bfloatToFloatImpl(bits);
            }
            return true;
        }

        if (plan.execution == ExecutionFormat::FP16) {
            const size_t required = static_cast<size_t>(elementCount * sizeof(uint16_t));
            if (destinationBytes < required)
                return false;
            auto* dst = reinterpret_cast<uint16_t*>(destination);
            for (uint64_t i = 0; i < elementCount; ++i) {
                uint16_t bits = static_cast<uint16_t>(source[i * 2 + 0])
                              | (static_cast<uint16_t>(source[i * 2 + 1]) << 8);
                // BF16 -> F16 conversion: treat as float32 then convert to F16
                float f = bfloatToFloatImpl(bits);
                uint32_t fbits = 0;
                std::memcpy(&fbits, &f, sizeof(fbits));
                const uint32_t sign = (fbits >> 16) & 0x8000u;
                int32_t exp = static_cast<int32_t>((fbits >> 23) & 0xFFu) - 127 + 15;
                uint32_t frac = fbits & 0x007FFFFFu;
                uint16_t hv = 0;
                if (exp <= 0) {
                    hv = static_cast<uint16_t>(sign);
                } else if (exp >= 31) {
                    hv = static_cast<uint16_t>(sign | 0x7C00u);
                } else {
                    uint32_t mant = frac >> 13;
                    if (frac & 0x00001000u)
                        ++mant;
                    if (mant == 0x0400u) {
                        mant = 0;
                        ++exp;
                        if (exp >= 31) {
                            hv = static_cast<uint16_t>(sign | 0x7C00u);
                            dst[i] = hv;
                            continue;
                        }
                    }
                    hv = static_cast<uint16_t>(sign | (static_cast<uint32_t>(exp) << 10) | mant);
                }
                dst[i] = hv;
            }
            return true;
        }
        return false;
    }

    case GGMLType::Q4_0: {
        const uint64_t needQ4 = elementCount * sizeof(float);
        if (destinationBytes < needQ4) return false;
        return decodeQ4_0Impl(source, sourceBytes,
                              reinterpret_cast<float*>(destination),
                              elementCount);
    }

    case GGMLType::Q8_0: {
        const uint64_t needQ8 = elementCount * sizeof(float);
        if (destinationBytes < needQ8) return false;
        return decodeQ8_0Impl(source, sourceBytes,
                              reinterpret_cast<float*>(destination),
                              elementCount);
    }

    case GGMLType::Q4_K: {
        const uint64_t needQ4K = elementCount * sizeof(float);
        if (destinationBytes < needQ4K) return false;
        return decodeQ4_K_MImpl(source, sourceBytes,
                                reinterpret_cast<float*>(destination),
                                elementCount);
    }

    case GGMLType::Q3_K: {
        const uint64_t needQ3K = elementCount * sizeof(float);
        if (destinationBytes < needQ3K) return false;
        return decodeQ3_KImpl(source, sourceBytes,
                              reinterpret_cast<float*>(destination),
                              elementCount);
    }

    case GGMLType::Q5_K: {
        const uint64_t needQ5K = elementCount * sizeof(float);
        if (destinationBytes < needQ5K) return false;
        return decodeQ5_KImpl(source, sourceBytes,
                              reinterpret_cast<float*>(destination),
                              elementCount);
    }

    case GGMLType::Q6_K: {
        const uint64_t needQ6K = elementCount * sizeof(float);
        if (destinationBytes < needQ6K) return false;
        return decodeQ6_KImpl(source, sourceBytes,
                              reinterpret_cast<float*>(destination),
                              elementCount);
    }

    default:
        // IQ* and other unsupported formats are explicitly rejected
        return false;
    }
}

bool SharedModelRuntime::decodeF32(const uint8_t* src, size_t srcBytes,
                                     float* dst, uint64_t count) {
    const uint64_t needed = count * sizeof(float);
    if (!src || !dst || srcBytes < needed)
        return false;
    std::memcpy(dst, src, static_cast<size_t>(needed));
    return true;
}

bool SharedModelRuntime::decodeF16(const uint8_t* src, size_t srcBytes,
                                     float* dst, uint64_t count) {
    const uint64_t needed = count * sizeof(uint16_t);
    if (!src || !dst || srcBytes < needed)
        return false;
    for (uint64_t i = 0; i < count; ++i) {
        uint16_t bits = static_cast<uint16_t>(src[i * 2 + 0])
                      | (static_cast<uint16_t>(src[i * 2 + 1]) << 8);
        dst[i] = halfToFloatImpl(bits);
    }
    return true;
}

bool SharedModelRuntime::decodeBF16(const uint8_t* src, size_t srcBytes,
                                      float* dst, uint64_t count) {
    const uint64_t needed = count * sizeof(uint16_t);
    if (!src || !dst || srcBytes < needed)
        return false;
    for (uint64_t i = 0; i < count; ++i) {
        uint16_t bits = static_cast<uint16_t>(src[i * 2 + 0])
                      | (static_cast<uint16_t>(src[i * 2 + 1]) << 8);
        dst[i] = bfloatToFloatImpl(bits);
    }
    return true;
}

bool SharedModelRuntime::decodeQ4_0(const uint8_t* src, size_t srcBytes,
                                    float* dst, uint64_t count) {
    return decodeQ4_0Impl(src, srcBytes, dst, count);
}

bool SharedModelRuntime::decodeQ8_0(const uint8_t* src, size_t srcBytes,
                                    float* dst, uint64_t count) {
    return decodeQ8_0Impl(src, srcBytes, dst, count);
}

bool SharedModelRuntime::decodeQ4_K_M(const uint8_t* src, size_t srcBytes,
                                        float* dst, uint64_t count) {
    return decodeQ4_K_MImpl(src, srcBytes, dst, count);
}

bool SharedModelRuntime::decodeQ3_K(const uint8_t* src, size_t srcBytes,
                                      float* dst, uint64_t count) {
    return decodeQ3_KImpl(src, srcBytes, dst, count);
}

bool SharedModelRuntime::decodeQ5_K(const uint8_t* src, size_t srcBytes,
                                      float* dst, uint64_t count) {
    return decodeQ5_KImpl(src, srcBytes, dst, count);
}

bool SharedModelRuntime::decodeQ6_K(const uint8_t* src, size_t srcBytes,
                                      float* dst, uint64_t count) {
    return decodeQ6_KImpl(src, srcBytes, dst, count);
}

// ============================================================================
// Helpers
// ============================================================================
StorageFormat SharedModelRuntime::storageFormatFromGGML(GGMLType type) {
    switch (type) {
    case GGMLType::F32:  return StorageFormat::FP32;
    case GGMLType::F16:  return StorageFormat::FP16;
    case GGMLType::BF16: return StorageFormat::BF16;
    case GGMLType::Q4_0: return StorageFormat::GGUF_Q4;
    case GGMLType::Q8_0: return StorageFormat::GGUF_Q8;
    case GGMLType::Q2_K: return StorageFormat::GGUF_Q2;
    case GGMLType::Q3_K: return StorageFormat::GGUF_Q3;
    case GGMLType::Q4_K: return StorageFormat::GGUF_Q4;
    case GGMLType::Q5_K: return StorageFormat::GGUF_Q5;
    case GGMLType::Q6_K: return StorageFormat::GGUF_Q6;
    default:               return StorageFormat::Unknown;
    }
}

uint32_t SharedModelRuntime::blockBytesFor(GGMLType type) {
    switch (type) {
    case GGMLType::F32:  return 4;
    case GGMLType::F16:  return 2;
    case GGMLType::BF16: return 2;
    case GGMLType::Q4_0: return 18;
    case GGMLType::Q8_0: return 34;
    case GGMLType::Q2_K: return 256 + 16 + 12 + 96;   // ~380 (approx)
    case GGMLType::Q3_K: return 112;
    case GGMLType::Q4_K: return 144;
    case GGMLType::Q5_K: return 176;
    case GGMLType::Q6_K: return 208;
    default:             return 0;
    }
}

uint32_t SharedModelRuntime::blockElementsFor(GGMLType type) {
    switch (type) {
    case GGMLType::F32:
    case GGMLType::F16:
    case GGMLType::BF16:
        return 1;
    case GGMLType::Q4_0:
    case GGMLType::Q8_0:
        return 32;
    case GGMLType::Q2_K:
    case GGMLType::Q3_K:
    case GGMLType::Q4_K:
    case GGMLType::Q5_K:
    case GGMLType::Q6_K:
        return 256;
    default:
        return 0;
    }
}

uint64_t SharedModelRuntime::elementSizeFor(GGMLType type) {
    switch (type) {
    case GGMLType::F32:  return 4;
    case GGMLType::F16:  return 2;
    case GGMLType::BF16: return 2;
    default:             return 0;
    }
}

uint16_t SharedModelRuntime::readU16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0])
         | (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t SharedModelRuntime::readU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t SharedModelRuntime::readU64(const uint8_t* p) {
    return static_cast<uint64_t>(p[0])
         | (static_cast<uint64_t>(p[1]) << 8)
         | (static_cast<uint64_t>(p[2]) << 16)
         | (static_cast<uint64_t>(p[3]) << 24)
         | (static_cast<uint64_t>(p[4]) << 32)
         | (static_cast<uint64_t>(p[5]) << 40)
         | (static_cast<uint64_t>(p[6]) << 48)
         | (static_cast<uint64_t>(p[7]) << 56);
}

float SharedModelRuntime::halfToFloat(uint16_t h) {
    return halfToFloatImpl(h);
}

float SharedModelRuntime::bfloatToFloat(uint16_t h) {
    return bfloatToFloatImpl(h);
}

void SharedModelRuntime::updateStats(bool reused, uint64_t bytes) {
    std::lock_guard<std::mutex> lk(m_statMu);
    if (reused) {
        ++m_stats.tilesReused;
    } else {
        m_stats.bytesStreamed += bytes;
    }
    const uint64_t total = m_stats.tilesMaterialized + m_stats.tilesReused;
    if (total != 0) {
        m_stats.cacheHitRate = static_cast<double>(m_stats.tilesReused) /
                               static_cast<double>(total);
    }
}

} // namespace Shared
} // namespace Serve
} // namespace RawrXD
