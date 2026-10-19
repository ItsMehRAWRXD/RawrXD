#pragma once

// ---------------------------------------------------------------------------
// Bounded key and value cache: sizing, admission, and ring indexing.
//
// A model advertises a maximum context that is often several times the
// memory on the machine. For phi3-mini the advertised maximum is 131072
// tokens, which costs 96 GiB in f32 and 48 GiB in fp16, against 47 GiB
// of VRAM across two cards. The window the engine actually runs with is
// therefore chosen from the memory budget rather than from the metadata.
//
// The layout is [layer][window][hiddenDim] for the keys and the same for
// the values, so a position's row for one layer is contiguous.
//
// The cache is a ring. The logical position p lives in the physical slot
// p % window, so once the window is full the oldest token is overwritten.
// The attended set is the last `window` logical positions, and the
// physical slots they occupy are rotated once the ring has wrapped. The
// keys keep their absolute RoPE position, because the rotation is applied
// at write time and never to the position a key was computed for.
//
// This header is the single definition of that layout, so the device cache
// and the host reference cache cannot disagree about where a token lives.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstring>

namespace deep2 {

// Bytes per cached element: 2 for fp16, 4 for f32.
inline constexpr uint32_t kKvBytesFp16 = 2;
inline constexpr uint32_t kKvBytesFp32 = 4;

// Bytes a window of `tokens` costs.
//
//     layers * kvHeads * headDim * bytesPerElement * 2 (keys and values)
inline uint64_t KvWindowBytes(uint32_t layers, uint32_t kvHeads, uint32_t headDim,
                              uint32_t bytesPerElement, uint64_t tokens) {
    return static_cast<uint64_t>(layers) * kvHeads * headDim *
           bytesPerElement * 2ull * tokens;
}

// Bytes one token costs across every layer.
inline uint64_t KvBytesPerToken(uint32_t layers, uint32_t kvHeads, uint32_t headDim,
                                uint32_t bytesPerElement) {
    return KvWindowBytes(layers, kvHeads, headDim, bytesPerElement, 1);
}

// The physical slot a logical position lives in.
inline uint32_t KvPhysicalIndex(uint32_t logicalPos, uint32_t window) {
    return (window == 0) ? 0u : (logicalPos % window);
}

// The first logical position the cache holds, and how many it holds.
//
// Before the ring has wrapped the cache holds positions [0, count). After
// it has wrapped it holds the last `window` positions.
inline uint32_t KvWindowStart(uint32_t logicalCount, uint32_t window) {
    return (logicalCount > window) ? (logicalCount - window) : 0u;
}

inline uint32_t KvWindowCount(uint32_t logicalCount, uint32_t window) {
    return (logicalCount < window) ? logicalCount : window;
}

// Choose the window to run with.
//
// The model's advertised maximum is used when it fits the budget. Otherwise
// the window is reduced to the largest power of two that fits, which keeps
// the ring arithmetic a shift rather than a division.
//
// A window below `floorTokens` is refused and zero is returned: the engine
// would rather report the context as unavailable than run at a size it was
// not certified for. The floor is expected to be a power of two, which is
// what makes the rounded-down result land on it rather than below it.
inline uint32_t DetermineSafeContextWindow(uint32_t modelMaxLen,
                                          uint32_t layers, uint32_t kvHeads, uint32_t headDim,
                                          uint32_t bytesPerElement,
                                          uint64_t budgetBytes,
                                          uint32_t floorTokens = 4096) {
    if (modelMaxLen == 0 || layers == 0 || kvHeads == 0 || headDim == 0) return 0;

    const uint64_t perToken = KvBytesPerToken(layers, kvHeads, headDim, bytesPerElement);
    if (perToken == 0) return 0;

    const uint64_t maxTokens = budgetBytes / perToken;
    if (maxTokens >= modelMaxLen) return modelMaxLen;
    if (maxTokens < floorTokens) return 0;

    // Largest power of two that fits.
    uint32_t window = 1;
    while ((static_cast<uint64_t>(window) << 1) <= maxTokens) {
        window <<= 1;
    }
    if (window < floorTokens) window = floorTokens;
    if (window > modelMaxLen) window = modelMaxLen;
    return window;
}

// The bytes the f32 resident weights occupy, so the key and value budget
// can be taken from what the cards have left rather than from all of it.
//
// The projections are the f32 expansion of the quantized weights:
//     attn_qkv : 3 * hiddenDim x hiddenDim
//     ffn_up   : 2 * intermediateDim x hiddenDim
//     ffn_down : hiddenDim x intermediateDim
//     output   : vocab x hiddenDim
inline uint64_t KvResidentWeightBytes(uint32_t layers, uint32_t hiddenDim,
                                      uint32_t intermediateDim, uint32_t vocabSize) {
    const uint64_t perLayer =
        (3ull * hiddenDim * hiddenDim) +
        (2ull * intermediateDim * hiddenDim) +
        (1ull * hiddenDim * intermediateDim);
    const uint64_t total = perLayer * layers + (1ull * vocabSize * hiddenDim);
    return total * kKvBytesFp32;
}

// Convert a float to IEEE 754 half precision, rounding to nearest even.
//
// The cache is stored in fp16 because that is what halves its footprint,
// and because the attention shader reads fp16 natively. The keys and the
// values are the two things the model is least sensitive to in reduced
// precision, which is why the same choice is made by the reference
// implementations.
inline uint16_t KvFloatToHalf(float value) {
    uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));

    const uint32_t sign = (bits >> 16) & 0x8000u;
    const uint32_t exponent = (bits >> 23) & 0xFFu;
    const uint32_t mantissa = bits & 0x007FFFFFu;

    if (exponent == 0xFFu) {
        // Infinity, or a NaN that stays a NaN.
        return static_cast<uint16_t>(sign | 0x7C00u | (mantissa ? 0x0200u : 0u));
    }

    // Rebias the exponent from 127 to 15.
    int32_t halfExponent = static_cast<int32_t>(exponent) - 127 + 15;
    if (halfExponent >= 0x1F) {
        return static_cast<uint16_t>(sign | 0x7C00u);   // overflow to infinity
    }
    if (halfExponent <= 0) {
        if (halfExponent < -10) {
            return static_cast<uint16_t>(sign);          // underflow to zero
        }
        // Subnormal: restore the implicit bit and shift down.
        const uint32_t shifted = mantissa | 0x00800000u;
        const uint32_t shift = static_cast<uint32_t>(14 - halfExponent);
        const uint32_t rounded = (shifted + (1u << (shift - 1))) >> shift;
        return static_cast<uint16_t>(sign | rounded);
    }

    uint32_t rounded = (mantissa + 0x00001000u) >> 13;
    if (rounded == 0x0400u) {
        // The rounding carried into the exponent.
        rounded = 0;
        halfExponent++;
        if (halfExponent >= 0x1F) {
            return static_cast<uint16_t>(sign | 0x7C00u);
        }
    }
    return static_cast<uint16_t>(sign | (static_cast<uint32_t>(halfExponent) << 10) | rounded);
}

// Convert an IEEE 754 half back to a float.
//
// The verification needs this to check the conversion in both directions:
// casting the bit pattern to a float would give the integer pattern, not
// the value it represents.
inline float KvHalfToFloat(uint16_t half) {
    const uint32_t sign = static_cast<uint32_t>(half & 0x8000u) << 16;
    const uint32_t exponent = (half >> 10) & 0x1Fu;
    const uint32_t mantissa = half & 0x03FFu;

    uint32_t bits = 0;
    if (exponent == 0) {
        if (mantissa == 0) {
            bits = sign;
        } else {
            // Subnormal: normalise it.
            uint32_t e = 0;
            uint32_t m = mantissa;
            while ((m & 0x0400u) == 0) { m <<= 1; e++; }
            m &= 0x03FFu;
            bits = sign | ((127u - 15u - e + 1u) << 23) | (m << 13);
        }
    } else if (exponent == 0x1F) {
        bits = sign | 0x7F800000u | (mantissa << 13);
    } else {
        bits = sign | ((exponent + 127u - 15u) << 23) | (mantissa << 13);
    }
    float value = 0.0f;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

}  // namespace deep2