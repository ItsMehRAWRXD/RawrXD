#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace rawrxd::compression::native_lz {

inline std::uint32_t hash4(const std::uint8_t* p) noexcept {
    const std::uint32_t v = std::uint32_t(p[0]) |
        (std::uint32_t(p[1]) << 8) | (std::uint32_t(p[2]) << 16) |
        (std::uint32_t(p[3]) << 24);
    return (v * 2654435761u) >> 16;
}

// Wire-compatible with CompressedWeightStore's native block token stream:
// control byte, then eight literal bytes or (distance-1:u16,length:u8) matches.
// Raw fallback is represented by an exact-size payload.
inline bool encode(const std::uint8_t* src, std::size_t size,
                   std::vector<std::uint8_t>& out) {
    constexpr std::size_t kMinMatch = 4, kMaxMatch = 255, kMaxDistance = 65535;
    out.clear();
    if (!src && size) return false;
    if (size == 0) return true;
    if (size > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()))
        return false;
    try {
        out.reserve(size);
        std::vector<std::int32_t> last(1u << 16, -1);
        std::size_t pos = 0;
        while (pos < size) {
            const std::size_t controlPos = out.size();
            out.push_back(0);
            std::uint8_t control = 0;
            for (unsigned bit = 0; bit < 8 && pos < size; ++bit) {
                std::size_t length = 0, distance = 0;
                if (pos + kMinMatch <= size) {
                    const auto h = hash4(src + pos);
                    const auto candidate = last[h];
                    last[h] = static_cast<std::int32_t>(pos);
                    if (candidate >= 0) {
                        const auto c = static_cast<std::size_t>(candidate);
                        const auto d = pos - c;
                        if (d && d <= kMaxDistance) {
                            const auto limit = std::min(kMaxMatch, size - pos);
                            while (length < limit && src[c + length] == src[pos + length])
                                ++length;
                            if (length >= kMinMatch) distance = d;
                            else length = 0;
                        }
                    }
                }
                if (length) {
                    control |= static_cast<std::uint8_t>(1u << bit);
                    const auto d = static_cast<std::uint16_t>(distance - 1);
                    out.push_back(static_cast<std::uint8_t>(d));
                    out.push_back(static_cast<std::uint8_t>(d >> 8));
                    out.push_back(static_cast<std::uint8_t>(length));
                    const auto end = pos + length;
                    for (auto q = pos + 1; q + kMinMatch <= end; ++q)
                        last[hash4(src + q)] = static_cast<std::int32_t>(q);
                    pos = end;
                } else {
                    out.push_back(src[pos++]);
                }
            }
            out[controlPos] = control;
        }
        if (out.size() >= size) out.assign(src, src + size);
        return true;
    } catch (...) {
        out.clear();
        return false;
    }
}

inline bool decode(const std::uint8_t* src, std::size_t compressedSize,
                   std::uint8_t* dst, std::size_t rawSize) {
    if ((!src && compressedSize) || (!dst && rawSize)) return false;
    if (compressedSize == rawSize) {
        if (rawSize) std::copy_n(src, rawSize, dst);
        return true;
    }
    std::size_t in = 0, produced = 0;
    while (in < compressedSize && produced < rawSize) {
        const auto control = src[in++];
        for (unsigned bit = 0; bit < 8 && produced < rawSize; ++bit) {
            if (control & (1u << bit)) {
                if (compressedSize - in < 3) return false;
                const std::size_t encodedDistance =
                    std::size_t(src[in]) | (std::size_t(src[in + 1]) << 8);
                const std::size_t length = src[in + 2];
                in += 3;
                const std::size_t distance = encodedDistance + 1;
                if (distance > produced || length < 4 || length > rawSize - produced)
                    return false;
                for (std::size_t i = 0; i < length; ++i) {
                    dst[produced] = dst[produced - distance];
                    ++produced;
                }
            } else {
                if (in >= compressedSize) return false;
                dst[produced++] = src[in++];
            }
        }
    }
    return in == compressedSize && produced == rawSize;
}
} // namespace rawrxd::compression::native_lz
