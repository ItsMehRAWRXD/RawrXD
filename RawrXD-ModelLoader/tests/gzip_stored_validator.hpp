#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace rawrxd_test {
inline std::uint32_t gzipCrc32(const std::uint8_t* data, std::size_t size) {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc & 1u) ? (0xEDB88320u ^ (crc >> 1u)) : (crc >> 1u);
    }
    return crc ^ 0xFFFFFFFFu;
}

inline bool validateStoredGzip(const std::uint8_t* gzip, std::size_t gzipSize,
                               const std::uint8_t* expected,
                               std::size_t expectedSize) {
    if (!gzip || gzipSize < 18 || (!expected && expectedSize)) return false;
    if (gzip[0] != 0x1F || gzip[1] != 0x8B || gzip[2] != 8 || gzip[3] != 0)
        return false;
    std::size_t pos = 10;
    std::vector<std::uint8_t> decoded;
    decoded.reserve(expectedSize);
    bool finalBlock = false;
    while (!finalBlock) {
        if (pos >= gzipSize - 8) return false;
        const std::uint8_t header = gzip[pos++];
        finalBlock = (header & 1u) != 0;
        if ((header & 0x06u) != 0) return false; // BTYPE must be stored.
        if (pos + 4 > gzipSize - 8) return false;
        const std::uint16_t len = static_cast<std::uint16_t>(
            gzip[pos] | (static_cast<std::uint16_t>(gzip[pos + 1]) << 8));
        const std::uint16_t nlen = static_cast<std::uint16_t>(
            gzip[pos + 2] | (static_cast<std::uint16_t>(gzip[pos + 3]) << 8));
        pos += 4;
        if (static_cast<std::uint16_t>(~len) != nlen ||
            pos + len > gzipSize - 8) return false;
        decoded.insert(decoded.end(), gzip + pos, gzip + pos + len);
        pos += len;
    }
    if (pos + 8 != gzipSize || decoded.size() != expectedSize) return false;
    const auto read32 = [&](std::size_t at) {
        return static_cast<std::uint32_t>(gzip[at]) |
            (static_cast<std::uint32_t>(gzip[at + 1]) << 8) |
            (static_cast<std::uint32_t>(gzip[at + 2]) << 16) |
            (static_cast<std::uint32_t>(gzip[at + 3]) << 24);
    };
    if (read32(pos) != gzipCrc32(decoded.data(), decoded.size()) ||
        read32(pos + 4) != static_cast<std::uint32_t>(expectedSize))
        return false;
    return decoded.empty() ||
        std::memcmp(decoded.data(), expected, expectedSize) == 0;
}
}
