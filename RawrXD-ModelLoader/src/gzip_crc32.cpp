#include <array>
#include <cstddef>
#include <cstdint>

namespace {
constexpr std::array<std::uint32_t, 256> makeCrc32Table() noexcept {
    std::array<std::uint32_t, 256> table{};
    for (std::uint32_t i = 0; i < table.size(); ++i) {
        std::uint32_t value = i;
        for (unsigned bit = 0; bit < 8; ++bit) {
            value = (value & 1u)
                ? (0xEDB88320u ^ (value >> 1u))
                : (value >> 1u);
        }
        table[i] = value;
    }
    return table;
}
constexpr auto kCrc32Table = makeCrc32Table();
}

extern "C" std::uint32_t rawrxd_gzip_crc32(
    const void* source, std::size_t length) noexcept {
    if (!source && length != 0) return 0;
    const auto* bytes = static_cast<const std::uint8_t*>(source);
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < length; ++i) {
        crc = kCrc32Table[(crc ^ bytes[i]) & 0xFFu] ^ (crc >> 8u);
    }
    return crc ^ 0xFFFFFFFFu;
}
