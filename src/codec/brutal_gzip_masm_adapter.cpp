#include "brutal_gzip.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <limits>

extern "C" void* deflate_brutal_masm_raw(
    const void* source, std::size_t length, std::size_t* output_length);

namespace {
constexpr std::uint32_t crc_entry(std::uint32_t value) noexcept {
    for (unsigned bit = 0; bit != 8; ++bit)
        value = (value >> 1) ^ ((value & 1u) ? 0xedb88320u : 0u);
    return value;
}
constexpr auto make_crc_table() noexcept {
    struct Table { std::uint32_t values[256]{}; } table;
    for (std::uint32_t i = 0; i != 256; ++i)
        table.values[i] = crc_entry(i);
    return table;
}
constexpr auto kCrcTable = make_crc_table();

std::uint32_t gzip_crc32(const std::uint8_t* data, std::size_t size) noexcept {
    std::uint32_t crc = 0xffffffffu;
    for (std::size_t i = 0; i < size; ++i)
        crc = kCrcTable.values[(crc ^ data[i]) & 0xffu] ^ (crc >> 8);
    return crc ^ 0xffffffffu;
}
void write_le32(std::uint8_t* out, std::uint32_t value) noexcept {
    out[0] = static_cast<std::uint8_t>(value);
    out[1] = static_cast<std::uint8_t>(value >> 8);
    out[2] = static_cast<std::uint8_t>(value >> 16);
    out[3] = static_cast<std::uint8_t>(value >> 24);
}
} // namespace

// The MASM routine emits a gzip header, RFC 1951 stored blocks and a trailer.
// It deliberately leaves the CRC slot zero; this ABI wrapper finalizes the
// gzip member so the result is consumable by standard gzip/zlib readers.
extern "C" void* deflate_brutal_masm(
    const void* source, std::size_t length, std::size_t* output_length) {
    if (!output_length || (!source && length) ||
        length > (std::numeric_limits<std::size_t>::max)() - 65552u) {
        if (output_length) *output_length = 0;
        return nullptr;
    }
    *output_length = 0;
    std::size_t encoded_length = 0;
    void* encoded = deflate_brutal_masm_raw(source, length, &encoded_length);
    if (!encoded) return nullptr;
    if (encoded_length < 18u) {
        std::free(encoded);
        return nullptr;
    }
    auto* bytes = static_cast<std::uint8_t*>(encoded);
    if (bytes[0] != 0x1fu || bytes[1] != 0x8bu || bytes[2] != 0x08u) {
        std::free(encoded);
        return nullptr;
    }
    write_le32(bytes + encoded_length - 8u,
               gzip_crc32(static_cast<const std::uint8_t*>(source), length));
    write_le32(bytes + encoded_length - 4u,
               static_cast<std::uint32_t>(length));
    *output_length = encoded_length;
    return encoded;
}
