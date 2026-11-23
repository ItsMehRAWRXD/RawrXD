// Portable C++ stored-block gzip fallback. This is framing/copying, not
// entropy compression; it emits valid multi-block RFC 1952 streams.
#include "gzip_crc32.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>

extern "C" void* gzip_masm_alloc(
    const void* source, std::size_t length, std::size_t* outLength) {
    if (outLength) *outLength = 0;
    if ((!source && length != 0) || length >
            std::numeric_limits<std::uint32_t>::max())
        return nullptr;

    try {
        const auto* src = static_cast<const std::uint8_t*>(source);
        const std::size_t blockCount = length == 0
            ? 1
            : 1 + (length - 1) / 65535;
        if (blockCount > (std::numeric_limits<std::size_t>::max() - length) / 5)
            return nullptr;
        const std::size_t deflateBytes = length + blockCount * 5;
        if (deflateBytes > std::numeric_limits<std::size_t>::max() - 18)
            return nullptr;
        const std::size_t totalBytes = 10 + deflateBytes + 8;

        std::vector<std::uint8_t> deflate;
        deflate.reserve(deflateBytes);
        if (length == 0) {
            deflate.push_back(0x01); // final empty stored block
            deflate.push_back(0);
            deflate.push_back(0);
            deflate.push_back(0xFF);
            deflate.push_back(0xFF);
        } else {
            std::size_t offset = 0;
            while (offset < length) {
                const std::size_t chunk =
                    std::min<std::size_t>(length - offset, 65535);
                const bool finalBlock = offset + chunk == length;
                const auto len16 = static_cast<std::uint16_t>(chunk);
                const auto nlen16 = static_cast<std::uint16_t>(~len16);
                deflate.push_back(finalBlock ? 0x01 : 0x00);
                deflate.push_back(static_cast<std::uint8_t>(len16));
                deflate.push_back(static_cast<std::uint8_t>(len16 >> 8));
                deflate.push_back(static_cast<std::uint8_t>(nlen16));
                deflate.push_back(static_cast<std::uint8_t>(nlen16 >> 8));
                deflate.insert(deflate.end(), src + offset, src + offset + chunk);
                offset += chunk;
            }
        }

        auto* output = static_cast<std::uint8_t*>(std::malloc(totalBytes));
        if (!output) return nullptr;
        std::uint8_t* cursor = output;
        *cursor++ = 0x1F;
        *cursor++ = 0x8B;
        *cursor++ = 0x08;
        *cursor++ = 0x00;
        for (unsigned i = 0; i < 4; ++i) *cursor++ = 0;
        *cursor++ = 0; // XFL
        *cursor++ = 3; // OS
        std::memcpy(cursor, deflate.data(), deflate.size());
        cursor += deflate.size();

        const std::uint32_t crc = rawrxd_gzip_crc32(src, length);
        for (unsigned i = 0; i < 4; ++i)
            *cursor++ = static_cast<std::uint8_t>(crc >> (8 * i));
        const std::uint32_t isize = static_cast<std::uint32_t>(length);
        for (unsigned i = 0; i < 4; ++i)
            *cursor++ = static_cast<std::uint8_t>(isize >> (8 * i));

        if (outLength) *outLength = static_cast<std::size_t>(cursor - output);
        return output;
    } catch (...) {
        return nullptr;
    }
}
