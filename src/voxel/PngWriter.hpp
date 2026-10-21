// ============================================================================
// PngWriter.hpp - a minimal, dependency-free PNG writer.
//
// The certification gates write the frame they captured out as a PNG so the
// evidence can be inspected outside the process, rather than only asserted
// about. The PNG is emitted with stored (uncompressed) deflate blocks, so it
// needs no zlib and keeps the writer self-contained and first-party.
//
// Only what is needed is implemented: 8-bit truecolour RGB, no interlacing,
// one IDAT chunk. That is enough to write a frame buffer.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace RawrXD {
namespace Voxel {

inline uint32_t PngCrc32(const uint8_t* data, size_t bytes, uint32_t crc = 0xFFFFFFFFu) {
    for (size_t i = 0; i < bytes; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (0xEDB88320u & (~(crc & 1u) + 1u));
        }
    }
    return crc;
}

inline uint32_t PngAdler32(const uint8_t* data, size_t bytes) {
    uint32_t a = 1;
    uint32_t b = 0;
    for (size_t i = 0; i < bytes; ++i) {
        a = (a + data[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
}

inline void PngPushBE32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
}

inline void PngPushChunk(std::vector<uint8_t>& out, const char* type,
                         const std::vector<uint8_t>& payload) {
    PngPushBE32(out, static_cast<uint32_t>(payload.size()));
    const size_t start = out.size();
    out.insert(out.end(), type, type + 4);
    out.insert(out.end(), payload.begin(), payload.end());
    const uint32_t crc = PngCrc32(out.data() + start, out.size() - start) ^ 0xFFFFFFFFu;
    PngPushBE32(out, crc);
}

// Writes an RGBA8 buffer as an RGB PNG. Returns false if the file could not
// be written.
inline bool WritePng(const char* path, const std::vector<uint8_t>& rgba,
                     uint32_t width, uint32_t height) {
    if (width == 0 || height == 0) return false;
    if (rgba.size() != static_cast<size_t>(width) * height * 4u) return false;

    // Raw scanlines, each prefixed with the filter byte 0.
    std::vector<uint8_t> raw;
    raw.reserve(static_cast<size_t>(height) * (1 + static_cast<size_t>(width) * 3));
    for (uint32_t y = 0; y < height; ++y) {
        raw.push_back(0);
        const uint8_t* row = rgba.data() + static_cast<size_t>(y) * width * 4u;
        for (uint32_t x = 0; x < width; ++x) {
            raw.push_back(row[x * 4 + 0]);
            raw.push_back(row[x * 4 + 1]);
            raw.push_back(row[x * 4 + 2]);
        }
    }

    // A zlib stream of stored deflate blocks.
    std::vector<uint8_t> z;
    z.push_back(0x78);
    z.push_back(0x01);
    size_t offset = 0;
    while (offset < raw.size()) {
        const size_t chunk = raw.size() - offset > 65535 ? 65535 : raw.size() - offset;
        const bool final = (offset + chunk) >= raw.size();
        z.push_back(final ? 1 : 0);
        z.push_back(static_cast<uint8_t>(chunk & 0xFFu));
        z.push_back(static_cast<uint8_t>((chunk >> 8) & 0xFFu));
        z.push_back(static_cast<uint8_t>(~chunk & 0xFFu));
        z.push_back(static_cast<uint8_t>((~chunk >> 8) & 0xFFu));
        z.insert(z.end(), raw.begin() + offset, raw.begin() + offset + chunk);
        offset += chunk;
    }
    PngPushBE32(z, PngAdler32(raw.data(), raw.size()));

    std::vector<uint8_t> png;
    const uint8_t signature[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    png.insert(png.end(), signature, signature + 8);

    std::vector<uint8_t> ihdr;
    PngPushBE32(ihdr, width);
    PngPushBE32(ihdr, height);
    ihdr.push_back(8);  // bit depth
    ihdr.push_back(2);  // colour type: truecolour RGB
    ihdr.push_back(0);  // compression
    ihdr.push_back(0);  // filter
    ihdr.push_back(0);  // interlace
    PngPushChunk(png, "IHDR", ihdr);
    PngPushChunk(png, "IDAT", z);
    PngPushChunk(png, "IEND", {});

    FILE* file = nullptr;
    if (fopen_s(&file, path, "wb") != 0 || file == nullptr) return false;
    const size_t written = fwrite(png.data(), 1, png.size(), file);
    fclose(file);
    return written == png.size();
}

} // namespace Voxel
} // namespace RawrXD
