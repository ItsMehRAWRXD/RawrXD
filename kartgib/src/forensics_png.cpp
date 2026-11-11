#include "forensics_png.hpp"
#include <algorithm>
#include <fstream>
#include <vector>

static uint32_t pngCrc(const uint8_t* data, size_t size) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            uint32_t mask = 0u - (crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static void pngChunk(std::vector<uint8_t>& out, const char* type, const uint8_t* data, uint32_t size) {
    uint32_t len = size;
    uint8_t head[8] = {
        uint8_t(len >> 24), uint8_t(len >> 16), uint8_t(len >> 8), uint8_t(len),
        uint8_t(type[0]), uint8_t(type[1]), uint8_t(type[2]), uint8_t(type[3])
    };
    out.insert(out.end(), head, head + 8);
    if (size > 0 && data != nullptr) {
        out.insert(out.end(), data, data + size);
    }
    uint32_t crc = pngCrc(out.data() + out.size() - size - 4, size + 4);
    uint8_t tail[4] = {uint8_t(crc >> 24), uint8_t(crc >> 16), uint8_t(crc >> 8), uint8_t(crc)};
    out.insert(out.end(), tail, tail + 4);
}

bool writeStoredPng(const std::filesystem::path& path, const uint8_t* pixels,
    uint32_t width, uint32_t height, bool bgra) {
    std::vector<uint8_t> raw;
    raw.reserve(static_cast<size_t>(height) * (width * 3u + 1u));
    for (uint32_t y = 0; y < height; ++y) {
        raw.push_back(0);
        for (uint32_t x = 0; x < width; ++x) {
            const uint8_t* p = pixels + (static_cast<size_t>(y) * width + x) * 4u;
            raw.push_back(bgra ? p[2] : p[0]);
            raw.push_back(p[1]);
            raw.push_back(bgra ? p[0] : p[2]);
        }
    }
    std::vector<uint8_t> zlib;
    zlib.push_back(0x78);
    zlib.push_back(0x01);
    uint32_t adlerA = 1;
    uint32_t adlerB = 0;
    size_t offset = 0;
    while (offset < raw.size()) {
        uint16_t chunk = static_cast<uint16_t>(std::min<size_t>(65535, raw.size() - offset));
        bool last = offset + chunk == raw.size();
        uint16_t nlen = static_cast<uint16_t>(~chunk);
        zlib.push_back(last ? 1 : 0);
        zlib.push_back(uint8_t(chunk));
        zlib.push_back(uint8_t(chunk >> 8));
        zlib.push_back(uint8_t(nlen));
        zlib.push_back(uint8_t(nlen >> 8));
        zlib.insert(zlib.end(), raw.begin() + offset, raw.begin() + offset + chunk);
        offset += chunk;
    }
    for (uint8_t byte : raw) {
        adlerA = (adlerA + byte) % 65521u;
        adlerB = (adlerB + adlerA) % 65521u;
    }
    zlib.push_back(uint8_t(adlerB >> 8));
    zlib.push_back(uint8_t(adlerB));
    zlib.push_back(uint8_t(adlerA >> 8));
    zlib.push_back(uint8_t(adlerA));
    uint8_t ihdr[13] = {
        uint8_t(width >> 24), uint8_t(width >> 16), uint8_t(width >> 8), uint8_t(width),
        uint8_t(height >> 24), uint8_t(height >> 16), uint8_t(height >> 8), uint8_t(height),
        8, 2, 0, 0, 0
    };
    std::vector<uint8_t> png = {137, 80, 78, 71, 13, 10, 26, 10};
    pngChunk(png, "IHDR", ihdr, 13);
    pngChunk(png, "IDAT", zlib.data(), static_cast<uint32_t>(zlib.size()));
    pngChunk(png, "IEND", nullptr, 0);
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(png.data()), static_cast<std::streamsize>(png.size()));
    return out.good();
}
