// ============================================================================
// gguf_type_probe.cpp — Quick diagnostic to read raw GGML type IDs
// ============================================================================
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

static bool readU32(const uint8_t* p, uint64_t& cursor, uint32_t& v) {
    v = static_cast<uint32_t>(p[cursor])
      | (static_cast<uint32_t>(p[cursor+1]) << 8)
      | (static_cast<uint32_t>(p[cursor+2]) << 16)
      | (static_cast<uint32_t>(p[cursor+3]) << 24);
    cursor += 4;
    return true;
}
static bool readU64(const uint8_t* p, uint64_t& cursor, uint64_t& v) {
    v = static_cast<uint64_t>(p[cursor])
      | (static_cast<uint64_t>(p[cursor+1]) << 8)
      | (static_cast<uint64_t>(p[cursor+2]) << 16)
      | (static_cast<uint64_t>(p[cursor+3]) << 24)
      | (static_cast<uint64_t>(p[cursor+4]) << 32)
      | (static_cast<uint64_t>(p[cursor+5]) << 40)
      | (static_cast<uint64_t>(p[cursor+6]) << 48)
      | (static_cast<uint64_t>(p[cursor+7]) << 56);
    cursor += 8;
    return true;
}
static bool skipString(const uint8_t* p, uint64_t& cursor) {
    uint64_t len = 0;
    if (!readU64(p, cursor, len)) return false;
    cursor += len;
    return true;
}
static bool skipValue(const uint8_t* p, uint64_t& cursor, uint32_t type) {
    switch (type) {
    case 0: case 1: case 7: cursor += 1; return true;
    case 2: case 3: cursor += 2; return true;
    case 4: case 5: case 6: cursor += 4; return true;
    case 10: case 11: case 12: cursor += 8; return true;
    case 8: return skipString(p, cursor);
    case 9: {
        uint32_t et = 0; uint64_t n = 0;
        readU32(p, cursor, et); readU64(p, cursor, n);
        for (uint64_t i = 0; i < n; ++i) if (!skipValue(p, cursor, et)) return false;
        return true;
    }
    default: return false;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) { printf("Usage: gguf_type_probe <file.gguf>\n"); return 1; }

#ifdef _WIN32
    HANDLE h = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { printf("Open failed\n"); return 1; }
    LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
    HANDLE m = CreateFileMappingA(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    void* v = MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(h);
    const uint8_t* base = reinterpret_cast<const uint8_t*>(v);
    uint64_t fileSize = static_cast<uint64_t>(sz.QuadPart);
#else
    return 1;
#endif

    uint64_t cursor = 0;
    uint32_t magic = 0, version = 0;
    readU32(base, cursor, magic);
    readU32(base, cursor, version);
    printf("Magic=0x%08X Version=%u\n", magic, version);

    uint64_t tensorCount = 0, metaCount = 0;
    readU64(base, cursor, tensorCount);
    readU64(base, cursor, metaCount);
    printf("Tensors=%llu Metadata=%llu\n", tensorCount, metaCount);

    // Skip metadata
    for (uint64_t i = 0; i < metaCount; ++i) {
        skipString(base, cursor);
        uint32_t type = 0; readU32(base, cursor, type);
        skipValue(base, cursor, type);
    }

    // Align
    uint64_t align = 32;
    uint64_t pad = (align - (cursor % align)) % align;
    cursor += pad;
    printf("Data offset=%llu\n", cursor);

    // Read first 15 tensors
    for (uint64_t i = 0; i < std::min<uint64_t>(15, tensorCount); ++i) {
        std::string name;
        uint64_t nameLen = 0; readU64(base, cursor, nameLen);
        name.assign(reinterpret_cast<const char*>(base + cursor), nameLen);
        cursor += nameLen;
        uint32_t nDims = 0; readU32(base, cursor, nDims);
        for (uint32_t d = 0; d < nDims; ++d) { uint64_t dim = 0; readU64(base, cursor, dim); }
        uint32_t ggmlType = 0; readU32(base, cursor, ggmlType);
        uint64_t offset = 0; readU64(base, cursor, offset);
        printf("  %-40s | type=%u\n", name.c_str(), ggmlType);
    }

    // Count all types
    uint64_t tcursor = cursor;
    uint64_t counts[64] = {};
    for (uint64_t i = 0; i < tensorCount; ++i) {
        skipString(base, tcursor);
        uint32_t nDims = 0; readU32(base, tcursor, nDims);
        for (uint32_t d = 0; d < nDims; ++d) { uint64_t dim = 0; readU64(base, tcursor, dim); }
        uint32_t ggmlType = 0; readU32(base, tcursor, ggmlType);
        uint64_t offset = 0; readU64(base, tcursor, offset);
        if (ggmlType < 64) counts[ggmlType]++;
    }
    printf("\nType distribution:\n");
    for (int t = 0; t < 64; ++t) {
        if (counts[t]) printf("  type=%2d : %llu tensors\n", t, counts[t]);
    }

#ifdef _WIN32
    UnmapViewOfFile(v); CloseHandle(m);
#endif
    return 0;
}
