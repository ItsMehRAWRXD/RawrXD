// ============================================================================
// kimi_k2_probe.cpp — Full tensor dump for Kimi K2 GGUF analysis
// ============================================================================
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

static const char* ggmlTypeName(uint32_t t) {
    switch (t) {
        case 0:  return "F32";
        case 1:  return "F16";
        case 2:  return "Q4_0";
        case 3:  return "Q4_1";
        case 4:  return "Q4_2";
        case 5:  return "Q4_3";
        case 6:  return "Q5_0";
        case 7:  return "Q5_1";
        case 8:  return "Q8_0";
        case 9:  return "Q8_1";
        case 10: return "Q2_K";
        case 11: return "Q3_K";
        case 12: return "Q4_K";
        case 13: return "Q5_K";
        case 14: return "Q6_K";
        case 15: return "Q8_K";
        case 16: return "IQ2_XXS";
        case 17: return "IQ2_XS";
        case 18: return "IQ3_XXS";
        case 19: return "IQ1_S";
        case 20: return "IQ4_NL";
        case 21: return "IQ3_S";
        case 22: return "IQ2_S";
        case 23: return "IQ4_XS";
        case 24: return "I8";
        case 25: return "I16";
        case 26: return "I32";
        case 27: return "I64";
        case 28: return "F64";
        case 29: return "IQ1_M";
        case 30: return "BF16";
        case 31: return "Q4_0_4_4";
        case 32: return "Q4_0_4_8";
        case 33: return "Q4_0_8_8";
        default: return "UNKNOWN";
    }
}

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
static bool readString(const uint8_t* p, uint64_t& cursor, std::string& out) {
    uint64_t len = 0;
    if (!readU64(p, cursor, len)) return false;
    out.assign(reinterpret_cast<const char*>(p + cursor), len);
    cursor += len;
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

struct TensorInfo {
    std::string name;
    std::vector<uint64_t> dims;
    uint32_t type;
    uint64_t offset;
    uint64_t dataOffset;
};

int main(int argc, char** argv) {
    if (argc < 2) { printf("Usage: kimi_k2_probe <file.gguf>\n"); return 1; }

#ifdef _WIN32
    HANDLE h = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { printf("Open failed\n"); return 1; }
    LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
    uint64_t fileSize = static_cast<uint64_t>(sz.QuadPart);
    // Read first 8MB for header/metadata (avoids mapping 43GB file)
    // Data offset was ~6.9MB for this model
    const uint64_t kHeaderBufSize = 8 * 1024 * 1024;
    uint64_t headerReadSize = (fileSize < kHeaderBufSize) ? fileSize : kHeaderBufSize;
    std::vector<uint8_t> headerBuf(headerReadSize);
    DWORD readBytes = 0;
    if (!ReadFile(h, headerBuf.data(), static_cast<DWORD>(headerReadSize), &readBytes, nullptr)) {
        printf("ReadFile failed\n"); CloseHandle(h); return 1;
    }
    const uint8_t* base = headerBuf.data();
    // Keep file handle open for seeking later if needed
    // (not needed for this probe — tensor info is in header)
    CloseHandle(h);
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

    // Print metadata keys (first 30)
    printf("\n--- Metadata (first 30) ---\n");
    uint64_t metaCursor = cursor;
    for (uint64_t i = 0; i < std::min<uint64_t>(30, metaCount); ++i) {
        std::string key;
        readString(base, metaCursor, key);
        uint32_t type = 0; readU32(base, metaCursor, type);
        if (type == 8) {
            std::string val; readString(base, metaCursor, val);
            printf("  %-50s = \"%s\"\n", key.c_str(), val.c_str());
        } else if (type == 4 || type == 5 || type == 6) {
            uint32_t v32 = 0;
            readU32(base, metaCursor, v32);
            printf("  %-50s = %u\n", key.c_str(), v32);
        } else if (type == 10 || type == 11 || type == 12) {
            uint64_t v64 = 0;
            readU64(base, metaCursor, v64);
            printf("  %-50s = %llu\n", key.c_str(), v64);
        } else {
            skipValue(base, metaCursor, type);
        }
    }

    // Skip all metadata
    for (uint64_t i = 0; i < metaCount; ++i) {
        skipString(base, cursor);
        uint32_t type = 0; readU32(base, cursor, type);
        skipValue(base, cursor, type);
    }

    // Align
    uint64_t align = 32;
    uint64_t pad = (align - (cursor % align)) % align;
    cursor += pad;
    uint64_t dataOffset = cursor;
    printf("\nData offset=%llu\n", dataOffset);

    // Read all tensors
    std::vector<TensorInfo> tensors;
    tensors.reserve(tensorCount);
    for (uint64_t i = 0; i < tensorCount; ++i) {
        TensorInfo t{};
        readString(base, cursor, t.name);
        uint32_t nDims = 0; readU32(base, cursor, nDims);
        for (uint32_t d = 0; d < nDims; ++d) {
            uint64_t dim = 0; readU64(base, cursor, dim);
            t.dims.push_back(dim);
        }
        readU32(base, cursor, t.type);
        readU64(base, cursor, t.offset);
        t.dataOffset = dataOffset + t.offset;
        tensors.push_back(t);
    }

    // Print all tensors
    printf("\n--- All %llu tensors ---\n", tensorCount);
    printf("%-5s %-55s %-10s %-30s %-15s\n", "#", "Name", "Type", "Shape", "DataOffset");
    printf("-----------------------------------------------------------------------------------------------\n");
    for (size_t i = 0; i < tensors.size(); ++i) {
        const auto& t = tensors[i];
        std::string shapeStr;
        for (size_t d = 0; d < t.dims.size(); ++d) {
            if (d > 0) shapeStr += "x";
            shapeStr += std::to_string(t.dims[d]);
        }
        printf("%-5zu %-55s %-10s %-30s %-15llu\n", i, t.name.c_str(), ggmlTypeName(t.type), shapeStr.c_str(), t.dataOffset);
    }

    // Type distribution
    uint64_t counts[64] = {};
    for (const auto& t : tensors) {
        if (t.type < 64) counts[t.type]++;
    }
    printf("\n--- Type distribution ---\n");
    for (int t = 0; t < 64; ++t) {
        if (counts[t]) printf("  %-10s : %llu tensors\n", ggmlTypeName(t), counts[t]);
    }

    // Expert tensor analysis
    printf("\n--- Expert tensor analysis ---\n");
    int expertTensors = 0;
    int routerTensors = 0;
    int attnTensors = 0;
    int normTensors = 0;
    int embedTensors = 0;
    int otherTensors = 0;
    for (const auto& t : tensors) {
        if (t.name.find("ffn_experts") != std::string::npos) expertTensors++;
        else if (t.name.find("ffn_gate_inp") != std::string::npos) routerTensors++;
        else if (t.name.find("attn") != std::string::npos) attnTensors++;
        else if (t.name.find("norm") != std::string::npos || t.name.find("ln") != std::string::npos) normTensors++;
        else if (t.name.find("embd") != std::string::npos || t.name == "output.weight") embedTensors++;
        else otherTensors++;
    }
    printf("  Expert tensors (ffn_experts.*) : %d\n", expertTensors);
    printf("  Router tensors (ffn_gate_inp)  : %d\n", routerTensors);
    printf("  Attention tensors (attn_*)     : %d\n", attnTensors);
    printf("  Norm tensors (norm/ln_*)       : %d\n", normTensors);
    printf("  Embedding/output tensors       : %d\n", embedTensors);
    printf("  Other tensors                  : %d\n", otherTensors);

    // Find max expert ordinal
    int maxExpert = -1;
    for (const auto& t : tensors) {
        size_t pos = t.name.find("ffn_experts.");
        if (pos != std::string::npos) {
            int expNum = atoi(t.name.c_str() + pos + 12);
            if (expNum > maxExpert) maxExpert = expNum;
        }
    }
    printf("\n  Max expert ordinal found: %d\n", maxExpert);

    // List unique layer prefixes
    printf("\n--- Layer prefixes ---\n");
    std::vector<std::string> prefixes;
    for (const auto& t : tensors) {
        size_t dot = t.name.find('.');
        if (dot != std::string::npos) {
            std::string prefix = t.name.substr(0, dot);
            if (std::find(prefixes.begin(), prefixes.end(), prefix) == prefixes.end())
                prefixes.push_back(prefix);
        }
    }
    for (const auto& p : prefixes) {
        printf("  %s\n", p.c_str());
    }

#ifdef _WIN32
    // headerBuf auto-frees
#endif
    return 0;
}
