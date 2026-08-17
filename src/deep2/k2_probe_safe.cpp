// ============================================================================
// k2_probe_safe.cpp — Memory-safe GGUF tensor probe for Kimi K2
// Uses Windows memory mapping (only maps header region, NOT tensor data)
// Safe for 43GB+ files on systems with limited RAM
//
// Build: cl /O2 /EHsc k2_probe_safe.cpp /Fe:k2_probe_safe.exe
// Run:   k2_probe_safe.exe "F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf"
// ============================================================================
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>

// ============================================================================
// GGUF Constants
// ============================================================================
static constexpr uint32_t GGUF_MAGIC = 0x46554747; // "GGUF"
static constexpr uint32_t GGUF_VERSION = 3;

// GGUF value types
static constexpr uint32_t GGUF_TYPE_UINT8   = 0;
static constexpr uint32_t GGUF_TYPE_INT8    = 1;
static constexpr uint32_t GGUF_TYPE_UINT16  = 2;
static constexpr uint32_t GGUF_TYPE_INT16   = 3;
static constexpr uint32_t GGUF_TYPE_UINT32  = 4;
static constexpr uint32_t GGUF_TYPE_INT32   = 5;
static constexpr uint32_t GGUF_TYPE_FLOAT32 = 6;
static constexpr uint32_t GGUF_TYPE_BOOL    = 7;
static constexpr uint32_t GGUF_TYPE_STRING  = 8;
static constexpr uint32_t GGUF_TYPE_ARRAY   = 9;
static constexpr uint32_t GGUF_TYPE_UINT64  = 10;
static constexpr uint32_t GGUF_TYPE_INT64   = 11;
static constexpr uint32_t GGUF_TYPE_FLOAT64 = 12;

// GGML types
static constexpr uint32_t GGML_TYPE_F32     = 0;
static constexpr uint32_t GGML_TYPE_F16     = 1;
static constexpr uint32_t GGML_TYPE_Q4_0   = 2;
static constexpr uint32_t GGML_TYPE_Q4_1   = 3;
static constexpr uint32_t GGML_TYPE_Q5_0   = 6;
static constexpr uint32_t GGML_TYPE_Q5_1   = 7;
static constexpr uint32_t GGML_TYPE_Q8_0   = 8;
static constexpr uint32_t GGML_TYPE_Q8_K    = 14;
static constexpr uint32_t GGML_TYPE_Q2_K   = 15;
static constexpr uint32_t GGML_TYPE_Q3_K   = 16;
static constexpr uint32_t GGML_TYPE_Q4_K    = 17;
static constexpr uint32_t GGML_TYPE_Q5_K    = 18;
static constexpr uint32_t GGML_TYPE_Q6_K    = 19;
static constexpr uint32_t GGML_TYPE_IQ2_XXS = 20;
static constexpr uint32_t GGML_TYPE_IQ2_XS  = 21;
static constexpr uint32_t GGML_TYPE_IQ3_XXS = 22;
static constexpr uint32_t GGML_TYPE_IQ1_S    = 23;
static constexpr uint32_t GGML_TYPE_IQ4_NL  = 24;
static constexpr uint32_t GGML_TYPE_IQ3_S   = 25;
static constexpr uint32_t GGML_TYPE_IQ2_S   = 26;
static constexpr uint32_t GGML_TYPE_IQ4_XS   = 27;
static constexpr uint32_t GGML_TYPE_BF16    = 30;

// ============================================================================
// GGML Type Info — block sizes and bytes per block
// ============================================================================
struct GGMLTypeInfo {
    const char* name;
    uint32_t blockSize;      // Elements per block
    uint32_t blockSizeBytes; // Bytes per block
    float bytesPerElement;   // Approximate
};

static const GGMLTypeInfo kGGMLTypeInfo[] = {
    /*  0 */ {"F32",     1,   4, 4.0f},
    /*  1 */ {"F16",     1,   2, 2.0f},
    /*  2 */ {"Q4_0",   32,  18, 0.5625f},
    /*  3 */ {"Q4_1",   32,  20, 0.625f},
    /*  4 */ {"Q4_2",   32,  18, 0.5625f},  // deprecated
    /*  5 */ {"Q4_3",   32,  20, 0.625f},  // deprecated
    /*  6 */ {"Q5_0",   32,  22, 0.6875f},
    /*  7 */ {"Q5_1",   32,  24, 0.75f},
    /*  8 */ {"Q8_0",   32,  34, 1.0625f},
    /*  9 */ {"Q8_1",   32,  36, 1.125f},  // deprecated
    /* 10 */ {"Q2_K",   256, 32+256/16+256/4, 0.375f},  // approx
    /* 11 */ {"Q3_K",   256, 32+256/8+256/4, 0.4375f},  // approx
    /* 12 */ {"Q4_K",   256, 12+256/2, 0.5f},           // approx
    /* 13 */ {"Q5_K",   256, 12+256/8+256/2, 0.625f},   // approx
    /* 14 */ {"Q6_K",   256, 256/2+256/4+256/16+2, 0.75f}, // approx
    /* 15 */ {"Q8_K",   256, 32+256, 1.125f},           // approx
    /* 16 */ {"IQ2_XXS", 256, 66, 0.258f},               // approx
    /* 17 */ {"IQ2_XS",  256, 70, 0.273f},               // approx
    /* 18 */ {"IQ3_XXS", 256, 74, 0.289f},               // approx
    /* 19 */ {"IQ1_S",   256, 50, 0.195f},               // approx
    /* 20 */ {"IQ4_NL",  32,  18, 0.5625f},              // approx
    /* 21 */ {"IQ4_XS",  256, 76, 0.297f},               // approx
    /* 22 */ {"IQ3_S",   256, 78, 0.305f},               // approx
    /* 23 */ {"IQ2_S",   256, 80, 0.3125f},              // approx
    /* 24 */ {"BF16",    1,   2, 2.0f},
};

static const char* GGMLTypeName(uint32_t type) {
    if (type < sizeof(kGGMLTypeInfo)/sizeof(kGGMLTypeInfo[0])) {
        return kGGMLTypeInfo[type].name;
    }
    return "UNKNOWN";
}

static uint64_t ComputeTensorByteSize(uint32_t ggmlType, const std::vector<uint64_t>& dims) {
    if (ggmlType >= sizeof(kGGMLTypeInfo)/sizeof(kGGMLTypeInfo[0])) {
        return 0; // Unknown type
    }
    const auto& info = kGGMLTypeInfo[ggmlType];
    uint64_t numElements = 1;
    for (auto d : dims) numElements *= d;
    uint64_t numBlocks = (numElements + info.blockSize - 1) / info.blockSize;
    return numBlocks * info.blockSizeBytes;
}

// ============================================================================
// Safe memory-mapped file reader
// ============================================================================
class MappedFileView {
public:
    MappedFileView() = default;
    ~MappedFileView() { Close(); }

    bool Open(const wchar_t* path, uint64_t maxViewSize = 16 * 1024 * 1024) {
        hFile_ = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile_ == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "Failed to open file\n");
            return false;
        }

        LARGE_INTEGER size;
        if (!GetFileSizeEx(hFile_, &size)) {
            fprintf(stderr, "Failed to get file size\n");
            Close();
            return false;
        }
        fileSize_ = size.QuadPart;

        hMapping_ = CreateFileMapping(hFile_, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMapping_) {
            fprintf(stderr, "Failed to create file mapping\n");
            Close();
            return false;
        }

        // Map only the first maxViewSize bytes (header + metadata + tensor info)
        uint64_t viewSize = std::min(maxViewSize, fileSize_);
        base_ = MapViewOfFile(hMapping_, FILE_MAP_READ, 0, 0, static_cast<SIZE_T>(viewSize));
        if (!base_) {
            fprintf(stderr, "Failed to map view\n");
            Close();
            return false;
        }

        mappedSize_ = viewSize;
        return true;
    }

    void Close() {
        if (base_) { UnmapViewOfFile(base_); base_ = nullptr; }
        if (hMapping_) { CloseHandle(hMapping_); hMapping_ = nullptr; }
        if (hFile_ != INVALID_HANDLE_VALUE) { CloseHandle(hFile_); hFile_ = INVALID_HANDLE_VALUE; }
    }

    const uint8_t* Data() const { return static_cast<const uint8_t*>(base_); }
    uint64_t MappedSize() const { return mappedSize_; }
    uint64_t FileSize() const { return fileSize_; }

private:
    HANDLE hFile_ = INVALID_HANDLE_VALUE;
    HANDLE hMapping_ = nullptr;
    void* base_ = nullptr;
    uint64_t mappedSize_ = 0;
    uint64_t fileSize_ = 0;
};

// ============================================================================
// Binary reader from mapped view
// ============================================================================
struct BinaryReader {
    const uint8_t* data = nullptr;
    uint64_t size = 0;
    uint64_t pos = 0;

    bool CanRead(uint64_t bytes) const { return pos + bytes <= size; }

    uint8_t ReadU8() {
        if (!CanRead(1)) return 0;
        return data[pos++];
    }

    uint32_t ReadU32() {
        if (!CanRead(4)) return 0;
        uint32_t v = *reinterpret_cast<const uint32_t*>(data + pos);
        pos += 4;
        return v;
    }

    uint64_t ReadU64() {
        if (!CanRead(8)) return 0;
        uint64_t v = *reinterpret_cast<const uint64_t*>(data + pos);
        pos += 8;
        return v;
    }

    float ReadF32() {
        if (!CanRead(4)) return 0.0f;
        float v = *reinterpret_cast<const float*>(data + pos);
        pos += 4;
        return v;
    }

    std::string ReadString() {
        uint64_t len = ReadU64();
        if (len == 0 || !CanRead(len)) return "";
        std::string s(reinterpret_cast<const char*>(data + pos), len);
        pos += len;
        return s;
    }

    void SkipValue(uint32_t type);
};

void BinaryReader::SkipValue(uint32_t type) {
    switch (type) {
        case GGUF_TYPE_UINT8:  pos += 1; break;
        case GGUF_TYPE_INT8:   pos += 1; break;
        case GGUF_TYPE_UINT16: pos += 2; break;
        case GGUF_TYPE_INT16:  pos += 2; break;
        case GGUF_TYPE_UINT32: pos += 4; break;
        case GGUF_TYPE_INT32:  pos += 4; break;
        case GGUF_TYPE_FLOAT32:pos += 4; break;
        case GGUF_TYPE_BOOL:   pos += 1; break;
        case GGUF_TYPE_UINT64: pos += 8; break;
        case GGUF_TYPE_INT64:  pos += 8; break;
        case GGUF_TYPE_FLOAT64:pos += 8; break;
        case GGUF_TYPE_STRING: {
            uint64_t len = ReadU64();
            pos += len;
            break;
        }
        case GGUF_TYPE_ARRAY: {
            uint32_t arrType = ReadU32();
            uint64_t arrCount = ReadU64();
            for (uint64_t i = 0; i < arrCount; ++i) {
                SkipValue(arrType);
            }
            break;
        }
        default:
            break;
    }
}

// ============================================================================
// Tensor Info
// ============================================================================
struct TensorInfo {
    uint32_t index = 0;
    std::string name;
    uint32_t nDims = 0;
    std::vector<uint64_t> dims;
    uint32_t ggmlType = 0;
    uint64_t relOffset = 0;      // Relative to data section start
    uint64_t absOffset = 0;      // Absolute file offset
    uint64_t byteSize = 0;       // Computed from GGML type + dims
    uint64_t endOffset = 0;      // absOffset + byteSize
};

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: k2_probe_safe.exe <gguf_file>\n");
        return 1;
    }

    // Convert UTF-8 path to wide char for Windows API
    const char* pathUtf8 = argv[1];
    int wlen = MultiByteToWideChar(CP_UTF8, 0, pathUtf8, -1, nullptr, 0);
    std::vector<wchar_t> pathW(wlen);
    MultiByteToWideChar(CP_UTF8, 0, pathUtf8, -1, pathW.data(), wlen);
    const wchar_t* path = pathW.data();

    printf("=====================================================================\n");
    printf("Kimi K2 Safe GGUF Tensor Probe (memory-mapped header only)\n");
    printf("=====================================================================\n\n");

    MappedFileView file;
    if (!file.Open(path, 32 * 1024 * 1024)) { // Map first 32MB (safe)
        fprintf(stderr, "Failed to open/mmap file\n");
        return 1;
    }

    printf("File size: %llu bytes (%.2f GB)\n", file.FileSize(), file.FileSize() / (1024.0 * 1024 * 1024));
    printf("Mapped view: %llu bytes (%.2f MB)\n\n", file.MappedSize(), file.MappedSize() / (1024.0 * 1024));

    BinaryReader r;
    r.data = file.Data();
    r.size = file.MappedSize();

    // --- Header ---
    // GGUF v3 header: magic[4] + version[4] + n_tensors[8] + n_metadata[8] = 24 bytes
    uint32_t magic = r.ReadU32();
    if (magic != GGUF_MAGIC) {
        fprintf(stderr, "Invalid GGUF magic: 0x%08X (expected 0x%08X)\n", magic, GGUF_MAGIC);
        return 1;
    }

    uint32_t version = r.ReadU32();
    uint64_t nTensors = r.ReadU64();    // GGUF v2/v3: uint64
    uint64_t nMetadata = r.ReadU64();   // GGUF v2/v3: uint64

    printf("GGUF Magic:     0x%08X ('GGUF')\n", magic);
    printf("Version:        %u\n", version);
    printf("Tensors:        %llu\n", nTensors);
    printf("Metadata:       %llu\n\n", nMetadata);

    // --- Metadata ---
    printf("--- Metadata (first 20 keys) ---\n");
    uint64_t metadataStart = r.pos;
    int metaPrinted = 0;
    for (uint64_t i = 0; i < nMetadata; ++i) {
        uint64_t keyStart = r.pos;
        std::string key = r.ReadString();
        uint32_t valType = r.ReadU32();

        // Capture important values
        std::string valStr;
        if (valType == GGUF_TYPE_UINT32) {
            uint32_t v = r.ReadU32();
            valStr = std::to_string(v);
        } else if (valType == GGUF_TYPE_INT32) {
            int32_t v = static_cast<int32_t>(r.ReadU32());
            valStr = std::to_string(v);
        } else if (valType == GGUF_TYPE_FLOAT32) {
            float v = r.ReadF32();
            char buf[64];
            snprintf(buf, sizeof(buf), "%.6f", v);
            valStr = buf;
        } else if (valType == GGUF_TYPE_STRING) {
            valStr = r.ReadString();
        } else if (valType == GGUF_TYPE_UINT64) {
            uint64_t v = r.ReadU64();
            valStr = std::to_string(v);
        } else {
            r.SkipValue(valType);
            valStr = "<complex>";
        }

        if (metaPrinted < 20) {
            printf("  %-40s = %s\n", key.c_str(), valStr.c_str());
            metaPrinted++;
        }
    }
    uint64_t metadataEnd = r.pos;
    printf("  ... (%llu total metadata entries)\n", nMetadata);
    printf("  Metadata region: %llu - %llu (%llu bytes)\n\n",
           metadataStart, metadataEnd, metadataEnd - metadataStart);

    // --- Tensor Info Table ---
    printf("--- Tensor Info Table ---\n");
    uint64_t tensorInfoStart = r.pos;
    std::vector<TensorInfo> tensors;
    tensors.reserve(static_cast<size_t>(nTensors));

    for (uint64_t i = 0; i < nTensors; ++i) {
        TensorInfo t;
        t.index = i;
        t.name = r.ReadString();
        t.nDims = r.ReadU32();
        t.dims.resize(t.nDims);
        for (uint32_t d = 0; d < t.nDims; ++d) {
            t.dims[d] = r.ReadU64();
        }
        t.ggmlType = r.ReadU32();
        t.relOffset = r.ReadU64();
        tensors.push_back(t);
    }

    uint64_t tensorInfoEnd = r.pos;
    uint64_t dataOffset = tensorInfoEnd;
    // Align to 32 bytes (GGUF default alignment)
    dataOffset = (dataOffset + 31) & ~31ULL;

    printf("Tensor info start: %llu\n", tensorInfoStart);
    printf("Tensor info end:   %llu\n", tensorInfoEnd);
    printf("Data offset:       %llu\n", dataOffset);
    printf("Tensor info size:  %llu bytes\n\n", tensorInfoEnd - tensorInfoStart);

    // Compute absolute offsets and sizes
    for (auto& t : tensors) {
        t.absOffset = dataOffset + t.relOffset;
        t.byteSize = ComputeTensorByteSize(t.ggmlType, t.dims);
        t.endOffset = t.absOffset + t.byteSize;
    }

    // --- Print all tensors ---
    printf("--- All %llu Tensors ---\n", nTensors);
    printf("%-6s %-45s %-10s %-20s %-12s %-12s %-12s %-12s\n",
           "Idx", "Name", "Type", "Shape", "RelOff", "AbsOff", "Size", "End");
    printf("------------------------------------------------------------------------------------------------------------------------\n");

    for (const auto& t : tensors) {
        std::string shapeStr;
        for (size_t i = 0; i < t.dims.size(); ++i) {
            if (i > 0) shapeStr += "x";
            shapeStr += std::to_string(t.dims[i]);
        }

        printf("%-6u %-45s %-10s %-20s %-12llu %-12llu %-12llu %-12llu\n",
               t.index, t.name.c_str(), GGMLTypeName(t.ggmlType),
               shapeStr.c_str(), t.relOffset, t.absOffset, t.byteSize, t.endOffset);
    }

    // --- Boundary validation ---
    printf("\n--- Boundary Validation ---\n");
    bool boundariesOk = true;
    for (size_t i = 1; i < tensors.size(); ++i) {
        const auto& prev = tensors[i-1];
        const auto& curr = tensors[i];
        if (prev.endOffset > curr.absOffset) {
            printf("OVERLAP: tensor %zu (%s) ends at %llu, tensor %zu (%s) starts at %llu\n",
                   i-1, prev.name.c_str(), prev.endOffset,
                   i, curr.name.c_str(), curr.absOffset);
            boundariesOk = false;
        }
    }

    // Check last tensor fits in file
    if (!tensors.empty()) {
        const auto& last = tensors.back();
        if (last.endOffset > file.FileSize()) {
            printf("OVERFLOW: last tensor (%s) ends at %llu, file size is %llu\n",
                   last.name.c_str(), last.endOffset, file.FileSize());
            boundariesOk = false;
        }
    }

    if (boundariesOk) {
        printf("All tensor boundaries valid (no overlaps, no overflow)\n");
    }

    // --- Summary statistics ---
    printf("\n--- Summary ---\n");
    uint64_t totalTensorBytes = 0;
    std::unordered_map<std::string, uint32_t> typeCounts;
    for (const auto& t : tensors) {
        totalTensorBytes += t.byteSize;
        typeCounts[GGMLTypeName(t.ggmlType)]++;
    }

    printf("Total tensor data: %llu bytes (%.2f GB)\n", totalTensorBytes, totalTensorBytes / (1024.0 * 1024 * 1024));
    printf("File size:         %llu bytes (%.2f GB)\n", file.FileSize(), file.FileSize() / (1024.0 * 1024 * 1024));
    printf("Overhead:          %.2f%%\n", 100.0 * (1.0 - (double)totalTensorBytes / file.FileSize()));

    printf("\nQuantization breakdown:\n");
    for (const auto& [name, count] : typeCounts) {
        printf("  %-10s: %u tensors\n", name.c_str(), count);
    }

    // --- Expert tensor identification ---
    printf("\n--- Expert Tensors (3D) ---\n");
    for (const auto& t : tensors) {
        if (t.nDims == 3 && t.name.find("_exps") != std::string::npos) {
            printf("  %-45s shape=%s type=%s size=%.2f MB\n",
                   t.name.c_str(),
                   [](const std::vector<uint64_t>& d) {
                       std::string s;
                       for (size_t i = 0; i < d.size(); ++i) {
                           if (i) s += "x";
                           s += std::to_string(d[i]);
                       }
                       return s;
                   }(t.dims).c_str(),
                   GGMLTypeName(t.ggmlType),
                   t.byteSize / (1024.0 * 1024));
        }
    }

    printf("\n=====================================================================\n");
    printf("Probe complete. No tensor data was loaded into RAM.\n");
    printf("=====================================================================\n");

    return 0;
}
