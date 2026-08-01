// ============================================================================
// model_loader_test.cpp — GGUF Geometry Parser & Structural Validator
// Phase 8: AI Runtime Evidence — VAL-090
//
// Parses raw GGUF binary headers, validates magic bytes, version, tensor
// metadata, and KV key-value store. No third-party dependencies.
//
// Compile:
//   g++ -O2 -std=c++17 model_loader_test.cpp -o model_loader_test.exe
//   cl /nologo /O2 /EHsc /std:c++17 model_loader_test.cpp
//
// Usage:
//   model_loader_test.exe <path/to/model.gguf>
// ============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>

// ============================================================================
// GGUF Specification v3 Constants
// ============================================================================
constexpr uint32_t GGUF_MAGIC = 0x46554747;  // "GGUF" little-endian

enum class GGUFValueType : uint32_t {
    UINT8   = 0,
    INT8    = 1,
    UINT16  = 2,
    INT16   = 3,
    UINT32  = 4,
    INT32   = 5,
    FLOAT32 = 6,
    BOOL    = 7,
    STRING  = 8,
    ARRAY   = 9,
    UINT64  = 10,
    INT64   = 11,
    FLOAT64 = 12
};

enum class GGUFTensorType : uint32_t {
    F32  = 0,
    F16  = 1,
    Q4_0 = 2,
    Q4_1 = 3,
    Q5_0 = 6,
    Q5_1 = 7,
    Q8_0 = 8,
    Q8_1 = 9,
    Q2_K = 10,
    Q3_K = 11,
    Q4_K = 12,
    Q5_K = 13,
    Q6_K = 14,
    Q8_K = 15,
    IQ1_S = 16,
    IQ2_XXS = 17,
    IQ2_XS = 18,
    IQ3_XXS = 19,
    IQ1_M = 20,
    IQ4_NL = 21,
    IQ3_S = 22,
    IQ2_S = 23,
    IQ4_XS = 24,
    I8    = 25,
    I16   = 26,
    I32   = 27,
    I64   = 28,
    F64   = 29,
    IQ1_S_EXT = 30,
    IQ2_XXS_EXT = 31,
    IQ2_XS_EXT = 32,
    IQ3_XXS_EXT = 33,
    IQ1_M_EXT = 34,
    IQ4_NL_EXT = 35,
    IQ3_S_EXT = 36,
    IQ2_S_EXT = 37,
    IQ4_XS_EXT = 38
};

// ============================================================================
// GGUF Header Structures
// ============================================================================
#pragma pack(push, 1)
struct GgufHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensorCount;
    uint64_t kvCount;
};

struct GgufString {
    uint64_t len;
    // char data[len] follows
};

struct GgufTensorInfo {
    uint64_t nameLen;
    // char name[nameLen] follows
    uint32_t nDims;
    uint64_t ne[4];
    uint32_t type;
    uint64_t offset;
    // name padding to 8-byte alignment
};
#pragma pack(pop)

// ============================================================================
// Tensor type name lookup
// ============================================================================
static const char* TensorTypeName(uint32_t type) {
    switch (static_cast<GGUFTensorType>(type)) {
        case GGUFTensorType::F32:  return "F32";
        case GGUFTensorType::F16:  return "F16";
        case GGUFTensorType::Q4_0: return "Q4_0";
        case GGUFTensorType::Q4_1: return "Q4_1";
        case GGUFTensorType::Q5_0: return "Q5_0";
        case GGUFTensorType::Q5_1: return "Q5_1";
        case GGUFTensorType::Q8_0: return "Q8_0";
        case GGUFTensorType::Q8_1: return "Q8_1";
        case GGUFTensorType::Q2_K: return "Q2_K";
        case GGUFTensorType::Q3_K: return "Q3_K";
        case GGUFTensorType::Q4_K: return "Q4_K";
        case GGUFTensorType::Q5_K: return "Q5_K";
        case GGUFTensorType::Q6_K: return "Q6_K";
        case GGUFTensorType::Q8_K: return "Q8_K";
        case GGUFTensorType::IQ1_S: return "IQ1_S";
        case GGUFTensorType::IQ2_XXS: return "IQ2_XXS";
        case GGUFTensorType::IQ2_XS: return "IQ2_XS";
        case GGUFTensorType::IQ3_XXS: return "IQ3_XXS";
        case GGUFTensorType::IQ1_M: return "IQ1_M";
        case GGUFTensorType::IQ4_NL: return "IQ4_NL";
        case GGUFTensorType::IQ3_S: return "IQ3_S";
        case GGUFTensorType::IQ2_S: return "IQ2_S";
        case GGUFTensorType::IQ4_XS: return "IQ4_XS";
        case GGUFTensorType::I8:    return "I8";
        case GGUFTensorType::I16:   return "I16";
        case GGUFTensorType::I32:   return "I32";
        case GGUFTensorType::I64:   return "I64";
        case GGUFTensorType::F64:   return "F64";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Read a GGUF string from file at current position
// ============================================================================
static std::string ReadGgufString(std::ifstream& f) {
    GgufString s;
    f.read(reinterpret_cast<char*>(&s.len), sizeof(s.len));
    std::string result;
    if (s.len > 0 && s.len < 65536) {
        result.resize(s.len);
        f.read(&result[0], s.len);
    }
    return result;
}

// ============================================================================
// Read a GGUF value (recursive for arrays)
// ============================================================================
static std::string ReadGgufValue(std::ifstream& f, GGUFValueType type, int depth = 0) {
    std::stringstream ss;
    if (depth > 10) return "<max depth>";

    switch (type) {
        case GGUFValueType::UINT8: {
            uint8_t v; f.read(reinterpret_cast<char*>(&v), sizeof(v));
            ss << (int)v; break;
        }
        case GGUFValueType::INT8: {
            int8_t v; f.read(reinterpret_cast<char*>(&v), sizeof(v));
            ss << (int)v; break;
        }
        case GGUFValueType::UINT16: {
            uint16_t v; f.read(reinterpret_cast<char*>(&v), sizeof(v));
            ss << v; break;
        }
        case GGUFValueType::INT16: {
            int16_t v; f.read(reinterpret_cast<char*>(&v), sizeof(v));
            ss << v; break;
        }
        case GGUFValueType::UINT32: {
            uint32_t v; f.read(reinterpret_cast<char*>(&v), sizeof(v));
            ss << v; break;
        }
        case GGUFValueType::INT32: {
            int32_t v; f.read(reinterpret_cast<char*>(&v), sizeof(v));
            ss << v; break;
        }
        case GGUFValueType::FLOAT32: {
            float v; f.read(reinterpret_cast<char*>(&v), sizeof(v));
            ss << v; break;
        }
        case GGUFValueType::BOOL: {
            uint8_t v; f.read(reinterpret_cast<char*>(&v), sizeof(v));
            ss << (v ? "true" : "false"); break;
        }
        case GGUFValueType::STRING: {
            ss << "\"" << ReadGgufString(f) << "\""; break;
        }
        case GGUFValueType::ARRAY: {
            uint32_t typeId; f.read(reinterpret_cast<char*>(&typeId), sizeof(typeId));
            uint64_t count;  f.read(reinterpret_cast<char*>(&count), sizeof(count));
            ss << "[";
            for (uint64_t i = 0; i < count && i < 8; i++) {
                if (i > 0) ss << ", ";
                ss << ReadGgufValue(f, static_cast<GGUFValueType>(typeId), depth + 1);
            }
            if (count > 8) ss << ", ...";
            ss << "]";
            break;
        }
        case GGUFValueType::UINT64: {
            uint64_t v; f.read(reinterpret_cast<char*>(&v), sizeof(v));
            ss << v; break;
        }
        case GGUFValueType::INT64: {
            int64_t v; f.read(reinterpret_cast<char*>(&v), sizeof(v));
            ss << v; break;
        }
        case GGUFValueType::FLOAT64: {
            double v; f.read(reinterpret_cast<char*>(&v), sizeof(v));
            ss << v; break;
        }
        default:
            ss << "<unknown type " << (int)type << ">";
    }
    return ss.str();
}

// ============================================================================
// Main — Parse and validate GGUF file
// ============================================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: model_loader_test.exe <path/to/model.gguf>\n";
        return 1;
    }

    const char* filePath = argv[1];

    // --- File metadata ---
    std::ifstream f(filePath, std::ios::binary);
    if (!f.is_open()) {
        std::cerr << "ERROR: Cannot open file: " << filePath << "\n";
        return 1;
    }

    f.seekg(0, std::ios::end);
    uint64_t fileSize = f.tellg();
    f.seekg(0, std::ios::beg);

    // --- Parse header ---
    GgufHeader header;
    f.read(reinterpret_cast<char*>(&header), sizeof(GgufHeader));

    if (!f) {
        std::cerr << "ERROR: Failed to read GGUF header\n";
        return 1;
    }

    // Validate magic
    if (header.magic != GGUF_MAGIC) {
        std::cerr << "ERROR: Invalid GGUF magic: 0x" << std::hex << header.magic
                  << " (expected 0x" << GGUF_MAGIC << ")\n";
        return 1;
    }

    std::cout << "============================================================\n";
    std::cout << "  GGUF Model Geometry Validator\n";
    std::cout << "============================================================\n";
    std::cout << "  File:           " << filePath << "\n";
    std::cout << "  Size:           " << fileSize << " bytes ("
              << (fileSize / (1024*1024)) << " MB)\n";
    std::cout << "  GGUF Version:   v" << header.version << "\n";
    std::cout << "  Tensors:        " << header.tensorCount << "\n";
    std::cout << "  KV Pairs:       " << header.kvCount << "\n";
    std::cout << "  Magic:          0x" << std::hex << header.magic
              << " (valid)\n" << std::dec;

    // --- Parse KV pairs ---
    std::cout << "\n--- Metadata KV Store ---\n";
    std::string archName;
    uint32_t contextLength = 0;
    uint32_t embeddingLength = 0;
    uint32_t blockCount = 0;
    uint32_t headCount = 0;
    uint32_t headCountKV = 0;
    uint32_t vocabSize = 0;

    for (uint64_t i = 0; i < header.kvCount; i++) {
        std::string key = ReadGgufString(f);
        uint32_t typeId;
        f.read(reinterpret_cast<char*>(&typeId), sizeof(typeId));
        auto type = static_cast<GGUFValueType>(typeId);
        std::string value = ReadGgufValue(f, type);

        std::cout << "    " << std::setw(32) << std::left << key
                  << " = " << value << "\n";

        // Capture key metadata
        if (key == "general.architecture") {
            // Strip quotes
            if (value.size() >= 2) archName = value.substr(1, value.size() - 2);
        } else if (key == "llama.context_length") {
            contextLength = static_cast<uint32_t>(std::stoull(value));
        } else if (key == "llama.embedding_length") {
            embeddingLength = static_cast<uint32_t>(std::stoull(value));
        } else if (key == "llama.block_count") {
            blockCount = static_cast<uint32_t>(std::stoull(value));
        } else if (key == "llama.attention.head_count") {
            headCount = static_cast<uint32_t>(std::stoull(value));
        } else if (key == "llama.attention.head_count_kv") {
            headCountKV = static_cast<uint32_t>(std::stoull(value));
        } else if (key == "llama.vocab_size") {
            vocabSize = static_cast<uint32_t>(std::stoull(value));
        }
    }

    // --- Parse tensor info ---
    std::cout << "\n--- Tensor Inventory ---\n";

    struct TensorEntry {
        std::string name;
        uint32_t nDims;
        uint64_t ne[4];
        uint32_t type;
        uint64_t offset;
        uint64_t sizeBytes;
    };
    std::vector<TensorEntry> tensors;
    tensors.reserve(header.tensorCount);

    uint64_t totalWeightBytes = 0;
    uint64_t maxTensorSize = 0;
    std::string maxTensorName;

    for (uint64_t i = 0; i < header.tensorCount; i++) {
        TensorEntry t;
        t.name = ReadGgufString(f);

        // Align to 8 bytes
        uint64_t pos = f.tellg();
        uint64_t aligned = (pos + 7) & ~7ULL;
        if (aligned != pos) {
            f.seekg(aligned);
        }

        f.read(reinterpret_cast<char*>(&t.nDims), sizeof(t.nDims));
        for (uint32_t d = 0; d < 4; d++) {
            t.ne[d] = 0;
        }
        f.read(reinterpret_cast<char*>(t.ne), sizeof(uint64_t) * t.nDims);
        f.read(reinterpret_cast<char*>(&t.type), sizeof(t.type));
        f.read(reinterpret_cast<char*>(&t.offset), sizeof(t.offset));

        // Calculate size (approximate for quantized)
        uint64_t elements = 1;
        for (uint32_t d = 0; d < t.nDims; d++) elements *= t.ne[d];

        // Size per element type
        switch (static_cast<GGUFTensorType>(t.type)) {
            case GGUFTensorType::F32:  t.sizeBytes = elements * 4; break;
            case GGUFTensorType::F16:  t.sizeBytes = elements * 2; break;
            case GGUFTensorType::Q4_0: t.sizeBytes = (elements * 4 + 31) / 32 * 20; break;
            case GGUFTensorType::Q4_1: t.sizeBytes = (elements * 4 + 31) / 32 * 24; break;
            case GGUFTensorType::Q5_0: t.sizeBytes = (elements * 4 + 31) / 32 * 28; break;
            case GGUFTensorType::Q5_1: t.sizeBytes = (elements * 4 + 31) / 32 * 32; break;
            case GGUFTensorType::Q8_0: t.sizeBytes = (elements * 4 + 31) / 32 * 36; break;
            case GGUFTensorType::Q2_K: t.sizeBytes = (elements * 4 + 255) / 256 * 80; break;
            case GGUFTensorType::Q3_K: t.sizeBytes = (elements * 4 + 255) / 256 * 104; break;
            case GGUFTensorType::Q4_K: t.sizeBytes = (elements * 4 + 255) / 256 * 144; break;
            case GGUFTensorType::Q5_K: t.sizeBytes = (elements * 4 + 255) / 256 * 176; break;
            case GGUFTensorType::Q6_K: t.sizeBytes = (elements * 4 + 255) / 256 * 208; break;
            default:                    t.sizeBytes = elements * 4; break;
        }

        totalWeightBytes += t.sizeBytes;
        if (t.sizeBytes > maxTensorSize) {
            maxTensorSize = t.sizeBytes;
            maxTensorName = t.name;
        }

        tensors.push_back(t);

        // Print first 10 and last 5
        if (i < 10 || i >= header.tensorCount - 5) {
            std::cout << "    [" << std::setw(4) << i << "] "
                      << std::setw(36) << std::left << t.name
                      << " dims=" << t.nDims
                      << " type=" << std::setw(8) << std::left << TensorTypeName(t.type)
                      << " size=" << (t.sizeBytes / 1024) << " KB"
                      << " offset=0x" << std::hex << t.offset << std::dec << "\n";
        } else if (i == 10) {
            std::cout << "    ... (" << (header.tensorCount - 15) << " more tensors) ...\n";
        }
    }

    // --- Model summary ---
    std::cout << "\n--- Model Architecture Summary ---\n";
    std::cout << "  Architecture:   " << (archName.empty() ? "unknown" : archName) << "\n";
    std::cout << "  Context Length: " << contextLength << "\n";
    std::cout << "  Embedding Dim:  " << embeddingLength << "\n";
    std::cout << "  Block Count:    " << blockCount << "\n";
    std::cout << "  Head Count:     " << headCount << "\n";
    if (headCountKV > 0) std::cout << "  Head Count KV: " << headCountKV << "\n";
    std::cout << "  Vocab Size:     " << vocabSize << "\n";
    std::cout << "  Total Tensors:  " << tensors.size() << "\n";
    std::cout << "  Weight Data:    " << (totalWeightBytes / (1024*1024)) << " MB\n";
    std::cout << "  Largest Tensor: " << maxTensorName << " ("
              << (maxTensorSize / (1024*1024)) << " MB)\n";

    // --- Validation ---
    std::cout << "\n--- Validation ---\n";
    bool valid = true;

    if (header.magic != GGUF_MAGIC) {
        std::cout << "  ❌ Invalid GGUF magic\n";
        valid = false;
    }
    if (header.version < 1 || header.version > 3) {
        std::cout << "  ⚠ Unusual GGUF version: " << header.version << "\n";
    }
    if (header.tensorCount == 0) {
        std::cout << "  ❌ No tensors declared\n";
        valid = false;
    }
    if (totalWeightBytes == 0) {
        std::cout << "  ❌ Zero weight data\n";
        valid = false;
    }
    if (embeddingLength == 0 && blockCount > 0) {
        std::cout << "  ⚠ embedding_length not found in metadata\n";
    }

    std::cout << "  Result: " << (valid ? "✅ PASS" : "❌ FAIL") << "\n";

    // --- JSON output for certification pipeline ---
    std::cout << "\n--- JSON ---\n";
    std::cout << "{\n";
    std::cout << "  \"model\": {\n";
    std::cout << "    \"artifact\": \"" << filePath << "\",\n";
    std::cout << "    \"sizeBytes\": " << fileSize << ",\n";
    std::cout << "    \"ggufVersion\": " << header.version << ",\n";
    std::cout << "    \"architecture\": \"" << archName << "\",\n";
    std::cout << "    \"quantization\": \""
              << (tensors.empty() ? "unknown" : TensorTypeName(tensors[0].type)) << "\",\n";
    std::cout << "    \"tensors\": " << header.tensorCount << ",\n";
    std::cout << "    \"weightDataMB\": " << (totalWeightBytes / (1024*1024)) << ",\n";
    std::cout << "    \"contextLength\": " << contextLength << ",\n";
    std::cout << "    \"embeddingDim\": " << embeddingLength << ",\n";
    std::cout << "    \"blockCount\": " << blockCount << ",\n";
    std::cout << "    \"headCount\": " << headCount << ",\n";
    std::cout << "    \"vocabSize\": " << vocabSize << "\n";
    std::cout << "  },\n";
    std::cout << "  \"validation\": \"" << (valid ? "PASS" : "FAIL") << "\"\n";
    std::cout << "}\n";

    f.close();
    return valid ? 0 : 1;
}
