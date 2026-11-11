// Quick GGUF inspector - dumps metadata and tensor names
// Build: cl /EHsc /O2 /std:c++20 inspect_gguf.cpp /Fe:inspect_gguf.exe

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <algorithm>

// GGUF magic and constants
static const uint32_t GGUF_MAGIC = 0x46554747; // "GGUF"
static const uint32_t GGUF_VERSION = 3;

enum class GGUFType : uint32_t {
    UINT8 = 0, INT8 = 1, UINT16 = 2, INT16 = 3, UINT32 = 4, INT32 = 5,
    FLOAT32 = 6, BOOL = 7, STRING = 8, ARRAY = 9, UINT64 = 10, INT64 = 11,
    FLOAT64 = 12
};

struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};

struct GGUFMetadataKV {
    std::string key;
    GGUFType type;
    std::vector<uint8_t> value;
};

struct GGUFTensorInfo {
    std::string name;
    uint32_t n_dims;
    uint64_t dims[4];
    uint32_t type;
    uint64_t offset;
};

std::string readString(std::ifstream& f) {
    uint64_t len;
    f.read(reinterpret_cast<char*>(&len), sizeof(len));
    std::string s(len, '\0');
    f.read(s.data(), len);
    return s;
}

uint64_t readU64(std::ifstream& f) {
    uint64_t v;
    f.read(reinterpret_cast<char*>(&v), sizeof(v));
    return v;
}

uint32_t readU32(std::ifstream& f) {
    uint32_t v;
    f.read(reinterpret_cast<char*>(&v), sizeof(v));
    return v;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <gguf_file>\n", argv[0]);
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary);
    if (!file) {
        printf("Failed to open: %s\n", argv[1]);
        return 1;
    }

    // Read header
    GGUFHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    if (header.magic != GGUF_MAGIC) {
        printf("Invalid GGUF magic: 0x%08X (expected 0x%08X)\n", header.magic, GGUF_MAGIC);
        return 1;
    }

    printf("╔═══════════════════════════════════════════════════════════════════╗\n");
    printf("║                    GGUF Inspector                               ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════╝\n\n");
    printf("Magic:    0x%08X (GGUF)\n", header.magic);
    printf("Version:  %u\n", header.version);
    printf("Tensors:  %llu\n", header.tensor_count);
    printf("Metadata: %llu KV pairs\n\n", header.metadata_kv_count);

    // Read metadata
    printf("═══════════════════════════════════════════════════════════════════\n");
    printf("METADATA:\n");
    printf("═══════════════════════════════════════════════════════════════════\n");

    for (uint64_t i = 0; i < header.metadata_kv_count; i++) {
        std::string key = readString(file);
        uint32_t type_val;
        file.read(reinterpret_cast<char*>(&type_val), sizeof(type_val));
        GGUFType type = static_cast<GGUFType>(type_val);

        printf("  %s = ", key.c_str());

        switch (type) {
            case GGUFType::UINT32: {
                uint32_t v = readU32(file);
                printf("%u (uint32)\n", v);
                break;
            }
            case GGUFType::INT32: {
                int32_t v;
                file.read(reinterpret_cast<char*>(&v), sizeof(v));
                printf("%d (int32)\n", v);
                break;
            }
            case GGUFType::FLOAT32: {
                float v;
                file.read(reinterpret_cast<char*>(&v), sizeof(v));
                printf("%.4f (float32)\n", v);
                break;
            }
            case GGUFType::STRING: {
                std::string v = readString(file);
                if (v.length() > 80) {
                    printf("\"%.77s...\" (string, %zu chars)\n", v.c_str(), v.length());
                } else {
                    printf("\"%s\" (string)\n", v.c_str());
                }
                break;
            }
            case GGUFType::BOOL: {
                uint8_t v;
                file.read(reinterpret_cast<char*>(&v), sizeof(v));
                printf("%s (bool)\n", v ? "true" : "false");
                break;
            }
            case GGUFType::UINT64: {
                uint64_t v = readU64(file);
                printf("%llu (uint64)\n", v);
                break;
            }
            case GGUFType::INT64: {
                int64_t v;
                file.read(reinterpret_cast<char*>(&v), sizeof(v));
                printf("%lld (int64)\n", v);
                break;
            }
            case GGUFType::ARRAY: {
                uint32_t arr_type;
                file.read(reinterpret_cast<char*>(&arr_type), sizeof(arr_type));
                uint64_t arr_len = readU64(file);
                printf("[array of %llu items, type=%u]\n", arr_len, arr_type);
                // Skip array data
                for (uint64_t j = 0; j < arr_len; j++) {
                    if (arr_type == static_cast<uint32_t>(GGUFType::STRING)) {
                        std::string s = readString(file);
                    } else if (arr_type == static_cast<uint32_t>(GGUFType::UINT32)) {
                        uint32_t v = readU32(file);
                    } else {
                        // Skip other types
                        file.seekg(8, std::ios::cur);
                    }
                }
                break;
            }
            default: {
                printf("[type=%u, skipping...]\n", type_val);
                // Skip unknown
                file.seekg(8, std::ios::cur);
            }
        }
    }

    // Read tensor info
    printf("\n═══════════════════════════════════════════════════════════════════\n");
    printf("TENSOR INFO (first 50):\n");
    printf("═══════════════════════════════════════════════════════════════════\n");

    int expert_count = 0;
    int moe_tensors = 0;
    int ffn_gate_count = 0;
    int ffn_gate_exps_count = 0;
    std::vector<std::string> tensor_names;

    for (uint64_t i = 0; i < header.tensor_count && i < 50; i++) {
        GGUFTensorInfo info;
        info.name = readString(file);
        tensor_names.push_back(info.name);

        file.read(reinterpret_cast<char*>(&info.n_dims), sizeof(info.n_dims));
        for (uint32_t d = 0; d < info.n_dims && d < 4; d++) {
            info.dims[d] = readU64(file);
        }
        file.read(reinterpret_cast<char*>(&info.type), sizeof(info.type));
        info.offset = readU64(file);

        printf("  [%2llu] %-40s ", i, info.name.c_str());
        printf("dims=[");
        for (uint32_t d = 0; d < info.n_dims; d++) {
            printf("%llu%s", info.dims[d], d < info.n_dims - 1 ? "," : "");
        }
        printf("] type=%u offset=%llu\n", info.type, info.offset);

        // Check for MoE indicators
        if (info.name.find("expert") != std::string::npos ||
            info.name.find("_exp") != std::string::npos ||
            info.name.find("_exps") != std::string::npos) {
            moe_tensors++;
        }
        if (info.name.find("ffn_gate") != std::string::npos) {
            ffn_gate_count++;
        }
        if (info.name.find("ffn_gate_exps") != std::string::npos ||
            info.name.find("ffn_gate_exp") != std::string::npos) {
            ffn_gate_exps_count++;
        }
    }

    // Summary
    printf("\n═══════════════════════════════════════════════════════════════════\n");
    printf("ANALYSIS:\n");
    printf("═══════════════════════════════════════════════════════════════════\n");

    // Check for MoE patterns
    bool has_moe_tensors = (ffn_gate_exps_count > 0);
    bool has_expert_routing = false;

    for (const auto& name : tensor_names) {
        if (name.find("router") != std::string::npos ||
            name.find("gate") != std::string::npos && name.find("expert") != std::string::npos) {
            has_expert_routing = true;
        }
    }

    printf("  Total tensors shown: %zu\n", tensor_names.size());
    printf("  Tensors with 'expert' in name: %d\n", moe_tensors);
    printf("  ffn_gate tensors: %d\n", ffn_gate_count);
    printf("  ffn_gate_exps tensors: %d\n", ffn_gate_exps_count);
    printf("\n");

    if (has_moe_tensors || ffn_gate_exps_count > 0) {
        printf("  ✅ VERDICT: This IS a Mixture-of-Experts (MoE) model!\n");
        printf("     Found expert-specific tensors indicating sparse routing.\n");
    } else if (ffn_gate_count > 0 && ffn_gate_exps_count == 0) {
        printf("  ❌ VERDICT: This is a DENSE Llama model (NOT MoE)\n");
        printf("     Has standard ffn_gate weights but NO expert-specific tensors.\n");
        printf("     The '200B sparse MoE' claim is MARKETING, not architecture.\n");
    } else {
        printf("  ⚠️  VERDICT: Architecture unclear - check full tensor list\n");
    }

    printf("\n");
    return 0;
}
