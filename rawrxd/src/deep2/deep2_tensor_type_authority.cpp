// deep2_tensor_type_authority.cpp
// Standalone zero-dep tool that loads a GGUF and emits the exact tensor-type
// histogram requested by the 185-in-30 gate authority report.
//
// Build:
//   cl /O2 /EHsc /nologo /W4 /I"F:\~dev\rawrxd\src\deep2" deep2_tensor_type_authority.cpp /Fe:deep2_tensor_type_authority.exe
//
// Run:
//   deep2_tensor_type_authority.exe <model.gguf>
//
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <vector>

// Pull in the real GGUFLoader (header-only apart from OS mapping)
#include "GGUFLoader.hpp"

using Deep2::GGUFLoader;
using Deep2::GGMLType;

static const char* ggmlTypeName(uint32_t t) {
    switch (t) {
        case 0:  return "F32";
        case 1:  return "F16";
        case 2:  return "Q4_0";
        case 3:  return "Q4_1";
        case 6:  return "Q5_0";
        case 7:  return "Q5_1";
        case 8:  return "Q8_0";
        case 10: return "Q2_K";
        case 11: return "Q3_K";
        case 12: return "Q4_K";
        case 13: return "Q5_K";
        case 14: return "Q6_K";
        case 15: return "Q8_K";
        case 24: return "I8";
        case 25: return "I16";
        case 26: return "I32";
        case 27: return "I64";
        case 28: return "F64";
        case 30: return "BF16";
        default: return "UNKNOWN";
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <model.gguf>\n", argv[0]);
        return 2;
    }

    GGUFLoader loader;
    if (!loader.load(argv[1])) {
        std::fprintf(stderr, "FAIL=GGUF_LOAD msg=%s\n", loader.error().c_str());
        return 3;
    }

    std::unordered_map<uint32_t, size_t> countByType;
    std::unordered_map<uint32_t, size_t> bytesByType;

    for (const auto& name : loader.listTensors()) {
        const auto* t = loader.getTensor(name);
        if (!t) continue;
        uint32_t type = static_cast<uint32_t>(t->type);
        countByType[type]++;
        bytesByType[type] += t->sizeBytes;
    }

    // Emit the exact fields requested by the authority gate
    auto get = [&](uint32_t type) -> size_t {
        auto it = countByType.find(type);
        return it != countByType.end() ? it->second : 0;
    };
    auto getBytes = [&](uint32_t type) -> size_t {
        auto it = bytesByType.find(type);
        return it != bytesByType.end() ? it->second : 0;
    };

    std::fprintf(stderr,
        "=== MODEL_TENSOR_TYPE_AUTHORITY_REPORT ===\n"
        "MODEL_TENSOR_TYPE_COUNT_Q2_K=%zu\n"
        "MODEL_TENSOR_TYPE_COUNT_Q4_K=%zu\n"
        "MODEL_TENSOR_TYPE_COUNT_Q5_K=%zu\n"
        "MODEL_TENSOR_TYPE_COUNT_Q6_K=%zu\n"
        "MODEL_TENSOR_TYPE_COUNT_F32=%zu\n"
        "MODEL_TENSOR_BYTES_Q5_K=%zu\n"
        "TOTAL_TENSORS=%zu\n"
        "MAPPED_BYTES=%llu\n"
        "=== END_REPORT ===\n",
        get(10),
        get(12),
        get(13),
        get(14),
        get(0),
        getBytes(13),
        loader.tensorCount(),
        (unsigned long long)loader.mappedBytes()
    );

    // Optional full histogram for human review
    std::fprintf(stderr, "\n--- FULL_HISTOGRAM ---\n");
    std::vector<uint32_t> types;
    types.reserve(countByType.size());
    for (const auto& kv : countByType) types.push_back(kv.first);
    std::sort(types.begin(), types.end());
    for (uint32_t t : types) {
        std::fprintf(stderr, "  %-8s  count=%5zu  bytes=%12zu\n",
                     ggmlTypeName(t), countByType[t], bytesByType[t]);
    }

    return 0;
}
