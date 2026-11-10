#include "deep2/GGUFLoader.hpp"
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

using namespace Deep2;

static const char* typeName(uint32_t t) {
    switch (t) {
        case 0: return "F32"; case 1: return "F16"; case 2: return "Q4_0";
        case 3: return "Q4_1"; case 6: return "Q5_0"; case 7: return "Q5_1";
        case 8: return "Q8_0"; case 10: return "Q2_K"; case 11: return "Q3_K";
        case 12: return "Q4_K"; case 13: return "Q5_K"; case 14: return "Q6_K";
        case 15: return "Q8_K"; case 16: return "IQ2_XXS"; case 24: return "I8";
        case 25: return "I16"; case 26: return "I32"; case 27: return "I64";
        case 28: return "F64"; case 30: return "BF16"; case 40: return "NVFP4";
        default: return "UNKNOWN";
    }
}

static bool isExpertTensor(const std::string& name) {
    return name.find(".ffn_gate_exps.") != std::string::npos ||
           name.find(".ffn_up_exps.") != std::string::npos ||
           name.find(".ffn_down_exps.") != std::string::npos ||
           name.find(".ffn_gate_inp.weight") != std::string::npos ||
           name.find(".exp_probs_b.bias") != std::string::npos ||
           name.find(".ffn_down_shexp.") != std::string::npos ||
           name.find(".ffn_gate_shexp.") != std::string::npos ||
           name.find(".ffn_up_shexp.") != std::string::npos;
}

static bool isPackedProjection(const std::string& name) {
    return name.find(".ffn_gate_exps.") != std::string::npos ||
           name.find(".ffn_up_exps.") != std::string::npos ||
           name.find(".ffn_down_exps.") != std::string::npos;
}

int main(int argc, char** argv) {
    const char* path = argc > 1 ? argv[1] :
        "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M\\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf";

    GGUFLoader loader;
    if (!loader.load(path)) {
        fprintf(stderr, "LOAD_FAILED: %s\n", loader.error().c_str());
        return 1;
    }

    printf("=== GGUF Tensor Geometry Audit ===\n");
    printf("shards=%u tensors=%zu version=%u\n\n",
           loader.shardCount(), loader.tensorCount(), loader.version());

    // Block geometry table (must match GGUFLoader)
    struct BlockInfo { uint64_t elems; uint64_t bytes; };
    std::unordered_map<uint32_t, BlockInfo> blocks = {
        {0,{1,4}},{1,{1,2}},{2,{32,18}},{3,{32,20}},{6,{32,22}},{7,{32,24}},
        {8,{32,34}},{10,{256,84}},{11,{256,110}},{12,{256,144}},{13,{256,176}},
        {14,{256,210}},{15,{256,292}},{16,{256,66}},{24,{1,1}},{25,{1,2}},
        {26,{1,4}},{27,{1,8}},{28,{1,8}},{30,{1,2}},{40,{64,36}}
    };

    uint64_t totalPackedBytes = 0;
    uint64_t packedTensorCount = 0;
    uint32_t maxExpertsSeen = 0;
    bool anyMismatch = false;

    auto names = loader.listTensors();
    for (const auto& name : names) {
        const auto* t = loader.getTensor(name);
        if (!t) continue;

        if (!isExpertTensor(name)) continue;

        ++packedTensorCount;
        const uint32_t type = static_cast<uint32_t>(t->type);
        const auto& shape = t->shape;
        const uint64_t bytes = t->sizeBytes;
        const uint64_t offset = t->tensorOffset;

        // Calculate expected bytes using dims[0] contiguous (GGUFLoader convention)
        uint64_t calcBytes = 0;
        bool calcOk = false;
        if (!shape.empty() && blocks.count(type)) {
            const auto& bi = blocks[type];
            uint64_t contiguous = static_cast<uint64_t>(shape[0]);
            uint64_t blockElems = bi.elems;
            uint64_t blockBytes = bi.bytes;
            uint64_t blocksPerRow = (contiguous + blockElems - 1) / blockElems;
            uint64_t rowBytes = blocksPerRow * blockBytes;
            uint64_t rows = 1;
            bool overflow = false;
            for (size_t i = 1; i < shape.size(); ++i) {
                if (shape[i] == 0 || rows > UINT64_MAX / static_cast<uint64_t>(shape[i])) { overflow = true; break; }
                rows *= static_cast<uint64_t>(shape[i]);
            }
            if (!overflow && rows > 0) {
                calcBytes = rowBytes * rows;
                calcOk = true;
            }
        }

        uint64_t dimsBack = shape.empty() ? 0 : static_cast<uint64_t>(shape.back());
        uint64_t strideByBack = dimsBack ? (bytes / dimsBack) : 0;
        bool divisible = dimsBack && (bytes % dimsBack == 0);

        // Expert dim = dims.back() if this is a packed projection
        uint64_t expertCount = 0;
        if (isPackedProjection(name)) expertCount = dimsBack;

        if (expertCount > maxExpertsSeen) maxExpertsSeen = static_cast<uint32_t>(expertCount);

        bool bytesMatch = calcOk && (calcBytes == bytes);

        if (!bytesMatch || !divisible) anyMismatch = true;

        printf("%-55s type=%-8s dims=[", name.c_str(), typeName(type));
        for (size_t i = 0; i < shape.size(); ++i) {
            if (i) printf(", ");
            printf("%llu", (unsigned long long)shape[i]);
        }
        printf("] bytes=%llu offset=%llu calcBytes=%llu calcMatch=%s "
               "dimsBack=%llu strideByBack=%llu divisible=%s",
               (unsigned long long)bytes, (unsigned long long)offset,
               (unsigned long long)calcBytes, bytesMatch ? "YES" : "NO",
               (unsigned long long)dimsBack, (unsigned long long)strideByBack,
               divisible ? "YES" : "NO");

        if (isPackedProjection(name)) {
            printf(" EXPERT_COUNT=%llu", (unsigned long long)expertCount);
            totalPackedBytes += bytes;
        }
        printf("\n");
    }

    printf("\n=== Summary ===\n");
    printf("expert-related tensors in shard 1: %llu\n", (unsigned long long)packedTensorCount);
    printf("max expert count seen: %u\n", maxExpertsSeen);
    printf("any geometry mismatch: %s\n", anyMismatch ? "YES" : "NO");
    printf("total packed projection bytes (shard 1): %llu\n", (unsigned long long)totalPackedBytes);

    return anyMismatch ? 1 : 0;
}
