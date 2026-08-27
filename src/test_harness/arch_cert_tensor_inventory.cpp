// =============================================================================
// arch_cert_tensor_inventory.cpp — ARCH-CERT-001: GGUF Tensor/Operation Inventory
//
// Enumerates every tensor in a GGUF model and produces a machine-readable
// inventory with: name, type, shape, offset, size, and classification
// (embedding, attention, FFN, norm, output, SSM, conv, gate, etc.)
//
// Build: cl /std:c++20 /EHsc /Fe:arch_cert_tensor_inventory.exe arch_cert_tensor_inventory.cpp
// Usage: arch_cert_tensor_inventory.exe <model.gguf> [output.json]
// =============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#include <string>
#include <map>
#include <algorithm>

// =============================================================================
// Minimal GGUF parser (same as hotpatch_e2e_test.cpp)
// =============================================================================
#pragma pack(push, 1)
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensorCount;
    uint64_t metadataKVCount;
};
#pragma pack(pop)

static const char* ggmlTypeName(uint32_t type) {
    switch (type) {
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
        case 24: return "I8";
        case 25: return "I16";
        case 26: return "I32";
        case 27: return "I64";
        case 28: return "F64";
        default: return "UNKNOWN";
    }
}

struct GGUFTensorInfo {
    std::string name;
    uint32_t    type;
    std::vector<uint64_t> shape;
    uint64_t    offset;
    uint64_t    sizeBytes;
};

static bool readGGUFString(std::ifstream& f, std::string& out) {
    uint64_t len;
    f.read(reinterpret_cast<char*>(&len), sizeof(len));
    if (len > 65536) return false;
    out.resize(len);
    f.read(&out[0], len);
    return f.good();
}

static bool skipGGUFMetadataValue(std::ifstream& f, uint32_t type) {
    switch (type) {
        case 0: { uint8_t v;  f.read(reinterpret_cast<char*>(&v), 1); break; }
        case 1: { int8_t v;   f.read(reinterpret_cast<char*>(&v), 1); break; }
        case 2: { uint16_t v; f.read(reinterpret_cast<char*>(&v), 2); break; }
        case 3: { int16_t v;  f.read(reinterpret_cast<char*>(&v), 2); break; }
        case 4: { uint32_t v; f.read(reinterpret_cast<char*>(&v), 4); break; }
        case 5: { int32_t v;  f.read(reinterpret_cast<char*>(&v), 4); break; }
        case 6: { float v;    f.read(reinterpret_cast<char*>(&v), 4); break; }
        case 7: { bool v;     f.read(reinterpret_cast<char*>(&v), 1); break; }
        case 8: { std::string s; return readGGUFString(f, s); }
        case 9: {
            uint32_t elemType;
            f.read(reinterpret_cast<char*>(&elemType), 4);
            uint64_t count;
            f.read(reinterpret_cast<char*>(&count), 8);
            static const uint32_t metaTypeSizes[] = {1,1,2,2,4,4,4,1,0,0,8,8,8};
            uint32_t es = (elemType < 13) ? metaTypeSizes[elemType] : 0;
            if (es == 0) {
                if (elemType == 8) {
                    for (uint64_t i = 0; i < count; i++) { std::string s; if (!readGGUFString(f, s)) return false; }
                } else return false;
            } else {
                f.seekg(count * es, std::ios::cur);
            }
            break;
        }
        case 10:{ uint64_t v; f.read(reinterpret_cast<char*>(&v), 8); break; }
        case 11:{ int64_t v;  f.read(reinterpret_cast<char*>(&v), 8); break; }
        case 12:{ double v;   f.read(reinterpret_cast<char*>(&v), 8); break; }
        default: return false;
    }
    return f.good();
}

// =============================================================================
// Tensor classification
// =============================================================================
enum class TensorCategory {
    EMBEDDING,
    ATTENTION,
    FFN,
    NORM,
    OUTPUT,
    SSM,
    CONV,
    GATE,
    ROPE,
    MOE,
    UNKNOWN
};

static const char* categoryName(TensorCategory c) {
    switch (c) {
        case TensorCategory::EMBEDDING:  return "embedding";
        case TensorCategory::ATTENTION:  return "attention";
        case TensorCategory::FFN:        return "ffn";
        case TensorCategory::NORM:       return "norm";
        case TensorCategory::OUTPUT:     return "output";
        case TensorCategory::SSM:        return "ssm";
        case TensorCategory::CONV:       return "conv";
        case TensorCategory::GATE:       return "gate";
        case TensorCategory::ROPE:       return "rope";
        case TensorCategory::MOE:        return "moe";
        default:                         return "unknown";
    }
}

static TensorCategory classifyTensor(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // Embedding
    if (lower.find("token_embd") != std::string::npos ||
        lower.find("token_embedding") != std::string::npos ||
        lower.find("embed_tokens") != std::string::npos ||
        lower.find("tok_emb") != std::string::npos)
        return TensorCategory::EMBEDDING;

    // Output
    if (lower.find("output.weight") != std::string::npos ||
        lower.find("lm_head") != std::string::npos ||
        lower.find("output_norm") != std::string::npos ||
        lower.find("final_norm") != std::string::npos)
        return TensorCategory::OUTPUT;

    // SSM / Mamba state-space
    if (lower.find("ssm_") != std::string::npos ||
        lower.find("mamba_") != std::string::npos ||
        lower.find("state_space") != std::string::npos ||
        lower.find("a_log") != std::string::npos ||
        lower.find("dt_bias") != std::string::npos ||
        lower.find("in_proj") != std::string::npos ||
        lower.find("out_proj") != std::string::npos ||
        lower.find("conv1d") != std::string::npos ||
        lower.find("x_proj") != std::string::npos ||
        lower.find("dt_proj") != std::string::npos)
        return (lower.find("conv1d") != std::string::npos) ? TensorCategory::CONV : TensorCategory::SSM;

    // RoPE
    if (lower.find("rope") != std::string::npos && lower.find("freq") != std::string::npos)
        return TensorCategory::ROPE;

    // MoE
    if (lower.find("moe") != std::string::npos ||
        lower.find("expert") != std::string::npos ||
        lower.find("gate_proj") != std::string::npos ||
        lower.find("router") != std::string::npos)
        return TensorCategory::MOE;

    // Attention
    if (lower.find("attn") != std::string::npos ||
        lower.find("self_attn") != std::string::npos ||
        lower.find("q_proj") != std::string::npos ||
        lower.find("k_proj") != std::string::npos ||
        lower.find("v_proj") != std::string::npos ||
        lower.find("o_proj") != std::string::npos ||
        lower.find("wq") != std::string::npos ||
        lower.find("wk") != std::string::npos ||
        lower.find("wv") != std::string::npos ||
        lower.find("wo") != std::string::npos ||
        lower.find("qkv") != std::string::npos)
        return TensorCategory::ATTENTION;

    // FFN
    if (lower.find("ffn") != std::string::npos ||
        lower.find("mlp") != std::string::npos ||
        lower.find("gate") != std::string::npos ||
        lower.find("up_proj") != std::string::npos ||
        lower.find("down_proj") != std::string::npos ||
        lower.find("w_gate") != std::string::npos ||
        lower.find("w_up") != std::string::npos ||
        lower.find("w_down") != std::string::npos)
        return TensorCategory::FFN;

    // Norm
    if (lower.find("norm") != std::string::npos ||
        lower.find("ln_") != std::string::npos ||
        lower.find("rms") != std::string::npos)
        return TensorCategory::NORM;

    // Gate (if not already classified as FFN/MoE)
    if (lower.find("gate") != std::string::npos)
        return TensorCategory::GATE;

    return TensorCategory::UNKNOWN;
}

// =============================================================================
// Main
// =============================================================================
int main(int argc, char* argv[]) {
    std::string modelPath = argc > 1 ? argv[1] : "F:\\~dev\\tinyllama_fresh.gguf";
    std::string outputPath = argc > 2 ? argv[2] : "ARCH-CERT-001_tensor_inventory.txt";

    printf("=== ARCH-CERT-001: GGUF Tensor/Operation Inventory ===\n");
    printf("Model: %s\n\n", modelPath.c_str());

    std::ifstream f(modelPath, std::ios::binary);
    if (!f) { printf("FAIL: Cannot open %s\n", modelPath.c_str()); return 1; }

    GGUFHeader hdr;
    f.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    if (hdr.magic != 0x46554747) { printf("FAIL: Not a GGUF file\n"); return 1; }

    printf("GGUF version: %u\n", hdr.version);
    printf("Tensor count: %llu\n", (unsigned long long)hdr.tensorCount);
    printf("Metadata KV count: %llu\n\n", (unsigned long long)hdr.metadataKVCount);

    // Skip metadata
    std::map<std::string, std::string> metadata;
    for (uint64_t i = 0; i < hdr.metadataKVCount; i++) {
        std::string key;
        if (!readGGUFString(f, key)) { printf("FAIL: metadata key read at KV %llu\n", (unsigned long long)i); return 1; }
        uint32_t valueType;
        f.read(reinterpret_cast<char*>(&valueType), 4);
        if (!skipGGUFMetadataValue(f, valueType)) { printf("FAIL: metadata value skip at KV %llu\n", (unsigned long long)i); return 1; }
    }

    // Read tensor info
    std::vector<GGUFTensorInfo> tensors;
    for (uint64_t i = 0; i < hdr.tensorCount; i++) {
        GGUFTensorInfo ti;
        if (!readGGUFString(f, ti.name)) { printf("FAIL: tensor name read at %llu\n", (unsigned long long)i); return 1; }
        uint32_t nDims;
        f.read(reinterpret_cast<char*>(&nDims), 4);
        ti.shape.resize(nDims);
        for (uint32_t d = 0; d < nDims; d++)
            f.read(reinterpret_cast<char*>(&ti.shape[d]), 8);
        f.read(reinterpret_cast<char*>(&ti.type), 4);
        f.read(reinterpret_cast<char*>(&ti.offset), 8);

        // Calculate approximate size
        ti.sizeBytes = 1;
        for (auto dim : ti.shape) ti.sizeBytes *= dim;
        // For quantized types, adjust (rough estimate)
        if (ti.type >= 2 && ti.type <= 14) {
            // Quantized — actual size depends on block structure
            // Just use the product of dimensions as a rough estimate
        }

        tensors.push_back(ti);
    }

    uint64_t tensorDataOffset = (uint64_t)f.tellg();
    tensorDataOffset = (tensorDataOffset + 31) & ~31ULL;

    // Classify and count
    std::map<TensorCategory, int> categoryCounts;
    std::map<TensorCategory, uint64_t> categorySizes;
    std::vector<std::pair<GGUFTensorInfo, TensorCategory>> classified;

    for (const auto& t : tensors) {
        TensorCategory cat = classifyTensor(t.name);
        categoryCounts[cat]++;
        categorySizes[cat] += t.sizeBytes;
        classified.push_back({t, cat});
    }

    // Print summary
    printf("=== Tensor Category Summary ===\n");
    printf("%-15s %8s %15s\n", "Category", "Count", "Approx Size");
    printf("%-15s %8s %15s\n", "---------------", "--------", "---------------");
    for (auto& [cat, count] : categoryCounts) {
        printf("%-15s %8d %15llu\n", categoryName(cat), count, (unsigned long long)categorySizes[cat]);
    }
    printf("%-15s %8zu %15llu\n", "TOTAL", tensors.size(),
           (unsigned long long)0);

    // Print all tensors
    printf("\n=== Full Tensor Inventory ===\n");
    printf("%-50s %-8s %-20s %12s %15s\n", "Name", "Type", "Shape", "Offset", "Category");
    printf("%-50s %-8s %-20s %12s %15s\n",
           "--------------------------------------------------",
           "--------", "--------------------", "------------", "---------------");

    for (const auto& [t, cat] : classified) {
        std::string shapeStr;
        for (size_t i = 0; i < t.shape.size(); i++) {
            if (i > 0) shapeStr += "x";
            shapeStr += std::to_string(t.shape[i]);
        }
        if (shapeStr.empty()) shapeStr = "scalar";

        printf("%-50s %-8s %-20s %12llu %15s\n",
               t.name.c_str(),
               ggmlTypeName(t.type),
               shapeStr.c_str(),
               (unsigned long long)(tensorDataOffset + t.offset),
               categoryName(cat));
    }

    // Write machine-readable output
    std::ofstream out(outputPath);
    out << "ARCH-CERT-001: GGUF Tensor/Operation Inventory\n";
    out << "Model: " << modelPath << "\n";
    out << "GGUF version: " << hdr.version << "\n";
    out << "Tensor count: " << tensors.size() << "\n";
    out << "Tensor data offset: " << tensorDataOffset << "\n";
    out << "\n=== Category Summary ===\n";
    out << "Category,Count,ApproxSize\n";
    for (auto& [cat, count] : categoryCounts) {
        out << categoryName(cat) << "," << count << "," << categorySizes[cat] << "\n";
    }
    out << "\n=== Full Inventory ===\n";
    out << "Name,Type,Shape,Offset,Size,Category\n";
    for (const auto& [t, cat] : classified) {
        std::string shapeStr;
        for (size_t i = 0; i < t.shape.size(); i++) {
            if (i > 0) shapeStr += "x";
            shapeStr += std::to_string(t.shape[i]);
        }
        out << t.name << "," << ggmlTypeName(t.type) << "," << shapeStr << ","
            << (tensorDataOffset + t.offset) << "," << t.sizeBytes << ","
            << categoryName(cat) << "\n";
    }
    out.close();

    printf("\nInventory written to: %s\n", outputPath.c_str());

    // Flag unknown tensors
    int unknownCount = categoryCounts[TensorCategory::UNKNOWN];
    if (unknownCount > 0) {
        printf("\nWARNING: %d tensor(s) classified as UNKNOWN — need manual review\n", unknownCount);
    }

    // Flag SSM tensors specifically
    int ssmCount = categoryCounts[TensorCategory::SSM];
    int convCount = categoryCounts[TensorCategory::CONV];
    if (ssmCount > 0 || convCount > 0) {
        printf("\nSSM/Mamba architecture detected: %d SSM tensors, %d conv tensors\n",
               ssmCount, convCount);
    } else {
        printf("\nNo SSM/Mamba tensors detected — pure transformer architecture\n");
    }

    return 0;
}