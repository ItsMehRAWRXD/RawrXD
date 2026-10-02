// fp16_model_impact.cpp
// RAWRXD_FP16_SUBNORMAL_001
//
// The fp16 subnormal defect was a constant-factor error on a small slice of the
// value range, which is exactly the shape that survives testing: a scale that
// happens to be normal decodes perfectly, and tests built from normal scales
// cannot see the bug at all.
//
// So the question that decides whether this was a real weight-corruption bug or
// a theoretical one is empirical: how many scale fields in a real model are
// fp16 subnormals? This counts them, per tensor and per quant type, over the
// actual bytes of the actual file.
//
// Every block with a subnormal scale was being decoded at HALF its true value
// before the repair, for every quant type routed through rawrxd::FP16ToFP32 or
// the kernel header's copy.
#include "gguf_loader.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace rawrxd;

namespace {

struct TypeStat {
    const char* name = nullptr;
    uint64_t tensors = 0;
    uint64_t blocks  = 0;      // blocks examined
    uint64_t fields  = 0;      // fp16 scale fields examined
    uint64_t subnorm = 0;      // ...of which are subnormals
    uint64_t zeros   = 0;      // ...of which are exactly zero
    uint64_t negsub  = 0;      // subnormals with the sign bit set
};

// How many fp16 scale fields each block type carries.
int FieldsPerBlock(GGMLType t) {
    switch (t) {
        case GGMLType::Q4_0: case GGMLType::Q8_0: return 1;
        case GGMLType::Q4_1: case GGMLType::Q5_0:
        case GGMLType::Q5_1: case GGMLType::Q8_1: return 2;
        // d, dmin, 12 packed scale bytes, of which 8 are 6-bit and 8 are 4-bit
        // halves -- each packed byte is two fields.
        case GGMLType::Q2_K: return 2;
        case GGMLType::Q3_K: return 1;         // d only; mins are int6, not fp16
        case GGMLType::Q4_K: return 2;         // d, dmin
        case GGMLType::Q5_K: return 2;         // d, dmin
        case GGMLType::Q6_K: return 1;         // d only
        case GGMLType::Q8_K: return 0;         // d is fp32
        default: return -1;
    }
}

// Byte offsets, within a block, of the fp16 scale fields.
std::vector<int> FieldOffsets(GGMLType t) {
    switch (t) {
        case GGMLType::Q4_0: return { 0 };
        case GGMLType::Q8_0: return { 0 };
        case GGMLType::Q4_1: case GGMLType::Q5_0: return { 0, 2 };
        case GGMLType::Q5_1: case GGMLType::Q8_1: return { 0, 2 };
        case GGMLType::Q2_K: return { 0, 2 };
        case GGMLType::Q3_K: return { 0 };
        case GGMLType::Q4_K: case GGMLType::Q5_K: return { 0, 2 };
        case GGMLType::Q6_K: return { 208 };
        default: return {};
    }
}

void Count(const uint8_t* p, const GGUFTensorInfo& info, TypeStat& s) {
    const int tsz = GGMLTypeSize(info.ggml_type);
    const int nfields = FieldsPerBlock(info.ggml_type);
    if (tsz <= 0 || nfields < 0) return;
    const std::vector<int> offs = FieldOffsets(info.ggml_type);
    const size_t nblocks = static_cast<size_t>(info.byte_size) /
                           static_cast<size_t>(tsz);
    ++s.tensors;
    for (size_t b = 0; b < nblocks; ++b) {
        const uint8_t* blk = p + b * static_cast<size_t>(tsz);
        ++s.blocks;
        for (int f = 0; f < nfields; ++f) {
            const int off = (f < static_cast<int>(offs.size())) ? offs[f] : 0;
            const uint16_t h = static_cast<uint16_t>(blk[off] | (blk[off + 1] << 8));
            ++s.fields;
            const uint32_t e = (h >> 10) & 0x1Fu;
            const uint32_t m = h & 0x3FFu;
            if (e == 0) {
                if (m == 0) ++s.zeros;
                else {
                    ++s.subnorm;
                    if (h & 0x8000u) ++s.negsub;
                }
            }
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1]
                                      : "F:/~dev/qwen2.5-coder-1.5b-base.gguf";
    GGUFLoader loader;
    if (!loader.LoadFromFile(path)) { std::printf("LOAD=FAIL\n"); return 2; }
    const GGUFModel* m = loader.GetModel();

    TypeStat stats[16];
    for (auto& s : stats) s.name = nullptr;

    size_t worstTensors = 0;
    std::string worstName;
    uint64_t worstSub = 0;

    for (const auto& t : m->tensors) {
        const int ti = static_cast<int>(t.ggml_type);
        if (ti < 0 || ti >= 16) continue;
        if (!stats[ti].name) stats[ti].name = GGMLTypeName(t.ggml_type);
        const uint64_t before = stats[ti].subnorm;
        auto view = loader.GetTensor(t.name);
        if (!view) continue;
        Count(view->data<uint8_t>(), t, stats[ti]);
        const uint64_t added = stats[ti].subnorm - before;
        if (added > worstSub) {
            worstSub = added;
            worstTensors = 1;
            worstName = t.name;
        }
    }

    std::printf("RAWRXD_FP16_SUBNORMAL_001\nMODEL=%s\n", path.c_str());
    std::printf("\n%-8s %-9s %-13s %-13s %-11s %-11s %s\n",
                "TYPE", "TENSORS", "BLOCKS", "FP16_FIELDS", "SUBNORMAL", "FRACTION", "HALVED_BEFORE");
    uint64_t totBlocks = 0, totFields = 0, totSub = 0;
    for (const auto& s : stats) {
        if (!s.name || s.blocks == 0) continue;
        std::printf("%-8s %-9llu %-13llu %-13llu %-11llu %-11.6g %s\n",
                    s.name,
                    (unsigned long long)s.tensors, (unsigned long long)s.blocks,
                    (unsigned long long)s.fields, (unsigned long long)s.subnorm,
                    s.fields ? (double)s.subnorm / (double)s.fields : 0.0,
                    s.subnorm ? "YES" : "no");
        totBlocks += s.blocks; totFields += s.fields; totSub += s.subnorm;
    }
    std::printf("\nTOTAL_BLOCKS=%llu\n", (unsigned long long)totBlocks);
    std::printf("TOTAL_FP16_FIELDS=%llu\n", (unsigned long long)totFields);
    std::printf("TOTAL_SUBNORMAL_FIELDS=%llu\n", (unsigned long long)totSub);
    std::printf("SUBNORMAL_FRACTION=%.9g\n",
                totFields ? (double)totSub / (double)totFields : 0.0);
    std::printf("WEIGHT_FIELDS_MATERIALLY_WRONG_BEFORE=%llu\n", (unsigned long long)totSub);
    std::printf("WORST_SINGLE_TENSOR=%s subnormal_fields=%llu\n",
                worstName.c_str(), (unsigned long long)worstSub);
    std::printf("Q6K_SUBNORMAL_BLOCKS=%llu\n",
                (unsigned long long)stats[static_cast<size_t>(GGMLType::Q6_K)].subnorm);
    std::printf("Q4K_SUBNORMAL_BLOCKS=%llu\n",
                (unsigned long long)stats[static_cast<size_t>(GGMLType::Q4_K)].subnorm);
    return 0;
}