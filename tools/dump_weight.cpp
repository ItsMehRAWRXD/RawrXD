//=============================================================================
// dump_weight - RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001
//
// Dequantizes a named GGUF tensor through the same ROMResolver +
// DequantizeTensor path the IR executor uses, and dumps it as raw FP32 so
// the dequantization can be diffed element-by-element against an
// independent ggml reference implementation.
//
// Usage: dump_weight <gguf> <tensor_name> <out_f32>
//=============================================================================

#include "ModelGenieExecutor.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

int main(int argc, char* argv[])
{
    if (argc < 4) {
        std::fprintf(stderr, "usage: dump_weight <gguf> <tensor_name> <out_f32>\n");
        return 2;
    }
    const std::string gguf = argv[1];
    const std::string want = argv[2];
    const std::string outPath = argv[3];

    // Resolve the tensor by name from the generated ROM table.
    ROMResolver resolver(gguf);
    uint32_t romId = GEN::ModelConfig::kTensorCount;
    for (uint32_t i = 0; i < GEN::ModelConfig::kTensorCount; ++i) {
        if (GEN::kTensorROMTable[i].name == want) { romId = i; break; }
    }
    if (romId == GEN::ModelConfig::kTensorCount) {
        std::fprintf(stderr, "tensor not in ROM table: %s\n", want.c_str());
        return 3;
    }

    const TensorView* v = resolver.Resolve(romId);
    if (!v) { std::fprintf(stderr, "ROM resolve failed\n"); return 4; }
    const uint64_t dataOffset =
        static_cast<uint64_t>(reinterpret_cast<const uint8_t*>(v->data) - resolver.Base());
    std::fprintf(stderr, "%s: dims=%u bytes=%llu elements=%llu type=%d data_offset=%llu\n",
                 want.c_str(), v->rank ? v->dims[0] : 0u,
                 (unsigned long long)v->bytes,
                 (unsigned long long)v->elementCount, (int)v->type,
                 (unsigned long long)dataOffset);

    // Absolute file offset of the tensor payload, so an independent
    const float* deq = resolver.GetDequantizedWeight(romId);
    if (!deq) { std::fprintf(stderr, "dequantize failed\n"); return 5; }

    const size_t n = v->elementCount;
    FILE* f = std::fopen(outPath.c_str(), "wb");
    if (!f) { std::fprintf(stderr, "cannot write %s\n", outPath.c_str()); return 6; }
    std::fwrite(deq, sizeof(float), n, f);
    std::fclose(f);
    std::fprintf(stderr, "wrote %zu floats to %s\n", n, outPath.c_str());
    return 0;
}
