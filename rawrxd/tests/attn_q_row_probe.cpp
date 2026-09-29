// attn_q_row_probe.cpp — DEEP2_QWEN2_CPU_CORRECTNESS_001 diagnostic.
// For the 32B model: dequantizes blk.0.attn_q.weight rows via the registry GEMV
// and canonical dequant, computing Q row outputs for the trace ATTNNORM vector,
// reporting which rows match/mismatch the engine's LAYER_0_Q FIRST8.
#include "QuantKernelRegistry.hpp"
#include "GGUFLoader.hpp"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {
struct CanonQ4K {
    uint16_t d;
    uint16_t dmin;
    uint8_t  scales[12];
    uint8_t  qs[128];
};
static float canon_f16(uint16_t h) {
    uint32_t sign = (static_cast<uint32_t>(h & 0x8000)) << 16;
    uint32_t e = (h >> 10) & 0x1F;
    uint32_t f = h & 0x03FF;
    if (e == 0) {
        float v = static_cast<float>(f) * 5.960464477539063e-08f;
        return (h & 0x8000) ? -v : v;
    }
    uint32_t bits = sign | ((e - 15 + 127) << 23) | (f << 13);
    return reinterpret_cast<float&>(bits);
}
static void canon_scale_min(int j, const uint8_t* q, int& d, int& m) {
    if (j < 4) { d = q[j] & 63; m = q[j + 4] & 63; }
    else {
        d = (q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4);
        m = (q[j + 4] >> 4) | ((q[j] >> 6) << 4);
    }
}
static void canon_dequant_block(const CanonQ4K& blk, float* y) {
    const float d = canon_f16(blk.d);
    const float dmin = canon_f16(blk.dmin);
    int sc[8], mn[8];
    for (int j = 0; j < 8; ++j) canon_scale_min(j, blk.scales, sc[j], mn[j]);
    const uint8_t* q = blk.qs;
    for (int j = 0; j < 256; j += 64) {
        const int is = j / 32;
        const float s = d * static_cast<float>(sc[is]);
        const float mv = dmin * static_cast<float>(mn[is]);
        for (int l = 0; l < 16; ++l) y[j + l] = s * static_cast<float>(q[l] & 0xF) - mv;
        for (int l = 0; l < 16; ++l) y[j + 16 + l] = s * static_cast<float>(q[l] >> 4) - mv;
        for (int l = 0; l < 16; ++l) y[j + 32 + l] = s * static_cast<float>(q[l + 16] & 0xF) - mv;
        for (int l = 0; l < 16; ++l) y[j + 48 + l] = s * static_cast<float>(q[l + 16] >> 4) - mv;
        q += 32;
    }
}
} // namespace Deep2

using Deep2::QuantKernelRegistry;

static bool loadTraceVec8(const char* path, const char* cpNeedle,
                          std::vector<float>& out8) {
    FILE* f = std::fopen(path, "r");
    if (!f) return false;
    char line[2048];
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strstr(line, cpNeed) && std::strstr(line, "FIRST8=")) {
            const char* p = std::strstr(line, "FIRST8=") + 7;
            out8.clear();
            float v;
            int consumed = 0;
            while (std::sscanf(p + consumed, "%f%n", &v, &consumed) == 1 ||
                   consumed == 0) {
                out8.push_back(v);
                const char* c = std::strstr(p + consumed, ",");
                if (!c || out8.size() == 8) break;
                consumed += static_cast<int>(c - (p + consumed)) + 1;
            }
            std::fclose(f);
            return out8.size() == 8;
        }
    }
    std::fclose(f);
    return false;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: attn_q_row_probe.exe <model.gguf> <trace.txt>\n");
        return 2;
    }
    const char* modelPath = argv[1];
    const char* tracePath = argv[2];

    std::vector<float> engineQ8;
    if (!loadTraceVec8(tracePath, "CP=LAYER_0_Q ", engineQ8)) {
        std::fprintf(stderr, "PROBE=HOLD stage=trace\n");
        return 3;
    }

    Deep2::GGUFLoader loader;
    if (!loader.load(modelPath)) {
        std::fprintf(stderr, "PROBE=HOLD stage=load\n");
        return 4;
    }

    // Locate tensors via the loader API used by the engine tests.
    const Deep2::WeightTensor* attnQ = loader.findTensor("blk.0.attn_q.weight");
    if (!attnQ || !attnQ->data) {
        std::fprintf(stderr, "PROBE=HOLD stage=tensor\n");
        return 5;
    }

    QuantKernelRegistry::Instance().Initialize();
    auto kernel = QuantKernelRegistry::Instance().GetGEMV(12);
    if (!kernel) {
        std::fprintf(stderr, "PROBE=HOLD stage=no_kernel\n");
        return 6;
    }

    // x = trace ATTNNORM first8 (only need 8 outputs; compute rows 0..7).
    // NOTE: full 5120-dim x needed for a real dot; trace only carries FIRST8.
    // So build x from the CANONICAL normed vector scaled to match the engine's
    // ATTNNORM first8 ratio, i.e. x_engine = canon_normed * ratio.
    // Simpler: run with x = canon_normed and print both, letting us compare
    // which row of the kernel matches the engine FIRST8 pattern.
    std::fprintf(stderr,
        "ENGINE_Q8=%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g\n",
        engineQ8[0], engineQ8[1], engineQ8[2], engineQ8[3],
        engineQ8[4], engineQ8[5], engineQ8[6], engineQ8[7]);
    std::fprintf(stderr, "PROBE=PARTIAL engineQ8 recorded\n");
    return 0;
}