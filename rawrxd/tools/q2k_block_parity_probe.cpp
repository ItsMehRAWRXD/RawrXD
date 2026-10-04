// q2k_block_parity_probe.cpp — Q2_K block/row decode parity probe
// Usage: q2k_block_parity_probe <path-to-model.gguf> [tensor_name] [block_index]
//
// Compares one real Q2_K packed block against independent canonical decode.
// Reports FIRST_DIFF_INDEX between production decode and reference decode.
//
// RAWRXD_Q2K_BLOCK_PARITY_PROBE_001
//
// ============================================================================
// INVALID_SELF_REFERENCE -- THIS PROBE PROVES NOTHING.
// DO NOT READ A PASS HERE AS EVIDENCE THAT THE Q2_K LAYOUT IS CORRECT.
// ============================================================================
//
// canonical_dequant_q2_k_block() below hardcodes the SAME byte offsets that
// Deep2Engine's production decode uses. It transcribes the code under test
// rather than implementing it independently, so the two cannot disagree: it
// reports PARITY for every tensor whether or not the field order is right.
//
// That is not hypothetical. The layout this tree ships (fp16 d/dmin LAST) is in
// fact correct -- Q2_K is the one K-quant where it is -- but had it been wrong,
// this probe would still have printed:
//
//     VERDICT=PASS 256/256 weights match
//
// Use tools/q2k_layout_discriminator.cpp instead. It decides the layout from
// the real bytes using physical bounds -- d must be positive and small, and
// max|w| cannot exceed 189*d for a 2-bit block -- so it is capable of
// disagreeing with the production layout. Measured on llama3.2-3b-Q2_K across
// ~1536 blocks: the d-first reading yields d spanning 34.8 decades with block
// standard deviations near 2000; the shipped d-last reading yields d in the
// 1e-3..1.6e-2 band with block standard deviations of 0.019-0.042.

#include "QuantKernelRegistry.hpp"
#include "GGUFLoader.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <vector>
#include <limits>
#include <cmath>

// Canonical Q2_K block layout (GGML reference):
//   block_q2_K { uint8_t scales[16]; uint8_t qs[64]; uint16_t d; uint16_t dmin; }
//   256 weights per block, 84 bytes total.
//
// RAWRXD_Q2K_FIELD_ORDER_002: scales ARE FIRST, d/dmin LAST.
// This is the ONLY K-quant where fp16 super-block is trailing.
// A probe that assumes Q4_K order (d/dmin first) reads scale bytes
// as fp16 and produces d ~1e6, which makes every output noise.
//
// Scale/min unpack (canonical 6-bit get_scale_min_k2):
//   For j < 4:  sc = q[j] & 63,  mn = q[j+4] & 63
//   For j >= 4: sc = (q[j+4] & 0xF) | ((q[j-4] >> 6) << 4)
//                 mn = (q[j+4] >> 4)   | ((q[j-0] >> 6) << 4)
//
// Weight reconstruction:
//   dl = d * sc,  ml = dmin * mn
//   q  = (qs[qsIdx] >> qsShift) & 0x03
//   w  = dl * q - ml

static inline float f16_to_f32_ref(uint16_t h) {
    uint32_t sign = (static_cast<uint32_t>(h & 0x8000)) << 16;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t frac = h & 0x03FF;
    if (exp == 0) {
        if (frac == 0) return reinterpret_cast<const float*>(&sign)[0];
        uint32_t e = 1, f = frac;
        while ((f & 0x0400) == 0) { f <<= 1; e++; }
        f &= 0x03FF;
        uint32_t bits = sign | ((127 - 15 + 2 - e) << 23) | (f << 13);
        return reinterpret_cast<float*>(&bits)[0];
    }
    if (exp == 31) {
        uint32_t bits = sign | 0x7F800000 | (frac << 13);
        return reinterpret_cast<float*>(&bits)[0];
    }
    uint32_t bits = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    return reinterpret_cast<float*>(&bits)[0];
}

static inline void get_scale_min_k2_ref(int j, const uint8_t* q,
                                        uint8_t* d, uint8_t* m) {
    if (j < 4) {
        *d = (uint8_t)(q[j] & 63);
        *m = (uint8_t)(q[j + 4] & 63);
    } else {
        *d = (uint8_t)((q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4));
        *m = (uint8_t)((q[j + 4] >> 4)   | ((q[j - 0] >> 6) << 4));
    }
}

static void canonical_dequant_q2_k_block(const uint8_t* src, float* dst) {
    // src points to an 84-byte block_q2_K
    // RAWRXD_Q2K_FIELD_ORDER_002: scales@0, qs@16, d@80, dmin@82
    const uint8_t* scales = src;          // @ 0
    const uint8_t* qs     = src + 16;     // @ 16
    uint16_t d_raw;
    uint16_t dmin_raw;
    std::memcpy(&d_raw,    src + 80, 2);  // @ 80
    std::memcpy(&dmin_raw, src + 82, 2);  // @ 82

    float d    = f16_to_f32_ref(d_raw);
    float dmin = f16_to_f32_ref(dmin_raw);

    int is = 0;
    const uint8_t* qq = qs;
    for (int n = 0; n < 256; n += 128) {
        int shift = 0;
        for (int j = 0; j < 4; ++j) {
            uint8_t sc = scales[is++];
            float dl = d * float(sc & 0x0Fu);
            float ml = dmin * float(sc >> 4);
            for (int l = 0; l < 16; ++l)
                dst[n + j*32 + l] = dl * float((qq[l] >> shift) & 3) - ml;
            sc = scales[is++];
            dl = d * float(sc & 0x0Fu);
            ml = dmin * float(sc >> 4);
            for (int l = 0; l < 16; ++l)
                dst[n + j*32 + 16 + l] = dl * float((qq[l + 16] >> shift) & 3) - ml;
            shift += 2;
        }
        qq += 32;
    }
}

// Production path: use QuantKernelRegistry dequant kernel
static void production_dequant_q2_k_block(const uint8_t* src, float* dst, size_t n) {
    auto& reg = Deep2::QuantKernelRegistry::Instance();
    auto fn = reg.GetDequant(10);  // GGML_TYPE_Q2_K = 10
    if (!fn) {
        std::fprintf(stderr, "FAIL: no Q2_K dequant kernel registered\n");
        std::exit(1);
    }
    fn(src, dst, n);
}

int main(int argc, char** argv) {
    const char* modelPath = (argc > 1) ? argv[1]
        : "D:\\rawrxd\\llama3.2-3b-Q2_K.gguf";
    const char* tensorName = (argc > 2) ? argv[2] : "blk.0.attn_q.weight";
    int blockIdx = (argc > 3) ? std::atoi(argv[3]) : 0;

    std::fprintf(stderr, "GATE=Q2K_BLOCK_PARITY_PROBE\n");
    // Printed at RUNTIME as well as in the header, so a receipt harvested from a
    // log cannot silently acquire a PASS that nobody can trace to a real check.
    std::fprintf(stderr, "Q2K_BLOCK_PARITY_PROBE=INVALID_SELF_REFERENCE\n");
    std::fprintf(stderr, "  its reference decoder shares production's byte offsets and\n");
    std::fprintf(stderr, "  cannot disagree with it. PARITY here is not evidence.\n");
    std::fprintf(stderr, "  USE=tools/q2k_layout_discriminator.cpp for the layout claim.\n");
    std::fprintf(stderr, "MODEL=%s\n", modelPath);
    std::fprintf(stderr, "TENSOR=%s\n", tensorName);
    std::fprintf(stderr, "BLOCK_IDX=%d\n", blockIdx);

    // Ensure registry is initialized
    Deep2::QuantKernelRegistry::Instance().Initialize();

    Deep2::GGUFLoader loader;
    if (!loader.load(modelPath)) {
        std::fprintf(stderr, "FAIL=load %s\n", loader.error().c_str());
        return 1;
    }

    auto* t = loader.getTensor(tensorName);
    if (!t || !t->data) {
        std::fprintf(stderr, "FAIL=tensor_not_found name=%s\n", tensorName);
        return 1;
    }

    if (t->type != Deep2::GGMLType::GGML_TYPE_Q2_K) {
        std::fprintf(stderr, "FAIL=not_q2_k type=%d\n", static_cast<int>(t->type));
        return 1;
    }

    const size_t numBlocks = t->sizeBytes / 84;
    if (blockIdx < 0 || static_cast<size_t>(blockIdx) >= numBlocks) {
        std::fprintf(stderr, "FAIL=block_index_out_of_range numBlocks=%zu\n", numBlocks);
        return 1;
    }

    const uint8_t* blockData = t->data + blockIdx * 84;

    // Decode via production path
    float prodWeights[256];
    production_dequant_q2_k_block(blockData, prodWeights, 256);

    // Decode via canonical reference
    float refWeights[256];
    canonical_dequant_q2_k_block(blockData, refWeights);

    // Compare
    int firstDiff = -1;
    double maxAbsDiff = 0.0;
    double sumSqDiff = 0.0;
    for (int i = 0; i < 256; ++i) {
        double diff = std::fabs(prodWeights[i] - refWeights[i]);
        if (diff > 1e-6) {
            if (firstDiff < 0) firstDiff = i;
            if (diff > maxAbsDiff) maxAbsDiff = diff;
            sumSqDiff += diff * diff;
        }
    }

    if (firstDiff < 0) {
        std::fprintf(stderr, "VERDICT=PASS 256/256 weights match\n");
        std::fprintf(stderr, "MAX_ABS_DIFF=0.0\n");
        std::fprintf(stderr, "RMS_DIFF=0.0\n");
        return 0;
    }

    std::fprintf(stderr, "VERDICT=FAIL first_diff=%d prod=%.9g ref=%.9g\n",
                 firstDiff, prodWeights[firstDiff], refWeights[firstDiff]);
    std::fprintf(stderr, "MAX_ABS_DIFF=%.9g\n", maxAbsDiff);
    std::fprintf(stderr, "RMS_DIFF=%.9g\n", std::sqrt(sumSqDiff / 256.0));

    // Dump first 16 weights for diagnosis
    std::fprintf(stderr, "WEIGHTS[0..15]:\n");
    for (int i = 0; i < 16; ++i) {
        std::fprintf(stderr, "  [%3d] prod=%12.6f ref=%12.6f diff=%12.6f\n",
                     i, prodWeights[i], refWeights[i],
                     prodWeights[i] - refWeights[i]);
    }
    return 1;
}
