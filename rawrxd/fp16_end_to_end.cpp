// fp16_end_to_end.cpp
// RAWRXD_FP16_SUBNORMAL_001 -- end-to-end consequence measurement.
//
// The census proves the CONVERSION is now correct. The impact census proves
// 1.73M scale fields in this model were affected. Neither of those says what
// happened to the numbers the model actually computes with.
//
// This measures the thing that matters: decode real weight rows through the
// PRODUCTION path (gguf_loader::ToFloat32 -> DequantQ6_K / DequantQ4_K) and
// compare against an independent decode of the same bytes, which is what the
// model should have been using all along. It reports how many decoded VALUES
// were wrong, not how many scale fields were subnormal -- a wrong scale field
// is only consequential to the extent it moves a weight.
//
// It is deliberately not a claim about tokens. A generation run needs the full
// forward stack, which does not link end to end in this tree for reasons
// unrelated to fp16. What is measured here is the tensor the model multiplies
// with, which is upstream of every token it will ever emit.
#include "gguf_loader.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace rawrxd;

namespace {

// Independent fp16 -> fp32, arithmetic, sharing no code with the loader.
float RefFp16(uint16_t h) {
    const int sign = (h & 0x8000) ? -1 : 1;
    const int e = (h >> 10) & 0x1F;
    const int m = h & 0x3FF;
    if (e == 31) return m ? NAN : (float)sign * INFINITY;
    if (e == 0) return (m == 0) ? (float)sign * 0.0f
                                : (float)sign * std::ldexp((float)m, -24);
    return (float)sign * std::ldexp((float)(m + 1024), e - 25);
}

// Independent Q6_K and Q4_K decoders, transcribed from the pinned upstream
// dequantize_row_q6_K / dequantize_row_q4_K, with RefFp16 for the scales.
void RefQ6K(const uint8_t* src, float* out) {
    const uint8_t* ql = src;
    const uint8_t* qh = src + 128;
    const int8_t* sc = reinterpret_cast<const int8_t*>(src + 192);
    const float d = RefFp16((uint16_t)(src[208] | (src[209] << 8)));
    for (int n = 0; n < 256; n += 128) {
        for (int l = 0; l < 32; ++l) {
            const int is = l / 16;
            const int q1 = ((ql[l + 0] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
            const int q2 = ((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
            const int q3 = ((ql[l + 0] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
            const int q4 = ((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
            out[l + 0] = d * sc[is + 0] * q1;
            out[l + 32] = d * sc[is + 2] * q2;
            out[l + 64] = d * sc[is + 4] * q3;
            out[l + 96] = d * sc[is + 6] * q4;
        }
        ql += 64; qh += 32; sc += 8; out += 128;
    }
}

void UnpackQ4K(const uint8_t* q, int j, uint8_t& d, uint8_t& m) {
    if (j < 4) { d = q[j] & 63; m = q[j + 4] & 63; }
    else { d = (q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4);
           m = (q[j + 4] >> 4) | ((q[j - 0] >> 6) << 4); }
}

void RefQ4K(const uint8_t* src, float* out) {
    const float d = RefFp16((uint16_t)(src[0] | (src[1] << 8)));
    const float dmin = RefFp16((uint16_t)(src[2] | (src[3] << 8)));
    const uint8_t* scales = src + 4;
    const uint8_t* qs = src + 16;
    uint8_t sc[8], mn[8];
    for (int j = 0; j < 8; ++j) UnpackQ4K(scales, j, sc[j], mn[j]);
    for (int g = 0; g < 8; ++g) {
        const uint8_t* q = qs + (g / 2) * 32;
        const int shift = (g & 1) ? 4 : 0;
        const float ds = d * (float)sc[g];
        const float dm = dmin * (float)mn[g];
        for (int l = 0; l < 32; ++l) {
            const int nib = (q[l] >> shift) & 0x0F;
            out[g * 32 + l] = ds * (float)nib - dm;
        }
    }
}

struct Acc {
    uint64_t elements = 0;
    uint64_t differing = 0;
    double maxRel = 0.0;
    double sumRel = 0.0;
    double dot = 0.0, na = 0.0, nb = 0.0;
};

void Tally(Acc& a, const std::vector<float>& got, const std::vector<float>& ref) {
    for (size_t i = 0; i < ref.size(); ++i) {
        const double g = got[i], r = ref[i];
        ++a.elements;
        const bool diff = (g != r);
        if (diff) ++a.differing;
        const double den = std::max(1e-30, std::fabs(r));
        const double rel = std::fabs(g - r) / den;
        if (rel > a.maxRel) a.maxRel = rel;
        a.sumRel += rel;
        a.dot += g * r; a.na += g * g; a.nb += r * r;
    }
}

}  // namespace

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1]
                                      : "F:/~dev/qwen2.5-coder-1.5b-base.gguf";
    const size_t maxRows  = argc > 2 ? (size_t)atoll(argv[2]) : 64;

    GGUFLoader loader;
    if (!loader.LoadFromFile(path)) { std::printf("LOAD=FAIL\n"); return 2; }
    const GGUFModel* m = loader.GetModel();

    Acc q6, q4;
    size_t q6t = 0, q4t = 0;

    for (const auto& t : m->tensors) {
        if (t.shape.size() != 2) continue;
        const size_t cols = (size_t)t.shape[0], rows = (size_t)t.shape[1];
        if (cols % 256 != 0) continue;
        auto view = loader.GetTensor(t.name);
        if (!view) continue;
        const uint8_t* packed = view->data<uint8_t>();
        const bool isQ6 = (t.ggml_type == GGMLType::Q6_K);
        const bool isQ4 = (t.ggml_type == GGMLType::Q4_K);
        if (!isQ6 && !isQ4) continue;

        std::vector<float> dec;
        // A slice, not the whole tensor: 151936x1536 is 233M elements and a
        // whole-tensor decode per row-count is pointless here.
        const size_t r0 = 0;
        const size_t r1 = (std::min)(rows, maxRows);
        if (!view->ToFloat32Rows(dec, r0, r1, cols)) continue;

        std::vector<float> ref(cols);
        const size_t bpr = cols / 256;
        for (size_t r = r0; r < r1; ++r) {
            const uint8_t* row = packed + r * bpr * (isQ6 ? 210 : 144);
            for (size_t b = 0; b < bpr; ++b) {
                float* dst = ref.data() + b * 256;
                if (isQ6) RefQ6K(row + b * 210, dst);
                else      RefQ4K(row + b * 144, dst);
            }
            Tally(isQ6 ? q6 : q4, std::vector<float>(
                       dec.begin() + (long)((r - r0) * cols),
                       dec.begin() + (long)((r - r0 + 1) * cols)), ref);
        }
        if (isQ6) ++q6t; else ++q4t;
    }

    auto report = [&](const char* tag, Acc& a, size_t tensors) {
        if (a.elements == 0) {
            std::printf("%s_NO_DATA\n", tag);
            return;
        }
        const double cos = (a.na > 0 && a.nb > 0) ? a.dot / std::sqrt(a.na * a.nb) : 0.0;
        std::printf("%s_TENSORS=%zu\n", tag, tensors);
        std::printf("%s_ELEMENTS=%llu\n", tag, (unsigned long long)a.elements);
        std::printf("%s_DIFFERING=%llu\n", tag, (unsigned long long)a.differing);
        std::printf("%s_DIFFERING_FRACTION=%.9g\n", tag,
                    (double)a.differing / (double)a.elements);
        std::printf("%s_MAX_REL=%.9g\n", tag, a.maxRel);
        std::printf("%s_MEAN_REL=%.9g\n", tag, a.sumRel / (double)a.elements);
        std::printf("%s_COSINE=%.12f\n", tag, cos);
        std::printf("%s_VERDICT=%s\n", tag,
                    (a.differing == 0) ? "EXACT" : "PRODUCTION_DIFFERS_FROM_REFERENCE");
    };

    std::printf("RAWRXD_FP16_SUBNORMAL_001_END_TO_END\n");
    std::printf("MODEL=%s\nROWS_PER_TENSOR=%zu\n", path.c_str(), maxRows);
    report("Q6_K", q6, q6t);
    report("Q4_K", q4, q4t);
    return 0;
}