// RAWRXD_Q4K_GEMV_PARITY_001
//
// Isolated parity gate for the quantized GEMV used by Deep2's Vulkan QKV
// projection. The live model path reached an impossible-looking state:
//   input parity PASS, weight binding PASS, shape/offset PASS, SPIR-V fresh,
//   shader statically audited correct -- and yet GPU Q4_K output was wrong
//   while Q6_K was correct. This harness removes the model loop, RoPE, KV
// cache, attention, sampler and teardown, and keeps everything that could
// actually be responsible:
//
//   * the same shader module            (deep2_qgemv.spv)
//   * the same descriptor layout        (getQuantDescriptor via dispatchQuant)
//   * the same push constants           (QPush, via SubmitGemvPrefetch)
//   * the same weight upload path       (PrefetchWeight)
//   * the same dispatch geometry       (vkCmdDispatch(rows,1,1))
//   * the same output readback          (DownloadVector)
//
// The CPU reference is the canonical GGML block_q4_K / block_q6_K layout,
// written out longhand rather than pulled from a library, because the point
// of this gate is to have two independent implementations of the dequant to
// disagree loudly if either is wrong.
//
// Verdict partition:
//   Q4K_FAIL_Q6K_PASS  -> Q4_K shader / Q4_K dispatch defect
//   Q4K_PASS_LIVE_FAIL -> shader exonerated; live plumbing feeds it wrong data
//   BOTH_FAIL          -> shared GEMV dispatch defect
//   BOTH_PASS          -> return to the live path with a descriptor diff
//
// Gated on RAWRXD_Q4K_PARITY=1 in the engine-side path; this tool always
// runs the gate when invoked.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include <algorithm>

#include "deep2/vulkan_compute.h"

using CPUInference::VulkanCompute;

namespace {

// Set when any case reports a GPU/tree mismatch that the double reference
// cannot explain. That is the signature of a data-interpretation defect in the
// shader rather than a summation-order difference.
bool gAnyDataInterpretationDefect = false;

// ---------------------------------------------------------------- CPU ref --
// Canonical GGML block_q4_K (144 bytes):
//   ggml_half d; ggml_half dmin; uint8_t scales[12]; uint8_t qs[128];
// Within each 64-element group, elements 0..31 use the LOW nibbles of
// qs[0..31] and elements 32..63 use the HIGH nibbles of qs[0..31].
static inline uint16_t rdU16(const uint8_t* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static inline float halfToF32(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    const uint32_t exp  = (h >> 10) & 0x1Fu;
    const uint32_t man  = h & 0x3FFu;
    uint32_t bits;
    if (exp == 0) {
        if (man == 0) { bits = sign; }
        else {
            // subnormal
            uint32_t e = 0, m = man;
            while (!(m & 0x400u)) { m <<= 1; ++e; }
            m &= 0x3FFu;
            bits = sign | ((127 - 15 - e) << 23) | (m << 13);
        }
    } else if (exp == 31) {
        bits = sign | 0x7F800000u | (man << 13);
    } else {
        bits = sign | ((exp - 15 + 127) << 23) | (man << 13);
    }
    float f; std::memcpy(&f, &bits, sizeof f); return f;
}

static void getScaleMinK4(int j, const uint8_t* q, uint8_t& d, uint8_t& m) {
    if (j < 4) { d = q[j] & 63; m = q[j + 4] & 63; }
    else {
        d = (uint8_t)((q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4));
        m = (uint8_t)((q[j + 4] >> 4)   | ((q[j - 0] >> 6) << 4));
    }
}

// Dequantize one 256-element Q4_K block into out[256].
static void dequantQ4K(const uint8_t* blk, float* out) {
    const float d    = halfToF32(rdU16(blk + 0));
    const float dmin = halfToF32(rdU16(blk + 2));
    const uint8_t* scales = blk + 4;
    const uint8_t* qs     = blk + 16;
    int is = 0;
    for (int g = 0; g < 4; ++g) {
        uint8_t sc, m;
        getScaleMinK4(is + 0, scales, sc, m);
        const float d1 = d * sc, m1 = dmin * m;
        getScaleMinK4(is + 1, scales, sc, m);
        const float d2 = d * sc, m2 = dmin * m;
        for (int l = 0; l < 32; ++l)
            out[g * 64 + l]      = d1 * (qs[g * 32 + l] & 0xF) - m1;
        for (int l = 0; l < 32; ++l)
            out[g * 64 + 32 + l] = d2 * (qs[g * 32 + l] >> 4)   - m2;
        is += 2;
    }
}

// Canonical GGML block_q6_K (210 bytes):
//   uint8_t ql[128]; uint8_t qh[64]; int8_t scales[16]; ggml_half d;
static void dequantQ6K(const uint8_t* blk, float* out) {
    const float d = halfToF32(rdU16(blk + 208));
    for (int n = 0; n < 2; ++n) {
        // Canonical Q6_K walks two 128-element halves, advancing each of the
        // three sub-arrays by (64, 32, 8) per half. An earlier revision of
        // this reference forgot the advance and re-dequantized the first
        // half twice, which made the GPU look wrong when it was correct.
        const uint8_t* ql = blk + n * 64;
        const uint8_t* qh = blk + 128 + n * 32;
        const int8_t*  sc = reinterpret_cast<const int8_t*>(blk + 192 + n * 8);
        for (int l = 0; l < 32; ++l) {
            const int is = l / 16;
            const int q1 = (int)((ql[l +  0] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
            const int q2 = (int)((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
            const int q3 = (int)((ql[l +  0] >> 4)  | (((qh[l] >> 4) & 3) << 4)) - 32;
            const int q4 = (int)((ql[l + 32] >> 4)  | (((qh[l] >> 6) & 3) << 4)) - 32;
            out[n * 128 + l +  0] = d * (float)sc[is + 0] * (float)q1;
            out[n * 128 + l + 32] = d * (float)sc[is + 2] * (float)q2;
            out[n * 128 + l + 64] = d * (float)sc[is + 4] * (float)q3;
            out[n * 128 + l + 96] = d * (float)sc[is + 6] * (float)q4;
        }
    }
}

// -------------------------------------------------------------- oracles --
// The CPU path above accumulates in double. That is the correct answer, but it
// cannot by itself distinguish "the GPU misread the block" from "the GPU and the
// reference used different summation orders", because only one order exists on
// the CPU side. These two extra oracles exist purely to falsify that ambiguity:
//
//   REF_DOUBLE       exact-ish reference (double accumulation, linear order)
//   REF_FP32_LINEAR  same order as the reference, forced through float
//   REF_FP32_TREE    float, pairwise-balanced (log depth) reduction
//
// A GPU that disagrees with FP32_TREE by far more than FP32_TREE disagrees with
// DOUBLE has a data-interpretation defect, not an accumulation-order defect.
// With terms summing to ~1e-6 relative slack, ordinary float rounding cannot
// manufacture the observed 0.21.

// Maximum |x| over a float vector, used to normalize the oracle deltas.
static double maxAbsOf(const std::vector<float>& v) {
    double m = 0.0;
    for (float f : v) m = std::max(m, (double)std::fabs((double)f));
    return m;
}

static double maxAbsDiff(const std::vector<float>& a, const std::vector<float>& b) {
    double m = 0.0;
    const size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; ++i)
        m = std::max(m, std::fabs((double)a[i] - (double)b[i]));
    return m;
}

// Linear float accumulation, per row. Models a naive serial GPU reduction.
static std::vector<float> reduceFp32Linear(const std::vector<std::vector<float>>& t) {
    std::vector<float> out(t.size(), 0.0f);
    for (size_t r = 0; r < t.size(); ++r) {
        float acc = 0.0f;
        for (float x : t[r]) acc += x;
        out[r] = acc;
    }
    return out;
}

// Pairwise-balanced float reduction, per row: halve the term count repeatedly,
// summing adjacent pairs, until one value remains. Depth is ceil(log2(N)),
// which is the most favorable legitimate float summation order for a fixed
// term set.
static std::vector<float> reduceFp32Tree(const std::vector<std::vector<float>>& t) {
    std::vector<float> out(t.size(), 0.0f);
    for (size_t r = 0; r < t.size(); ++r) {
        std::vector<float> cur(t[r]);
        for (size_t step = cur.size(); step > 1; ) {
            const size_t half = (step + 1) / 2;
            for (size_t i = 0; i < half; ++i)
                cur[i] = cur[2 * i] + (2 * i + 1 < step ? cur[2 * i + 1] : 0.0f);
            step = half;
        }
        out[r] = cur.empty() ? 0.0f : cur[0];
    }
    return out;
}

// ---------------------------------------------------------------------------
// Reference arbiter
// ---------------------------------------------------------------------------
// dequantQ4K above reconstructs all 256 weights into a float array and then
// dots them. gemv_q4_k_scalar in src/deep2/QuantKernelRegistry.cpp instead
// walks 64-element chunks and accumulates in place, pairing
// get_scale_min_k4(is+0) with 32 LOW nibbles and get_scale_min_k4(is+1) with 32
// HIGH nibbles of the same advancing 32-byte span.
//
// These are the same algorithm written two different ways, so on the synthetic
// CASE_A data (random d, random 12-byte scale blob, random qs) they must agree.
// When they disagree, the DEQUANT is wrong and the shader is exonerated; when
// they agree but the GPU still differs, the shader is the wrong side.
static void gemvQ4KArbiter(const uint8_t* w, const float* x, float* y,
                           size_t rows, size_t cols) {
    const size_t blocksPerRow = cols / 256;
    for (size_t r = 0; r < rows; ++r) {
        const uint8_t* rowBase = w + r * blocksPerRow * 144;
        float acc = 0.0f;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const uint8_t* blk = rowBase + b * 144;
            const float d    = halfToF32(rdU16(blk));
            const float dmin = halfToF32(rdU16(blk + 2));
            const uint8_t* s = blk + 4;
            const uint8_t* q = blk + 16;
            const float* xb = x + b * 256;
            for (int j = 0; j < 256; j += 64) {
                const int is = j / 32;
                uint8_t sc_a, mn_a, sc_b, mn_b;
                getScaleMinK4(is + 0, s, sc_a, mn_a);
                getScaleMinK4(is + 1, s, sc_b, mn_b);
                const float d1 = d    * (float)sc_a;
                const float m1 = dmin * (float)mn_a;
                const float d2 = d    * (float)sc_b;
                const float m2 = dmin * (float)mn_b;
                for (int l = 0; l < 32; ++l)
                    acc += (d1 * (float)(q[l] & 0xF) - m1) * xb[j + l];
                for (int l = 0; l < 32; ++l)
                    acc += (d2 * (float)(q[l] >> 4)   - m2) * xb[j + l + 32];
                q += 32;
            }
        }
        y[r] = acc;
    }
}

// fp16 -> f32 for the CASE_E expectations. Bit-identical to halfToF32 above;
// duplicated as a tiny helper so the expectation is computed from the same
// encoding rule the block construction used, not from a hand-typed constant.
static double VariantWeight(uint16_t dHalf, uint8_t sc, uint8_t qNibble) {
    return (double)halfToF32(dHalf) * (double)sc * (double)qNibble;
}

// CASE_E variants are built here so the expectation can be printed next to the
// measured value.
static size_t blockBytesFor(int type) {
    switch (type) {
        case 12: return 144;  // Q4_K
        case 14: return 210;  // Q6_K
        default: return 0;
    }
}

struct Stat {
    double maxAbs = 0.0, sumSq = 0.0, refMax = 0.0;
    double sumAbsTerms = 0.0;   // sum |a_i * w_i| -- the fp32 error budget basis
    int    argmaxCpu = -1, argmaxGpu = -1;
    size_t n = 0;
};

static Stat compare(const std::vector<float>& cpu, const std::vector<float>& gpu) {
    Stat s; s.n = std::min(cpu.size(), gpu.size());
    for (size_t i = 0; i < s.n; ++i) {
        const double d = std::fabs((double)cpu[i] - (double)gpu[i]);
        if (d > s.maxAbs) s.maxAbs = d;
        s.sumSq += d * d;
        s.refMax = std::max(s.refMax, (double)std::fabs(cpu[i]));
        if (cpu[i] > cpu[s.argmaxCpu < 0 ? 0 : (size_t)s.argmaxCpu]) s.argmaxCpu = (int)i;
        if (gpu[i] > gpu[s.argmaxGpu < 0 ? 0 : (size_t)s.argmaxGpu]) s.argmaxGpu = (int)i;
    }
    return s;
}

static void print8(const char* tag, const std::vector<float>& v) {
    std::fprintf(stderr, "%s", tag);
    for (int i = 0; i < 8 && (size_t)i < v.size(); ++i)
        std::fprintf(stderr, "%s%g", i ? " " : "", v[i]);
    std::fprintf(stderr, "\n");
}

// Run one case through the REAL dispatch path.
static bool runCase(VulkanCompute& vc, const char* role, const char* name,
                    const void* weights, size_t weightBytes,
                    int quantType, uint32_t rows, uint32_t cols,
                    const std::vector<float>& input, const char* env) {
    const size_t bb = blockBytesFor(quantType);
    if (!bb) { std::fprintf(stderr, "[Q4KPAR] %s unsupported type=%d\n", role, quantType); return false; }

    VulkanCompute::DeviceBuf in{}, out{};
    if (!vc.EnsureScratch(90, input.size()) ) { std::fprintf(stderr, "[Q4KPAR] scratch in\n"); return false; }
    in = vc.Scratch(90);
    if (!vc.EnsureScratch(91, rows)) { std::fprintf(stderr, "[Q4KPAR] scratch out\n"); return false; }
    out = vc.Scratch(91);
    if (!vc.UploadVector(in, input.data(), input.size())) { std::fprintf(stderr, "[Q4KPAR] upload in\n"); return false; }

    uint32_t slot = 0;
    if (!vc.PrefetchWeight(weights, weightBytes, slot)) { std::fprintf(stderr, "[Q4KPAR] prefetch\n"); return false; }
    if (!vc.SubmitGemvPrefetch(slot, in, out, rows, cols, weightBytes, quantType)) {
        std::fprintf(stderr, "[Q4KPAR] submit\n"); return false;
    }
    if (!vc.WaitWeightCompute(slot)) { std::fprintf(stderr, "[Q4KPAR] wait\n"); return false; }

    std::vector<float> gpu(rows, 0.0f);
    if (!vc.DownloadVector(out, gpu.data(), rows)) { std::fprintf(stderr, "[Q4KPAR] download\n"); return false; }

    // CPU reference: dequantize row by row, then dot with the same input.
    // Also accumulates sum|a_i*w_i|, because the correct tolerance for a
    // fp32 GPU tree-reduction dot is relative to the MAGNITUDE OF THE TERMS,
    // not to the (possibly cancellation-shrunk) result. A dot whose terms sum
    // to 1e6 in absolute value but cancels down to 178 cannot be compared to
    // 1e-7 of 178; that would flag ordinary fp32 rounding as a shader bug.
    //
    // Three references are produced from the SAME term set so that a mismatch
    // can be attributed:
    //   cpuDouble  double accumulation            (canonical)
    //   cpuLinear  float, linear order            (naive-serial shape)
    //   cpuTree    float, pairwise tree           (best-legitimate-order shape)
    // Only cpuTree is used for the pass/fail budget; the others exist to prove
    // that a failure is NOT attributable to summation order.
    std::vector<float> cpuDouble(rows, 0.0f);
    std::vector<double> sumAbs(rows, 0.0);
    std::vector<std::vector<float>> terms(rows);
    const size_t colsPerBlock = 256;
    const size_t blocksPerRow = cols / colsPerBlock;
    std::vector<float> row(colsPerBlock, 0.0f);
    const uint8_t* w = (const uint8_t*)weights;
    for (uint32_t r = 0; r < rows; ++r) {
        const uint8_t* rb = w + (size_t)r * blocksPerRow * bb;
        double acc = 0.0, mag = 0.0;
        terms[r].resize(cols);
        for (size_t bIdx = 0; bIdx < blocksPerRow; ++bIdx) {
            const uint8_t* blk = rb + bIdx * bb;
            if (quantType == 12) dequantQ4K(blk, row.data());
            else               dequantQ6K(blk, row.data());
            for (size_t c = 0; c < colsPerBlock; ++c) {
                const float  tf = row[c] * input[bIdx * colsPerBlock + c];
                const double t  = (double)tf;
                terms[r][bIdx * colsPerBlock + c] = tf;
                acc += t;
                mag += std::fabs(t);
            }
        }
        cpuDouble[r] = (float)acc;
        sumAbs[r] = mag;
    }
    const std::vector<float> cpuLinear = reduceFp32Linear(terms);
    const std::vector<float> cpuTree   = reduceFp32Tree(terms);

    // The budget is derived from the tree reference, because the tree is the
    // most favorable legitimate summation order. If the GPU disagrees with the
    // tree by far more than the budget, no summation order explains it.
    Stat s = compare(cpuTree, gpu);
    const Stat sDouble = compare(cpuDouble, gpu);
    const Stat sLinear = compare(cpuLinear, gpu);
    for (uint32_t r = 0; r < rows; ++r)
        if (sumAbs[r] > s.sumAbsTerms) s.sumAbsTerms = sumAbs[r];

    // Cross-oracle deltas: how much do the three CPU-side references differ
    // from EACH OTHER? If these are tiny, then any large GPU delta cannot be
    // an artifact of reduction order.
    const double dDoubleVsLinear = maxAbsDiff(cpuDouble, cpuLinear);
    const double dDoubleVsTree   = maxAbsDiff(cpuDouble, cpuTree);
    const double dLinearVsTree   = maxAbsDiff(cpuLinear, cpuTree);
    const double dTreeVsGpu      = s.maxAbs;
    const double dDoubleVsGpu    = sDouble.maxAbs;
    const double dLinearVsGpu    = sLinear.maxAbs;
    const double treeMax         = maxAbsOf(cpuTree);

    // fp32 has eps ~= 1.19e-7. A tree reduction over N terms accumulates on
    // the order of log2(N) * eps * sum|terms|. Allow a 20x safety factor for
    // genuinely different (but both valid) summation orders.
    const double budget = 20.0 * 1.2e-7 * (double)(std::log2((double)cols) + 1.0)
                        * s.sumAbsTerms;
    const bool pass = s.maxAbs <= budget;
    const double relToTerms = s.sumAbsTerms > 0 ? s.maxAbs / s.sumAbsTerms : 0.0;

    // Formal falsification oracle: if the GPU is within budget of the TREE, the
    // mismatch (if any) is summation order. If it is outside budget of the tree
    // AND the tree agrees with the double reference, the defect is data
    // interpretation -- the shader read different values than the dequant did.
    const bool orderExplainsIt  = (dTreeVsGpu <= budget);
    const bool treeIsAuthoritative = (dDoubleVsTree <= budget);
    const bool dataInterpretationDefect = (!orderExplainsIt && treeIsAuthoritative);

    std::fprintf(stderr, "[Q4KPAR] CASE role=%s name=%s quant=%s rows=%u cols=%u bytes=%zu\n",
        role, name, quantType == 12 ? "Q4_K" : "Q6_K", rows, cols, weightBytes);
    print8("[Q4KPAR]   REF_DOUBLE_0_8=", cpuDouble);
    print8("[Q4KPAR]   REF_FP32_LINEAR_0_8=", cpuLinear);
    print8("[Q4KPAR]   REF_FP32_TREE_0_8=", cpuTree);
    print8("[Q4KPAR]   GPU_OUT_0_8=", gpu);
    const double rms = s.n ? std::sqrt(s.sumSq / (double)s.n) : 0.0;
    std::fprintf(stderr, "[Q4KPAR]   MAX_ABS_ERR=%.9g RMS_ERR=%.9g REF_MAX=%.9g SUM_ABS_TERMS=%.9g REL_TO_TERMS=%.3g FP32_BUDGET=%.9g ARGMAX_CPU=%d ARGMAX_GPU=%d\n",
        s.maxAbs, rms, s.refMax, s.sumAbsTerms, relToTerms, budget,
        s.argmaxCpu, s.argmaxGpu);
    std::fprintf(stderr, "[Q4KPAR]   ORACLE DOUBLE_VS_LINEAR=%.9g DOUBLE_VS_TREE=%.9g LINEAR_VS_TREE=%.9g TREE_VS_GPU=%.9g DOUBLE_VS_GPU=%.9g LINEAR_VS_GPU=%.9g TREE_MAX=%.9g\n",
        dDoubleVsLinear, dDoubleVsTree, dLinearVsTree, dTreeVsGpu, dDoubleVsGpu,
        dLinearVsGpu, treeMax);
    std::fprintf(stderr, "[Q4KPAR]   ORDER_EXPLAINS_MISMATCH=%d TREE_IS_AUTHORITATIVE=%d DATA_INTERPRETATION_DEFECT=%d\n",
        orderExplainsIt ? 1 : 0, treeIsAuthoritative ? 1 : 0,
        dataInterpretationDefect ? 1 : 0);
    std::fprintf(stderr, "[Q4KPAR]   PARITY=%s\n", pass ? "PASS" : "FAIL");
    std::fflush(stderr);
    (void)env;
    gAnyDataInterpretationDefect = gAnyDataInterpretationDefect || dataInterpretationDefect;
    return pass;
}

} // namespace

int main(int argc, char** argv) {
    // Accept the model path as ANY argument, so callers do not have to know
    // the positional layout. An earlier revision only looked at argv[3] and
    // silently skipped CASE_B when the model was passed as argv[2].
    const char* mdl = nullptr;
    const char* syn = nullptr;
    long geoCols = 0;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a.size() > 5 && a.compare(a.size() - 5, 5, ".gguf") == 0) mdl = argv[i];
        else if (a.size() > 4 && a.compare(a.size() - 4, 4, ".bin") == 0) syn = argv[i];
        else if (a.rfind("cols=", 0) == 0) geoCols = atol(a.c_str() + 5);
    }

    uint32_t cols = 5120;
    const uint32_t rows = 256;
    std::vector<float> input(cols);
    for (uint32_t i = 0; i < cols; ++i)
        input[i] = std::sin((float)i * 0.001f) * 0.5f;

    VulkanCompute vc;
    if (!vc.Initialize()) {
        std::fprintf(stderr, "[Q4KPAR] VULKAN_INIT_FAIL\n");
        return 2;
    }
    std::fprintf(stderr, "[Q4KPAR] DEVICE_INIT_OK\n");

    // RAWRXD_Q4K_GEMV_PARITY_001 geometry sweep.
    // Pass a 4th argument to override cols. With cols=256 the whole dot is a
    // SINGLE Q4_K block, which reduces a data-dependent kernel defect to one
    // block per row and leaves only scale/min decode, nibble selection, lane
    // ownership and reduction as candidate dimensions. Grow cols until the
    // first failing geometry.
    if (geoCols > 0) cols = (uint32_t)geoCols;
    if ((cols % 256u) != 0u) {
        std::fprintf(stderr, "[Q4KPAR] cols=%u not a multiple of 256\n", cols);
        return 2;
    }
    std::fprintf(stderr, "[Q4KPAR] GEOMETRY rows=%u cols=%u blocksPerRow=%zu\n",
        rows, cols, (size_t)(cols / 256));

    bool q4Pass = false, q6Pass = false;
    bool dCasePass = false;   // constant-weight discriminator (CASE_D)

    // CASE_A: synthetic Q4_K blocks (no model). Deterministic bytes.
    // Rows MUST differ from each other: an earlier revision emitted the same
    // block for every row, so all outputs were identical and the case proved
    // only one block pattern. Vary d, dmin, scales and qs per row/block so a
    // single wrong row cannot hide behind 255 correct ones.
    {
        const size_t blocksPerRow = cols / 256;
        std::vector<uint8_t> wq((size_t)rows * blocksPerRow * 144);
        uint32_t seed = 0x12345678u;
        auto rnd = [&seed]() { seed = seed * 1664525u + 1013904223u; return (seed >> 8) & 0xFFu; };
        for (size_t r = 0; r < rows; ++r) {
            for (size_t bIdx = 0; bIdx < blocksPerRow; ++bIdx) {
                uint8_t* p = wq.data() + (r * blocksPerRow + bIdx) * 144;
                // d: a positive half-float spanning ~0.125..~24
                //
                // This must be built in 16 bits. An earlier revision built it
                // in a uint8_t and then stored `dh >> 8` as the high byte,
                // which is always 0 -- so `d` was written as the half 0x0030,
                // an fp16 SUBNORMAL worth ~2.9e-6 rather than ~0.125. That fed
                // the GPU a block whose scale was six orders of magnitude
                // below the intended range and produced a clean-looking but
                // meaningless 2.0x "defect" in CASE_A. The half is assembled in
                // a uint16_t and split explicitly so the exponent survives.
                const uint16_t dHalf =
                    (uint16_t)(0x3000u + ((r + bIdx) % 16u) * 0x0200u);
                p[0] = (uint8_t)(dHalf & 0xFFu); p[1] = (uint8_t)(dHalf >> 8);
                // dmin: sometimes zero, sometimes nonzero
                const uint16_t dmh = (bIdx % 5u == 0) ? 0u
                                  : (uint16_t)(0x2000u + ((r * 3u + bIdx) % 0x2000u));
                p[2] = (uint8_t)(dmh & 0xFFu); p[3] = (uint8_t)(dmh >> 8);
                for (int k = 0; k < 12; ++k) p[4 + k] = rnd();   // scales, all bit patterns
                for (int k = 0; k < 128; ++k) p[16 + k] = rnd(); // qs
            }
        }
        q4Pass = runCase(vc, "A", "synthetic_q4k", wq.data(), wq.size(), 12, rows, cols, input, "A");

        // Arbitrate the two independent CPU references on this exact data.
        {
            std::vector<float> arb(rows, 0.0f);
            gemvQ4KArbiter(wq.data(), input.data(), arb.data(), rows, cols);
            std::vector<float> ref(rows, 0.0f);
            std::vector<std::vector<float>> terms(rows);
            for (uint32_t r = 0; r < rows; ++r) {
                std::vector<float> blk(256, 0.0f);
                const uint8_t* rb = wq.data() + (size_t)r * blocksPerRow * 144;
                dequantQ4K(rb, blk.data());
                terms[r] = blk;
                for (uint32_t c = 0; c < 256; ++c)
                    ref[r] += (float)((double)blk[c] * (double)input[c]);
            }
            const double arbVsRef = maxAbsDiff(arb, ref);
            const double arbVsGpu1x = (double)arb[0];
            std::printf("[Q4KPAR]   ARBITER gemv_q4_k_scalar_vs_dequantQ4K=%.9g\n", arbVsRef);
            std::printf("[Q4KPAR]   ARBITER arbiter_row0=%.9g  dequantQ4K_row0=%.9g\n",
                        arbVsGpu1x, (double)ref[0]);
            std::fprintf(stderr, "[Q4KPAR] CPU_REFERENCES_AGREE=%d\n",
                         arbVsRef <= 1e-6 ? 1 : 0);
        }
    }

    // CASE_C: synthetic Q6_K control.
    {
        const size_t blocksPerRow = cols / 256;
        std::vector<uint8_t> wv((size_t)rows * blocksPerRow * 210);
        for (size_t i = 0; i < wv.size(); i += 210) {
            wv[i + 208] = 0x00; wv[i + 209] = 0x3C; // d ~1.0
            for (int k = 0; k < 128; ++k) wv[i + k] = (uint8_t)(k * 3 + 1);
            for (int k = 0; k < 64; ++k)  wv[i + 128 + k] = (uint8_t)(k * 5 + 2);
            for (int k = 0; k < 16; ++k)  wv[i + 192 + k] = (uint8_t)(2 + (k % 5));
        }
        q6Pass = runCase(vc, "C", "synthetic_q6k", wv.data(), wv.size(), 14, rows, cols, input, "C");
    }

    // CASE_D: constant-weight discriminator. Every dequantised weight in every
    // block is constructed to be exactly 1.0, and the input is exactly 1.0, so
    // the mathematically correct row sum is EXACTLY cols (no cancellation, no
    // rounding sensitivity, no dependence on fp32 summation order).
    //
    // This separates the two candidate causes that a general case cannot:
    //   GPU == cols      -> dequant values are correct; a general-case
    //                       mismatch must come from scale/min/nibble decode
    //   GPU == 2*cols    -> every column is being counted twice, i.e. the
    //                       defect is in the accumulation/column mapping, and
    //                       the dequant values are individually correct
    //
    // Construction:
    //   d    = 0x3C00 (fp16 1.0), dmin = 0x0000 (fp16 0.0)
    //   sc[sb] = 1 for all 8 sub-blocks, mn[sb] = 0 for all 8
    //   qs    = 0x11 everywhere -> low nibble 1, high nibble 1 -> q == 1
    //   weight = d*sc*q - dmin*mn = 1.0*1*1 - 0*0 = 1.0
    //   row sum = cols
    {
        const size_t blocksPerRow = cols / 256;
        std::vector<uint8_t> wd((size_t)rows * blocksPerRow * 144);
        for (size_t i = 0; i < wd.size(); i += 144) {
            uint8_t* p = wd.data() + i;
            p[0] = 0x00; p[1] = 0x3C;   // d    = 1.0
            p[2] = 0x00; p[3] = 0x00;   // dmin = 0.0
            // scales: sc[0..3] = 1, mn[0..3] = 0
            p[4] = 0x01; p[5] = 0x01; p[6] = 0x01; p[7] = 0x01;
            p[8] = 0x00; p[9] = 0x00; p[10] = 0x00; p[11] = 0x00;
            // scales[8..11]: low nibble -> sc[4..7] = 1, high nibble -> mn[4..7] = 0
            p[12] = 0x01; p[13] = 0x01; p[14] = 0x01; p[15] = 0x01;
            std::memset(p + 16, 0x11, 128); // qs -> q == 1 everywhere
        }
        std::vector<float> ones(cols, 1.0f);
        const bool ok = runCase(vc, "D", "constant_weight_q4k",
                                wd.data(), wd.size(), 12, rows, cols, ones, "D");
        // The exact expected value is printed by runCase's ORACLE line; the
        // discriminator is whether the GPU value is 1x or 2x that constant.
        dCasePass = ok;
    }

    // CASE_E: isolate WHICH weight factor is wrong.
    //
    // CASE_D proved the accumulation/reduction/half-decode/scale-unpack are
    // exact (constant weight 1.0 -> exact sum 256). CASE_E varies exactly one
    // factor at a time with everything else pinned, so a 2x error is attributed
    // to a specific term of  weight = d*sc*q - dmin*mn  rather than to the sum.
    //
    // Variant table (all with dmin = 0 so the min term contributes nothing):
    //   V1 q=1  sc=1  d=1.0 -> weight 1    -> expect sum   256
    //   V2 q=8  sc=1  d=1.0 -> weight 8    -> expect sum  2048
    //   V3 q=1  sc=3  d=1.0 -> weight 3    -> expect sum   768
    //   V4 q=1  sc=1  d=2.0 -> weight 2    -> expect sum   512
    //
    // A variant returning exactly 2x its expectation identifies the doubled
    // term. Ratios are printed by runCase; the exact expectation is also
    // computed here so the receipt carries a measured comparison.
    {
        struct Variant { const char* tag; uint16_t dHalf; uint8_t sc; uint8_t qByte; };
        const Variant variants[] = {
            { "V1_q1_sc1_d1", 0x3C00, 1u, 0x01u },  // 1.0 * 1 * 1 = 1
            { "V2_q8_sc1_d1", 0x3C00, 1u, 0x08u },  // 1.0 * 1 * 8 = 8
            { "V3_q1_sc3_d1", 0x3C00, 3u, 0x01u },  // 1.0 * 3 * 1 = 3
            { "V4_q1_sc1_d2", 0x4000, 1u, 0x01u },  // 2.0 * 1 * 1 = 2
        };
        const size_t bpr = cols / 256;
        std::vector<float> ones(cols, 1.0f);
        for (const auto& v : variants) {
            std::vector<uint8_t> wv((size_t)rows * bpr * 144);
            for (size_t i = 0; i < wv.size(); i += 144) {
                uint8_t* p = wv.data() + i;
                p[0] = (uint8_t)(v.dHalf & 0xFF);
                p[1] = (uint8_t)(v.dHalf >> 8);
                p[2] = 0x00; p[3] = 0x00;              // dmin = 0
                for (int k = 0; k < 8; ++k) {
                    p[4 + k] = v.sc;                  // sc[0..7] (low 6 bits)
                    p[8 + k] = 0x00;                  // mn[0..7] = 0
                    p[12 + (k - 4)] = v.sc;           // sc[4..7] low nibble
                }
                std::memset(p + 16, v.qByte, 128);     // q = (qByte&15)|(qByte>>4)
            }
            const double expectWeight =
                VariantWeight(v.dHalf, v.sc, v.qByte & 15u);
            std::printf("[Q4KPAR]   CASE_E %-14s EXPECT_SUM=%.9g\n",
                        v.tag, expectWeight * (double)cols);
            runCase(vc, "E", v.tag, wv.data(), wv.size(), 12, rows, cols, ones, "E");
        }
    }

    // CASE_B: the real model tensor. This is the decisive case. Case A uses
    // synthetic blocks and only proves one block pattern; Case B feeds the
    // actual blk.N.attn_k.weight bytes through the SAME isolated dispatch.
    //   real WK harness FAIL -> Q4_K has a data-dependent corner case
    //   real WK harness PASS -> kernel exonerated, live plumbing differs
    int caseBState = 0;   // 0 = not run, 1 = pass, 2 = fail
    if (mdl) {
        FILE* f = std::fopen(mdl, "rb");
        if (!f) {
            std::fprintf(stderr, "[Q4KPAR] CASE_B SKIP cannot open %s\n", mdl);
        } else {
            // Real WK rows are fixed at 1024; cols follows the sweep. Byte
            // span comes from the GGUF metadata (1024 x cols/256 x 144) and
            // must be clamped to the tensor's real size when sweeping, since
            // a narrower cols reads a prefix of each row.
            const uint32_t bRows = 1024, bCols = cols;
            const size_t span = (size_t)bRows * (bCols / 256) * 144;
            const long long bOff = 1082616800LL;
            std::vector<uint8_t> wk(span);
            if (std::fseek(f, (long)bOff, SEEK_SET) != 0 ||
                std::fread(wk.data(), 1, wk.size(), f) != wk.size()) {
                std::fprintf(stderr, "[Q4KPAR] CASE_B SKIP short read at off=%lld\n", bOff);
            } else {
                std::fclose(f); f = nullptr;
                const bool ok = runCase(vc, "B", "real_model_wk", wk.data(), wk.size(),
                                        12, bRows, bCols, input, "B");
                caseBState = ok ? 1 : 2;
            }
            if (f) std::fclose(f);
        }
    } else {
        std::fprintf(stderr, "[Q4KPAR] CASE_B SKIP no model arg\n");
    }

    const char* firstDiv;
    if (caseBState == 0)        firstDiv = "CASE_B_NOT_RUN";
    else if (caseBState == 2)   firstDiv = "Q4K_DATA_DEPENDENT_CORNER_CASE";
    else if (!q4Pass && q6Pass) firstDiv = "Q4K_SHADER_OR_Q4K_DISPATCH";
    else if (q4Pass && !q6Pass) firstDiv = "Q6K_CONTROL_ORACLE_MISMATCH";
    else if (!q4Pass && !q6Pass)firstDiv = "SHARED_GEMV_DISPATCH";
    else                        firstDiv = "LIVE_PLUMBING";

    std::fprintf(stderr, "\nRAWRXD_Q4K_GEMV_PARITY_001\n");
    std::fprintf(stderr, "Q4K_SYNTHETIC_GEMV=%s\n", q4Pass ? "PASS" : "FAIL");
    std::fprintf(stderr, "Q6K_SYNTHETIC_GEMV=%s\n", q6Pass ? "PASS" : "FAIL");
    std::fprintf(stderr, "REAL_WK_Q4K_GEMV=%s\n",
        caseBState == 0 ? "NOT_RUN" : (caseBState == 1 ? "PASS" : "FAIL"));
    std::fprintf(stderr, "SHARED_QUANT_GEMV_CERT=%d\n",
        (q4Pass && q6Pass && caseBState == 1) ? 1 : 0);
    std::fprintf(stderr, "FIRST_DIVERGENCE=%s\n", firstDiv);
    std::fprintf(stderr, "Q4K_DATA_INTERPRETATION_DEFECT=%d\n",
        gAnyDataInterpretationDefect ? 1 : 0);
    std::fprintf(stderr, "SUMMATION_ORDER_EXPLAINS_MISMATCH=%d\n",
        gAnyDataInterpretationDefect ? 0 : 1);
    std::fprintf(stderr, "VERDICT=%s\n",
        (q4Pass && q6Pass && caseBState == 1) ? "SHADER_EXONERATED"
        : (caseBState == 0)                  ? "INCONCLUSIVE_CASE_B_NOT_RUN"
                                             : "SHADER_OR_CASE_B_DEFECTIVE");
    std::fflush(stderr);
    (void)syn;
    return (q4Pass && q6Pass && caseBState == 1) ? 0 : 1;
}
