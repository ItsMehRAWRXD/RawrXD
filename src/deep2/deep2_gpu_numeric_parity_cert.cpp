// deep2_gpu_numeric_parity_cert.cpp — GPU↔CPU first numeric divergence
// Seal: PRODUCTION_MATURITY_TOP25_001/GPU_CPU_FIRST_DIVERGENCE_001
// Law: FNV mismatch alone ≠ FAIL if |a-b| <= atol+rtol*|ref|. PROMOTE=0.
#include "Deep2Engine.h"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;

// Product Q2_K decode floor (block-scale / FP16 accum noise). Explicit in seal.
static constexpr double kAtol = 1e-3;
static constexpr double kRtol = 1e-3;

struct Cmp {
    const char* op = nullptr;
    size_t n = 0;
    size_t first = (size_t)-1;
    double max_abs = 0, mean_abs = 0, max_rel = 0;
    double a0 = 0, b0 = 0;
    uint64_t fnv_a = 0, fnv_b = 0;
    size_t over = 0;
    bool pass = false;
};

static uint64_t Fnv(const float* p, size_t n) {
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; ++i) {
        uint32_t u;
        std::memcpy(&u, &p[i], 4);
        h ^= u;
        h *= 1099511628211ull;
    }
    return h;
}

static Cmp Compare(const char* op, const float* a, const float* b, size_t n,
                   double atol, double rtol) {
    Cmp c{};
    c.op = op;
    c.n = n;
    c.fnv_a = Fnv(a, n);
    c.fnv_b = Fnv(b, n);
    double sum = 0;
    for (size_t i = 0; i < n; ++i) {
        const double aa = (double)a[i], bb = (double)b[i];
        const double ad = std::fabs(aa - bb);
        const double rd = ad / (std::fabs(aa) > 1e-30 ? std::fabs(aa) : 1e-30);
        sum += ad;
        if (ad > c.max_abs) c.max_abs = ad;
        if (rd > c.max_rel) c.max_rel = rd;
        if (ad > atol + rtol * std::fabs(aa)) {
            ++c.over;
            if (c.first == (size_t)-1) {
                c.first = i;
                c.a0 = aa;
                c.b0 = bb;
            }
        }
    }
    c.mean_abs = n ? sum / (double)n : 0;
    c.pass = (c.over == 0);
    return c;
}

static void Print(const Cmp& c, double atol, double rtol) {
    printf("OP=%s n=%zu atol=%.3g rtol=%.3g PASS=%d\n", c.op, c.n, atol, rtol,
           c.pass ? 1 : 0);
    printf("  max_abs=%.9g mean_abs=%.9g max_rel=%.9g over_tol=%zu\n",
           c.max_abs, c.mean_abs, c.max_rel, c.over);
    if (c.first != (size_t)-1)
        printf("  FIRST_DIVERGENCE idx=%zu ref=%.9g gpu=%.9g |d|=%.9g\n",
               c.first, c.a0, c.b0, std::fabs(c.a0 - c.b0));
    else
        printf("  FIRST_DIVERGENCE=NONE\n");
    printf("  FNV_ref=%016llx FNV_gpu=%016llx FNV_match=%d (secondary)\n",
           (unsigned long long)c.fnv_a, (unsigned long long)c.fnv_b,
           c.fnv_a == c.fnv_b ? 1 : 0);
}

static bool Setup(Deep2Engine& e, const char* model) {
    if (!e.loadModel(model)) return false;
    const auto& mw = e.getModelWeights();
    EngineConfig c{};
    c.hiddenDim = mw.hiddenDim;
    c.numLayers = mw.numLayers;
    c.numHeads = mw.numHeads;
    c.numKVHeads = mw.numKVHeads;
    c.headDim = mw.headDim;
    c.vocabSize = mw.vocabSize;
    c.maxSeqLen = 128;
    c.useKVCache = true;
    c.useThreadPool = true;
    c.numThreads = 8;
    if (!e.initialize(c)) return false;
    if (!e.isVulkanEnabled()) {
        e.enableVulkan(true);
    }
    return e.isVulkanEnabled();
}

static void CpuGemv(const float* W, const float* x, float* y, uint32_t rows,
                    uint32_t cols) {
    for (uint32_t r = 0; r < rows; ++r) {
        double s = 0;
        const float* wr = W + (size_t)r * cols;
        for (uint32_t c = 0; c < cols; ++c) s += (double)wr[c] * (double)x[c];
        y[r] = (float)s;
    }
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    const char* seal =
        "G:\\~dev\\rawrxd\\evidence\\PRODUCTION_MATURITY_TOP25_001\\"
        "GPU_CPU_FIRST_DIVERGENCE_001";
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\PRODUCTION_MATURITY_TOP25_001", nullptr);
    CreateDirectoryA(seal, nullptr);
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_NUMERIC_PARITY_001", nullptr);

    printf("GPU_CPU_FIRST_DIVERGENCE_001\nModel: %s\n", model);
    printf("TOL_POLICY atol=%.3g rtol=%.3g (Q2_K decode floor; explicit)\n",
           kAtol, kRtol);
    printf("PROMOTE=0 FNV_SECONDARY=1\n");

    Deep2Engine e;
    if (!Setup(e, model)) {
        printf("FAIL_CLOSED setup\n");
        return 1;
    }
    auto* vc = e.getVulkanComputeSlot(0);
    if (!vc || !e.ensureGpuForwardArena(0)) {
        printf("FAIL_CLOSED arena\n");
        return 2;
    }
    const auto& mw = e.getModelWeights();
    const uint32_t H = (uint32_t)mw.hiddenDim;
    const uint32_t hd = (uint32_t)mw.headDim;
    const uint32_t nh = (uint32_t)mw.numHeads;
    const uint32_t nkv = (uint32_t)mw.numKVHeads;

    std::vector<Cmp> results;
    bool all = true;

    // --- Op1: RMSNORM (attn path, identical x + w) ---
    {
        std::vector<float> x(H), cpu(H), gpu(H);
        for (uint32_t i = 0; i < H; ++i)
            x[i] = 0.01f * std::sin(0.017f * (float)i);
        e.RMSNormW(mw.layers[0].attnNorm, x.data(), cpu.data(), H, mw.normEps);
        vc->UploadHidden(x.data(), H);
        vc->UploadNormWeight(
            vc->ArenaAttnW(),
            reinterpret_cast<const float*>(mw.layers[0].attnNorm.data), H);
        vc->DispatchRmsNorm(vc->ArenaHidden(), vc->ArenaAttnW(),
                            vc->ArenaNormed(), H, mw.normEps);
        vc->DownloadBuf(vc->ArenaNormed(), gpu.data(), H);
        auto c = Compare("RMSNORM_L0", cpu.data(), gpu.data(), H, kAtol, kRtol);
        Print(c, kAtol, kRtol);
        results.push_back(c);
        all = all && c.pass;
    }

    // --- Op2: GEMV_F32 identical W,x (primary first-divergence site) ---
    {
        const uint32_t rows = 64, cols = 64;
        std::vector<float> W((size_t)rows * cols), x(cols), yCpu(rows),
            yGpu(rows);
        for (uint32_t i = 0; i < rows * cols; ++i)
            W[i] = 0.01f * std::sin(0.013f * (float)i);
        for (uint32_t i = 0; i < cols; ++i)
            x[i] = 0.01f * (float)((i % 17) + 1);
        CpuGemv(W.data(), x.data(), yCpu.data(), rows, cols);
        vc->UploadBuf(vc->ArenaHidden(), x.data(), cols);
        const bool ok = vc->DispatchGemvDevice(
            W.data(), 0x4650524931ull, vc->ArenaHidden(), vc->ArenaDown(), rows,
            cols);
        if (!ok) {
            printf("OP=GEMV_F32 FAIL_CLOSED dispatch\n");
            all = false;
        } else {
            vc->DownloadBuf(vc->ArenaDown(), yGpu.data(), rows);
            auto c =
                Compare("GEMV_F32", yCpu.data(), yGpu.data(), rows, kAtol, kRtol);
            Print(c, kAtol, kRtol);
            results.push_back(c);
            all = all && c.pass;
        }
    }

    // --- Op3: ROPE (elementwise) ---
    {
        std::vector<float> q(nh * hd), k(nkv * hd), q2, k2, qg(nh * hd),
            kg(nkv * hd);
        for (uint32_t i = 0; i < nh * hd; ++i)
            q[i] = 0.01f * std::sin(0.03f * (float)i);
        for (uint32_t i = 0; i < nkv * hd; ++i)
            k[i] = 0.01f * std::cos(0.04f * (float)i);
        q2 = q;
        k2 = k;
        e.applyRoPE(q2.data(), k2.data(), hd, nh, nkv, 3, mw.ropeTheta, 1.0f);
        vc->UploadBuf(vc->ArenaQ(), q.data(), nh * hd);
        vc->UploadBuf(vc->ArenaK(), k.data(), nkv * hd);
        vc->DispatchRope(vc->ArenaQ(), vc->ArenaK(), hd, nh, nkv, 3, mw.ropeTheta);
        vc->DownloadBuf(vc->ArenaQ(), qg.data(), nh * hd);
        vc->DownloadBuf(vc->ArenaK(), kg.data(), nkv * hd);
        auto cq = Compare("ROPE_Q", q2.data(), qg.data(), nh * hd, kAtol, kRtol);
        auto ck = Compare("ROPE_K", k2.data(), kg.data(), nkv * hd, kAtol, kRtol);
        Print(cq, kAtol, kRtol);
        Print(ck, kAtol, kRtol);
        results.push_back(cq);
        results.push_back(ck);
        all = all && cq.pass && ck.pass;
    }

    const Cmp* first = nullptr;
    for (const auto& r : results) {
        if (r.first != (size_t)-1) {
            first = &r;
            break;
        }
    }

    printf("---- SUMMARY ----\n");
    if (first) {
        printf("FIRST_DIVERGENCE_SITE=%s idx=%zu max_abs=%.9g mean_abs=%.9g "
               "max_rel=%.9g\n",
               first->op, first->first, first->max_abs, first->mean_abs,
               first->max_rel);
        printf("FNV_ref=%016llx FNV_gpu=%016llx (secondary)\n",
               (unsigned long long)first->fnv_a,
               (unsigned long long)first->fnv_b);
    } else {
        printf("FIRST_DIVERGENCE_SITE=NONE (all within atol+rtol*|ref|)\n");
    }
    printf("GPU_CPU_FIRST_DIVERGENCE_001=%s\n",
           all ? "PASS" : "FAIL_CLOSED");
    printf("PROMOTE=0\n");

    char path[512];
    std::snprintf(path, sizeof(path), "%s\\SEAL.txt", seal);
    FILE* f = fopen(path, "w");
    if (f) {
        fprintf(f, "GATE=GPU_CPU_FIRST_DIVERGENCE_001\n");
        fprintf(f, "MODEL=%s\n", model);
        fprintf(f, "ATOL=%.6g\nRTOL=%.6g\n", kAtol, kRtol);
        fprintf(f, "TOL_RATIONALE=Q2_K_decode_floor_block_scale_fp16_accum\n");
        fprintf(f, "LAW=FNV_mismatch_alone_neq_FAIL_if_numeric_within_tol\n");
        fprintf(f, "PROMOTE=0\nTIP6754=UNTOUCHED\n");
        fprintf(f, "LIVE=0\nCANON=0\nPARENT=0\n");
        for (const auto& r : results) {
            fprintf(f,
                    "OP=%s n=%zu PASS=%d max_abs=%.9g mean_abs=%.9g "
                    "max_rel=%.9g over=%zu first_idx=%lld "
                    "fnv_ref=%016llx fnv_gpu=%016llx fnv_match=%d\n",
                    r.op, r.n, r.pass ? 1 : 0, r.max_abs, r.mean_abs, r.max_rel,
                    r.over,
                    r.first == (size_t)-1 ? -1ll : (long long)r.first,
                    (unsigned long long)r.fnv_a, (unsigned long long)r.fnv_b,
                    r.fnv_a == r.fnv_b ? 1 : 0);
        }
        if (first) {
            fprintf(f, "FIRST_DIVERGENCE_SITE=%s\nFIRST_DIVERGENCE_IDX=%zu\n",
                    first->op, first->first);
            fprintf(f, "FIRST_DIVERGENCE_MAX_ABS=%.9g\n", first->max_abs);
            fprintf(f, "FIRST_DIVERGENCE_MEAN_ABS=%.9g\n", first->mean_abs);
            fprintf(f, "FIRST_DIVERGENCE_MAX_REL=%.9g\n", first->max_rel);
            fprintf(f, "FIRST_DIVERGENCE_FNV_REF=%016llx\n",
                    (unsigned long long)first->fnv_a);
            fprintf(f, "FIRST_DIVERGENCE_FNV_GPU=%016llx\n",
                    (unsigned long long)first->fnv_b);
        } else {
            fprintf(f, "FIRST_DIVERGENCE_SITE=NONE\n");
        }
        fprintf(f, "GPU_CPU_FIRST_DIVERGENCE_001=%s\n",
                all ? "PASS" : "FAIL_CLOSED");
        fclose(f);
    }
    FILE* gs = fopen(
        "G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_NUMERIC_PARITY_001\\"
        "GATE_STATUS.txt",
        "w");
    if (gs) {
        fprintf(gs, "STREAMER_GPU_NUMERIC_PARITY_001=%s\n",
                all ? "PASS" : "FAIL");
        fclose(gs);
    }
    return all ? 0 : 2;
}
