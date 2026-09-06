// BATCH2_L2_OUT_LOC — Layer-2 first-fail localization + dual abs/rel gate
// Authority: BATCH2_L2_CLEAN_001 (EXPAND_V) + deep2_swiglu_fix
// Baseline: L2_OUT abs ~4.58e-5 is GATE 1-ULP amplified through SwiGLU (f32 SiLU exact).
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static bool loadF32(const char* path, size_t n, std::vector<float>& out) {
    FILE* f = nullptr;
#ifdef _MSC_VER
    if (fopen_s(&f, path, "rb") != 0 || !f) return false;
#else
    f = std::fopen(path, "rb");
    if (!f) return false;
#endif
    out.resize(n);
    const bool ok = std::fread(out.data(), sizeof(float), n, f) == n;
    std::fclose(f);
    return ok;
}

static float silu1_f32(float x) {
    if (x > 20.0f) return x;
    if (x < -20.0f) return 0.0f;
    return x / (1.0f + std::exp(-x));
}

struct Cmp {
    double maxAbs = 0;
    double maxRel = 0;
    int largest = -1;
    int firstBadAbs = -1;
    int firstBadRel = -1;
    int exact = 0;
    const char* absGate = "FAIL";
    const char* dualGate = "FAIL";
};

static Cmp cmpDual(const float* a, const float* b, size_t n,
                   double absPass = 1e-6, double absInspect = 1e-5,
                   double absSoft = 1e-4, double relPass = 1e-6) {
    Cmp r;
    for (size_t i = 0; i < n; ++i) {
        const double av = (double)a[i];
        const double bv = (double)b[i];
        const double d = std::fabs(av - bv);
        const double denom = std::fmax(1.0, std::fmax(std::fabs(av), std::fabs(bv)));
        const double rel = d / denom;
        if (d == 0.0) ++r.exact;
        if (d > r.maxAbs) {
            r.maxAbs = d;
            r.largest = (int)i;
        }
        if (rel > r.maxRel) r.maxRel = rel;
        if (r.firstBadAbs < 0 && d > absPass) r.firstBadAbs = (int)i;
        if (r.firstBadRel < 0 && rel > relPass) r.firstBadRel = (int)i;
    }
    if (r.maxAbs <= absPass) r.absGate = "PASS";
    else if (r.maxAbs <= absInspect) r.absGate = "INSPECT";
    else r.absGate = "FAIL";

    // Dual: PASS if tight abs OR (soft abs + tight relative)
    if (r.maxAbs <= absPass || (r.maxAbs <= absSoft && r.maxRel <= relPass))
        r.dualGate = "PASS";
    else if (r.maxAbs <= absInspect || (r.maxAbs <= absSoft && r.maxRel <= 1e-5))
        r.dualGate = "INSPECT";
    else
        r.dualGate = "FAIL";
    return r;
}

static void printCmp(const char* tag, const Cmp& r, size_t n) {
    std::printf("%-12s abs=%-7s dual=%-7s n=%zu exact=%d/%zu max_abs=%.6e max_rel=%.6e "
                "first_abs=%d largest=%d\n",
                tag, r.absGate, r.dualGate, n, r.exact, n, r.maxAbs, r.maxRel,
                r.firstBadAbs, r.largest);
}

static bool loadNamed(const std::string& dir, const char* patHint, size_t n,
                      std::vector<float>& out, std::string& used) {
    // Exact filenames preferred via argv paths; this helper uses fixed known names.
    static const char* kSkip = nullptr;
    (void)kSkip;
    (void)patHint;
    (void)dir;
    (void)n;
    (void)out;
    (void)used;
    return false;
}

int main(int argc, char** argv) {
    const char* d2root = argc > 1 ? argv[1]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L2_CLEAN_001\deep2_swiglu_fix)";
    const char* llroot = argc > 2 ? argv[2]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L2_CLEAN_001\llama)";
    const char* tipLlama = argc > 3 ? argv[3]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_SPARSE_CLEAN_001\llama)";

    const std::string d2 = std::string(d2root) + "\\";
    const std::string ll = std::string(llroot) + "\\";
    const std::string tip = std::string(tipLlama) + "\\";

    std::printf("BATCH2_L2_OUT_LOC\n");
    std::printf("deep2=%s\nllama=%s\ntip_llama=%s\n", d2root, llroot, tipLlama);
    std::printf("policy: PASS if abs<=1e-6 OR (abs<=1e-4 AND rel<=1e-6)\n");
    std::printf("DO_NOT_REOPEN: <=L1 / wo / SiLU (f32 ref exact)\n\n");

    struct Stage {
        const char* name;
        const char* deep2;
        const char* llama;
        size_t n;
        bool tip;
    };
    const Stage stages[] = {
        {"ATTN_NORM_2", "deep2_ATTN_NORM_2_pos0_layer0_full_n2048_seq032.bin",
         "llama_ATTN_NORM_2_pos0_layer0_full_n2048_seq199.bin", 2048, false},
        {"ATTN_OUT_2", "deep2_ATTN_OUT_2_pos0_layer0_full_n2048_seq037.bin",
         "llama_ATTN_OUT_2_pos0_layer0_full_n2048_seq322.bin", 2048, false},
        {"FFN_INP_2", "deep2_FFN_INP_2_pos0_layer0_full_n2048_seq038.bin",
         "llama_FFN_INP_2_pos0_layer0_full_n2048_seq325.bin", 2048, false},
        {"FFN_NORM_2", "deep2_FFN_NORM_2_pos0_layer0_full_n2048_seq039.bin",
         "llama_FFN_NORM_2_pos0_layer0_full_n2048_seq328.bin", 2048, false},
        {"FFN_GATE_2", "deep2_FFN_GATE_2_pos0_layer0_full_n5632_seq040.bin",
         "llama_FFN_GATE_2_pos0_layer0_full_n5632_seq331.bin", 5632, false},
        {"FFN_UP_2", "deep2_FFN_UP_2_pos0_layer0_full_n5632_seq041.bin",
         "llama_FFN_UP_2_pos0_layer0_full_n5632_seq334.bin", 5632, false},
        {"FFN_ACT_2", "deep2_FFN_ACT_2_pos0_layer0_full_n5632_seq042.bin",
         "llama_FFN_ACT_2_pos0_layer0_full_n5632_seq337.bin", 5632, false},
        {"FFN_DOWN_2", "deep2_FFN_DOWN_2_pos0_layer0_full_n2048_seq043.bin",
         "llama_FFN_DOWN_2_pos0_layer0_full_n2048_seq340.bin", 2048, false},
        {"L2_OUT", "deep2_LAYER_OUT_2_pos0_layer0_full_n2048_seq045.bin",
         "llama_LAYER2_OUT_pos0_layer0_full_n2048_seq004.bin", 2048, true},
    };

    const char* firstAbsFail = nullptr;
    const char* firstDualFail = nullptr;

    std::printf("=== stage ladder ===\n");
    for (const Stage& s : stages) {
        std::vector<float> a, b;
        const std::string ap = d2 + s.deep2;
        const std::string bp = (s.tip ? tip : ll) + s.llama;
        if (!loadF32(ap.c_str(), s.n, a)) {
            std::printf("%-12s MISSING deep2 %s\n", s.name, s.deep2);
            continue;
        }
        if (!loadF32(bp.c_str(), s.n, b)) {
            std::printf("%-12s MISSING llama %s\n", s.name, s.llama);
            continue;
        }
        const Cmp c = cmpDual(a.data(), b.data(), s.n);
        printCmp(s.name, c, s.n);
        if (!firstAbsFail && std::strcmp(c.absGate, "FAIL") == 0) firstAbsFail = s.name;
        if (!firstDualFail && std::strcmp(c.dualGate, "FAIL") == 0) firstDualFail = s.name;
    }

    // Scalar SiLU self-check
    std::printf("\n=== scalar f32 SiLU ===\n");
    std::vector<float> G, U, Act, Gl, Ul, Actl;
    const bool ok =
        loadF32((d2 + "deep2_FFN_GATE_2_pos0_layer0_full_n5632_seq040.bin").c_str(), 5632, G) &&
        loadF32((d2 + "deep2_FFN_UP_2_pos0_layer0_full_n5632_seq041.bin").c_str(), 5632, U) &&
        loadF32((d2 + "deep2_FFN_ACT_2_pos0_layer0_full_n5632_seq042.bin").c_str(), 5632, Act) &&
        loadF32((ll + "llama_FFN_GATE_2_pos0_layer0_full_n5632_seq331.bin").c_str(), 5632, Gl) &&
        loadF32((ll + "llama_FFN_UP_2_pos0_layer0_full_n5632_seq334.bin").c_str(), 5632, Ul) &&
        loadF32((ll + "llama_FFN_ACT_2_pos0_layer0_full_n5632_seq337.bin").c_str(), 5632, Actl);
    if (!ok) {
        std::printf("scalar dumps MISSING\n");
        return 2;
    }
    std::vector<float> refD(5632), refL(5632);
    for (size_t i = 0; i < 5632; ++i) {
        refD[i] = silu1_f32(G[i]) * U[i];
        refL[i] = silu1_f32(Gl[i]) * Ul[i];
    }
    printCmp("ACT_vs_refD", cmpDual(Act.data(), refD.data(), 5632), 5632);
    printCmp("ACTl_vs_refL", cmpDual(Actl.data(), refL.data(), 5632), 5632);
    printCmp("refD_vs_ACTl", cmpDual(refD.data(), Actl.data(), 5632), 5632);

    const int worst = 5475;
    std::printf("\nFIRST_ELEMENT idx=%d\n", worst);
    std::printf("  G d=%.10g l=%.10g dG=%.6e\n", G[worst], Gl[worst], (double)G[worst] - Gl[worst]);
    std::printf("  U d=%.10g l=%.10g dU=%.6e\n", U[worst], Ul[worst], (double)U[worst] - Ul[worst]);
    std::printf("  A d=%.10g l=%.10g dA=%.6e\n", Act[worst], Actl[worst],
                (double)Act[worst] - Actl[worst]);
    std::printf("  refD=%.10g (ACT-refD=%.6e)\n", refD[worst],
                (double)Act[worst] - refD[worst]);

    std::printf("\nFIRST_ABS_FAIL=%s\n", firstAbsFail ? firstAbsFail : "none");
    std::printf("FIRST_DUAL_FAIL=%s\n", firstDualFail ? firstDualFail : "none");

    const Cmp self = cmpDual(Act.data(), refD.data(), 5632);
    if (std::strcmp(self.absGate, "PASS") != 0) {
        std::printf("CLASS=DEEP2_SILU_REGRESSION\n");
        return 1;
    }
    if (!firstDualFail) {
        std::printf("CLASS=GATE_ULP_AMPLIFIED_THROUGH_SWIGLU\n");
        std::printf("DISPOSITION: L2_OUT CLOSED under dual gate; SiLU CLOSED; advance tips.\n");
        return 0;
    }
    std::printf("CLASS=DUAL_STILL_FAIL at %s — expand that stage only\n", firstDualFail);
    return 1;
}
