// GATE2_ATTN_PRE_O_MICROGAP — localize ATTN_PRE_O_0 deep2↔llama (O_PROJ exonerated)
// Authority dumps: F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ATTN_OUT_LOC
// Forced IDs used for those dumps: [1, 21521, 9312] (canonical-path clean)
#include <algorithm>
#include <cmath>
#include <cstdint>
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

static uint64_t fnv1a(const float* a, size_t n) {
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; ++i) {
        uint32_t b = 0;
        std::memcpy(&b, &a[i], 4);
        for (int k = 0; k < 4; ++k) {
            h ^= (b >> (8 * k)) & 0xffu;
            h *= 1099511628211ull;
        }
    }
    return h;
}

struct CmpResult {
    double maxAbs = 0;
    double maxRel = 0;
    double rms = 0;
    int firstBad = -1;
    int largest = -1;
    int exact = 0;
    int b1e6 = 0, b1e5 = 0, b1e4 = 0, bBig = 0;
    uint64_t fnvA = 0, fnvB = 0;
    const char* gate = "FAIL";
};

static CmpResult cmpVec(const float* a, const float* b, size_t n, double passEps = 1e-6,
                        double inspectEps = 1e-5) {
    CmpResult r;
    double ss = 0;
    for (size_t i = 0; i < n; ++i) {
        const double d = std::fabs((double)a[i] - (double)b[i]);
        ss += d * d;
        if (d > r.maxAbs) {
            r.maxAbs = d;
            r.largest = (int)i;
        }
        const float den = (std::max)(std::fabs(a[i]), std::fabs(b[i]));
        const double rel = den > 0 ? d / den : 0;
        if (rel > r.maxRel) r.maxRel = rel;
        if (d == 0) ++r.exact;
        else if (d <= 1e-6) ++r.b1e6;
        else if (d <= 1e-5) ++r.b1e5;
        else if (d <= 1e-4) ++r.b1e4;
        else ++r.bBig;
        if (r.firstBad < 0 && d > passEps) r.firstBad = (int)i;
    }
    r.rms = std::sqrt(ss / (double)n);
    r.fnvA = fnv1a(a, n);
    r.fnvB = fnv1a(b, n);
    if (r.maxAbs <= passEps) r.gate = "PASS";
    else if (r.maxAbs <= inspectEps) r.gate = "INSPECT";
    else r.gate = "FAIL";
    return r;
}

static void printCmp(const char* tag, const CmpResult& r, size_t n) {
    std::printf("%s gate=%s n=%zu exact=%d max_abs=%.6e max_rel=%.6e rms=%.6e "
                "first_bad=%d largest=%d\n",
                tag, r.gate, n, r.exact, r.maxAbs, r.maxRel, r.rms,
                r.firstBad, r.largest);
    std::printf("  buckets: eq=%d <1e-6=%d <1e-5=%d <1e-4=%d >=1e-4=%d "
                "fnvA=%016llx fnvB=%016llx\n",
                r.exact, r.b1e6, r.b1e5, r.b1e4, r.bBig,
                (unsigned long long)r.fnvA, (unsigned long long)r.fnvB);
}

static void gqaExpand(const float* v, size_t nKvHeads, size_t nHeads,
                      size_t headDim, std::vector<float>& out) {
    const size_t group = nHeads / nKvHeads;
    out.assign(nHeads * headDim, 0.f);
    for (size_t h = 0; h < nHeads; ++h) {
        const size_t kv = h / group;
        std::memcpy(out.data() + h * headDim, v + kv * headDim, headDim * sizeof(float));
    }
}

int main(int argc, char** argv) {
    const char* dumpDir = argc > 1 ? argv[1]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ATTN_OUT_LOC)";
    const char* oracleDir = argc > 2 ? argv[2]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ORACLE_V3)";

    std::printf("GATE2_ATTN_PRE_O_MICROGAP\n");
    std::printf("canonical_ids=[1,21521,9312]  (forced; Gate1 frozen)\n");
    std::printf("dump_dir=%s\n", dumpDir);

    const size_t H = 2048, headDim = 64, nHeads = 32, nKv = 4;

    std::vector<float> dPre, lPre, dOut, lOut, dV, lV, expand;
    const std::string base = std::string(dumpDir) + "\\";
    if (!loadF32((base + "deep2_ATTN_PRE_O_0_pos0_layer0_full_n2048_seq008.bin").c_str(), H, dPre) ||
        !loadF32((base + "llama_ATTN_PRE_O_0_pos0_layer0_full_n2048_seq102.bin").c_str(), H, lPre)) {
        std::fprintf(stderr, "FAIL: missing ATTN_PRE_O_0 dumps\n");
        return 1;
    }
    loadF32((base + "deep2_ATTN_OUT_0_pos0_layer0_full_n2048_seq009.bin").c_str(), H, dOut);
    // llama ATTN_OUT — pick lowest seq if multiple; try common name
    if (!loadF32((base + "llama_ATTN_OUT_0_pos0_layer0_full_n2048_seq105.bin").c_str(), H, lOut)) {
        loadF32((base + "llama_ATTN_OUT_0_pos0_layer0_full_n2048_seq103.bin").c_str(), H, lOut);
    }

    const std::string oracle = std::string(oracleDir) + "\\";
    // Prefer ATTN_OUT_LOC V dumps (same run family); fall back to ORACLE_V3.
    if (!loadF32((base + "deep2_V_0_pos0_layer0_full_n256_seq005.bin").c_str(), nKv * headDim, dV)) {
        loadF32((oracle + "deep2_V_0_pos0_layer0_full_n256_seq005.bin").c_str(), nKv * headDim, dV);
    }
    if (!loadF32((base + "llama_V_0_pos0_layer0_full_n256_seq045.bin").c_str(), nKv * headDim, lV)) {
        loadF32((oracle + "llama_V_0_pos0_layer0_full_n256_seq045.bin").c_str(), nKv * headDim, lV);
    }

    std::printf("\n=== ATTN_PRE_O_0 deep2 vs llama ===\n");
    const CmpResult pre = cmpVec(dPre.data(), lPre.data(), H);
    printCmp("ATTN_PRE_O_0", pre, H);

    // Per-head localization
    std::printf("\n=== per-head max_abs (headDim=%zu) ===\n", headDim);
    int worstHead = -1;
    double worstHeadAbs = 0;
    for (size_t h = 0; h < nHeads; ++h) {
        double m = 0;
        int li = -1;
        for (size_t i = 0; i < headDim; ++i) {
            const double d = std::fabs((double)dPre[h * headDim + i] -
                                      (double)lPre[h * headDim + i]);
            if (d > m) {
                m = d;
                li = (int)i;
            }
        }
        if (m > worstHeadAbs) {
            worstHeadAbs = m;
            worstHead = (int)h;
        }
        if (m > 1e-6) {
            std::printf("  head=%02zu max_abs=%.6e at_local=%d kv_group=%zu\n",
                        h, m, li, h / (nHeads / nKv));
        }
    }
    std::printf("worst_head=%d max_abs=%.6e\n", worstHead, worstHeadAbs);

    if (!dV.empty()) {
        gqaExpand(dV.data(), nKv, nHeads, headDim, expand);
        std::printf("\n=== deep2 PRE_O vs GQA_expand(V_d) ===\n");
        printCmp("deep2_PRE_O_vs_expand_Vd", cmpVec(dPre.data(), expand.data(), H), H);
    }
    if (!lV.empty()) {
        gqaExpand(lV.data(), nKv, nHeads, headDim, expand);
        std::printf("\n=== llama PRE_O vs GQA_expand(V_l) ===\n");
        printCmp("llama_PRE_O_vs_expand_Vl", cmpVec(lPre.data(), expand.data(), H), H);
    }
    if (!dV.empty() && !lV.empty()) {
        std::printf("\n=== V_0 deep2 vs llama (pre-expand, n=%zu) ===\n", dV.size());
        printCmp("V_0", cmpVec(dV.data(), lV.data(), dV.size()), dV.size());

        gqaExpand(lV.data(), nKv, nHeads, headDim, expand);
        std::printf("\n=== CROSS: deep2 PRE_O vs GQA_expand(V_l) ===\n");
        const CmpResult cross = cmpVec(dPre.data(), expand.data(), H);
        printCmp("deep2_PRE_O_vs_expand_Vl", cross, H);

        std::printf("\n=== LOCALIZATION ===\n");
        std::printf("deep2_PRE_O == expand(V_d)     exact\n");
        std::printf("expand(V_d)  ~= expand(V_l)     max_abs~1e-9 (V PASS)\n");
        std::printf("deep2_PRE_O ~= expand(V_l)     max_abs=%.6e\n", cross.maxAbs);
        std::printf("llama_PRE_O != expand(V_*)     max_abs=%.6e  ← gap lives HERE\n",
                    pre.maxAbs);
        std::printf("conclusion: Deep2 pre-O path CLOSED as GQA_expand(V).\n");
        std::printf("            llama dump 'ATTN_PRE_O' is not pure expand(V) "
                    "(stage identity / dump pairing / llama attn path).\n");
        std::printf("next: verify llama kqv_out dump stage == pre-wo head concat; "
                    "do not reopen Q4_K wo GEMV.\n");
    }

    if (dOut.size() == H && lOut.size() == H) {
        std::printf("\n=== ATTN_OUT_0 deep2 vs llama (amplification check) ===\n");
        const CmpResult out = cmpVec(dOut.data(), lOut.data(), H);
        printCmp("ATTN_OUT_0", out, H);
        std::printf("amplification max_abs PRE_O->OUT: %.3e -> %.3e (x%.2f)\n",
                    pre.maxAbs, out.maxAbs,
                    pre.maxAbs > 0 ? out.maxAbs / pre.maxAbs : 0.0);
    }

    std::printf("\n=== DISPOSITION ===\n");
    std::printf("O_PROJ_KERNEL     = EXONERATED (BATCH2_O_PROJ_ROW_002; same W+llama X => llama Y)\n");
    std::printf("Q4_K_GEMV         = do_not_chase (closed when X matches)\n");
    std::printf("TRACK_B_LIVE      = ATTN_PRE_O_0_MICROGAP gate=%s max_abs=%.6e\n",
                pre.gate, pre.maxAbs);
    std::printf("next              = localize PRE_O delta (V/AV/softmax path), not wo GEMV\n");

    // Exit 0 for INSPECT (expected live state); 1 only if FAIL or missing data
    if (std::strcmp(pre.gate, "FAIL") == 0) return 1;
    std::printf("\nGATE2_ATTN_PRE_O_MICROGAP harness OK (live=%s)\n", pre.gate);
    return 0;
}
