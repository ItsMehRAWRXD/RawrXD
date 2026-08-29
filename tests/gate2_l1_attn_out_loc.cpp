// BATCH2_L1_ATTN_OUT_LOC — L1 PRE_O / wo localization (do not promote native FAIL yet)
// Authority dumps: BATCH2_L1_CLEAN_001 (FORCE_PRE_O_EXPAND_V on L0+L1)
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

struct Cmp {
    double maxAbs = 0;
    int largest = -1;
    int firstBad = -1;
    const char* gate = "FAIL";
};

static Cmp cmp(const float* a, const float* b, size_t n,
               double passEps = 1e-6, double inspectEps = 1e-5) {
    Cmp r;
    for (size_t i = 0; i < n; ++i) {
        const double d = std::fabs((double)a[i] - (double)b[i]);
        if (d > r.maxAbs) {
            r.maxAbs = d;
            r.largest = (int)i;
        }
        if (r.firstBad < 0 && d > passEps) r.firstBad = (int)i;
    }
    if (r.maxAbs <= passEps) r.gate = "PASS";
    else if (r.maxAbs <= inspectEps) r.gate = "INSPECT";
    else r.gate = "FAIL";
    return r;
}

static void printCmp(const char* tag, const Cmp& r, size_t n) {
    std::printf("%-36s gate=%s n=%zu max_abs=%.6e first_bad=%d largest=%d\n",
                tag, r.gate, n, r.maxAbs, r.firstBad, r.largest);
}

static void gqaExpand(const float* v, std::vector<float>& out) {
    constexpr int nq = 32, nkv = 4, hd = 64;
    const int group = nq / nkv;
    out.assign(nq * hd, 0.f);
    for (int qh = 0; qh < nq; ++qh) {
        const int kv = qh / group;
        std::memcpy(out.data() + qh * hd, v + kv * hd, (size_t)hd * sizeof(float));
    }
}

int main(int argc, char** argv) {
    const char* root = argc > 1 ? argv[1]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L1_CLEAN_001)";
    const std::string d2 = std::string(root) + "\\deep2\\";
    const std::string ll = std::string(root) + "\\llama\\";
    constexpr size_t H = 2048, Vn = 256;

    std::printf("BATCH2_L1_ATTN_OUT_LOC\n");
    std::printf("ids=[1,21521,9312] pos=0 layer=1 abs_eps=1e-6\n");
    std::printf("root=%s\n", root);
    std::printf("DO_NOT: promote native L1_ATTN_OUT FAIL; DO_NOT inspect L1 FFN\n\n");

    std::vector<float> dV, lV, dPre, lPre, lPreForced, dOut, lOut, expand;

    const bool ok =
        loadF32((d2 + "deep2_V_1_pos0_layer0_full_n256_seq021.bin").c_str(), Vn, dV) &&
        loadF32((ll + "llama_V_1_pos0_layer0_full_n256_seq174.bin").c_str(), Vn, lV) &&
        loadF32((d2 + "deep2_ATTN_PRE_O_1_pos0_layer0_full_n2048_seq022.bin").c_str(), H, dPre) &&
        loadF32((ll + "llama_ATTN_PRE_O_1_pos0_layer0_full_n2048_seq232.bin").c_str(), H, lPre) &&
        loadF32((d2 + "deep2_ATTN_OUT_1_pos0_layer0_full_n2048_seq023.bin").c_str(), H, dOut) &&
        loadF32((ll + "llama_ATTN_OUT_1_pos0_layer0_full_n2048_seq235.bin").c_str(), H, lOut);

    if (!ok) {
        std::fprintf(stderr, "FAIL: missing required L1 V/PRE_O/OUT dumps under %s\n", root);
        return 2;
    }
    const bool hasForced =
        loadF32((ll + "llama_ATTN_PRE_O_FORCED_1_pos0_layer0_full_n2048_seq231.bin").c_str(),
                H, lPreForced);

    // Gate 1: Deep2 PRE_O vs GQA_expand(Deep2 V)
    gqaExpand(dV.data(), expand);
    std::printf("=== 1. Deep2 L1_PRE_O vs GQA_expand(Deep2 L1_V) ===\n");
    const Cmp g1 = cmp(dPre.data(), expand.data(), H);
    printCmp("deep2_PRE_O_vs_expand_Vd", g1, H);

    // Gate 2: llama PRE_O vs GQA_expand(llama V)
    gqaExpand(lV.data(), expand);
    std::printf("\n=== 2. llama L1_PRE_O vs GQA_expand(llama L1_V) ===\n");
    const Cmp g2 = cmp(lPre.data(), expand.data(), H);
    printCmp("llama_PRE_O_vs_expand_Vl", g2, H);
    if (hasForced) {
        const Cmp g2f = cmp(lPreForced.data(), expand.data(), H);
        printCmp("llama_PRE_O_FORCED_vs_expand_Vl", g2f, H);
    }

    // Gate 3: Deep2 V vs llama V
    std::printf("\n=== 3. Deep2 L1_V vs llama L1_V ===\n");
    const Cmp g3 = cmp(dV.data(), lV.data(), Vn);
    printCmp("V_1", g3, Vn);

    // Gate 4 proxy: Deep2 ATTN_OUT (== O(Deep2 PRE_O)) vs expand authority.
    // True O(expand(Vl)) requires wo apply; under attend=1 + PRE_O==expand(Vd),
    // Deep2_OUT is O(expand(Vd)). Cross-check vs llama OUT under FORCE.
    std::printf("\n=== 4. Deep2 L1_ATTN_OUT vs llama L1_ATTN_OUT (clean-oracle run) ===\n");
    const Cmp g4 = cmp(dOut.data(), lOut.data(), H);
    printCmp("ATTN_OUT_1_deep2_vs_llama", g4, H);

    // Also: Deep2 PRE_O vs expand(Vl) — input gap into wo
    gqaExpand(lV.data(), expand);
    std::printf("\n=== 4b. Deep2 L1_PRE_O vs GQA_expand(llama L1_V) ===\n");
    const Cmp g4b = cmp(dPre.data(), expand.data(), H);
    printCmp("deep2_PRE_O_vs_expand_Vl", g4b, H);

    // Gate 5 proxy (same-operands): if FORCE applied expand(V) and Deep2 PRE_O==expand(Vd)
    // and V_d~=V_l, then ATTN_OUT compare ≈ Gate A. Explicit forced X compare:
    std::printf("\n=== 5. same-operands Gate A proxy ===\n");
    std::printf("note: full Gate A = Deep2 wo(X) vs llama mul_mat(X) with frozen X.\n");
    std::printf("proxy: if PRE_O authorities match and ATTN_OUT PASSes under FORCE_EXPAND_V,\n");
    std::printf("       blk.1.attn_output is CLOSED at same-operands class.\n");
    if (hasForced) {
        const Cmp g5x = cmp(dPre.data(), lPreForced.data(), H);
        printCmp("X_deep2_PRE_O_vs_llama_FORCED", g5x, H);
    }
    printCmp("Y_ATTN_OUT_same_run", g4, H);

    // Classification
    std::printf("\n=== CLASSIFICATION ===\n");
    const bool oracleHygiene = (std::strcmp(g2.gate, "FAIL") == 0);
    const bool deep2PreClosed = (std::strcmp(g1.gate, "PASS") == 0);
    const bool vOk = (std::strcmp(g3.gate, "PASS") == 0 || std::strcmp(g3.gate, "INSPECT") == 0);
    const bool outOk = (std::strcmp(g4.gate, "PASS") == 0 || std::strcmp(g4.gate, "INSPECT") == 0);

    if (oracleHygiene) {
        std::printf("ROOT = ORACLE_HYGIENE\n");
        std::printf("reason: llama_PRE_O_1 != GQA_expand(llama_V_1) max_abs=%.6e\n", g2.maxAbs);
        std::printf("action: invalidate native L1_ATTN_OUT fail (BATCH2_L1_ENTRY_001)\n");
        if (hasForced && deep2PreClosed && outOk) {
            std::printf("NOTE: under FORCE_EXPAND_V, ATTN_OUT_1 deep2 vs llama gate=%s "
                        "max_abs=%.6e — treat as clean-oracle re-score.\n",
                        g4.gate, g4.maxAbs);
        }
    } else if (outOk && deep2PreClosed && vOk) {
        std::printf("ROOT = PRE_O/input-induced OR CLOSED\n");
        std::printf("blk.1.attn_output / wo = CLOSED (same-operands class under FORCE_EXPAND_V)\n");
        std::printf("native L1_ATTN_OUT gap from unclean oracle = INVALIDATED\n");
    } else if (!outOk && deep2PreClosed && !oracleHygiene && vOk) {
        std::printf("ROOT = FIRST_GENUINE_DEEP2_L1_DEFECT (candidate)\n");
        std::printf("reason: llama_PRE_O hygiene PASS, V PASS, but ATTN_OUT FAIL max_abs=%.6e\n",
                    g4.maxAbs);
        std::printf("next: explicit Gate A mul_mat with frozen X=deep2_ATTN_PRE_O_1\n");
    } else {
        std::printf("ROOT = NEEDS_MORE_EVIDENCE\n");
        std::printf("deep2_PRE_O_closed=%d v_ok=%d out_ok=%d oracle_hygiene=%d\n",
                    deep2PreClosed ? 1 : 0, vOk ? 1 : 0, outOk ? 1 : 0,
                    oracleHygiene ? 1 : 0);
    }

    std::printf("\nDO_NOT_INSPECT_L1_FFN_YET\n");
    std::printf("NEXT: if CLOSED → re-score L1_ATTN_OUT then L1 FFN under clean PRE_O;\n");
    std::printf("      if ORACLE_HYGIENE only → keep native fail invalidated; use FORCE_EXPAND path.\n");
    return 0;
}
