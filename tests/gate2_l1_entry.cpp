// BATCH2_L1_ENTRY_001 — L1 entry after L0 frozen closed (clean-oracle only).
// Authority: BATCH2_CLEAN_FFN_ORACLE (FORCE_PRE_O). Do not use contaminated natives.
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
    std::printf("%-16s gate=%s n=%zu max_abs=%.6e first_bad=%d largest=%d\n",
                tag, r.gate, n, r.maxAbs, r.firstBad, r.largest);
}

int main() {
    const std::string root =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_CLEAN_FFN_ORACLE\)";
    const std::string d2 = root + "deep2\\";
    const size_t H = 2048;

    std::printf("BATCH2_L1_ENTRY_001\n");
    std::printf("prereq: LAYER0_OUT PASS (clean FORCE_PRE_O oracle)\n");
    std::printf("ids=[1,21521,9312] pos=0 abs_eps=1e-6\n");
    std::printf("authority=BATCH2_CLEAN_FFN_ORACLE\n");
    std::printf("L0=FROZEN — do not re-walk\n\n");

    struct Step {
        const char* name;
        const char* deep2;
        const char* llama;
        bool optional;
    };

    // Prefer prefill seq (lower) over decode-step (~3xxx).
    const Step steps[] = {
        {"LAYER0_OUT",
         "deep2_LAYER_OUT_0_pos0_layer0_full_n2048_seq018.bin",
         "llama_POST_FFN_0_pos0_layer0_full_n2048_seq130.bin",
         false},
        {"L1_ATTN_NORM",
         "deep2_ATTN_NORM_1_pos0_layer0_full_n2048_seq019.bin",
         "llama_TENS_attn_norm_1_pos0_layer0_full_n2048_seq133.bin",
         false},
        {"L1_Q_PRE_ROPE", nullptr, nullptr, true},
        {"L1_K_PRE_ROPE", nullptr, nullptr, true},
        {"L1_V", nullptr, nullptr, true},
        {"L1_ATTN_OUT",
         "deep2_ATTN_OUT_1_pos0_layer0_full_n2048_seq020.bin",
         "llama_TENS_attn_out_1_pos0_layer0_full_n2048_seq262.bin",
         false},
        {"L1_FFN_INP",
         "deep2_FFN_INP_1_pos0_layer0_full_n2048_seq021.bin",
         "llama_TENS_ffn_inp_1_pos0_layer0_full_n2048_seq265.bin",
         false},
        {"L1_LAYER_OUT",
         "deep2_LAYER_OUT_1_pos0_layer0_full_n2048_seq025.bin",
         "llama_TENS_l_out_1_pos0_layer0_full_n2048_seq283.bin",
         false},
    };

    const char* firstFail = nullptr;
    double attnOutGap = -1.0;
    std::printf("rung             result\n");
    std::printf("----------------------------------------------\n");

    for (const Step& st : steps) {
        if (!st.deep2 || !st.llama) {
            std::printf("%-16s MISSING dumps (instrumentation gap — not FAIL)\n", st.name);
            continue;
        }
        std::vector<float> a, b;
        const std::string pa = (std::strncmp(st.deep2, "deep2_", 6) == 0)
                                   ? (d2 + st.deep2)
                                   : (root + st.deep2);
        const std::string pb = root + st.llama;
        if (!loadF32(pa.c_str(), H, a) || !loadF32(pb.c_str(), H, b)) {
            std::printf("%-16s LOAD_FAIL deep2=%s llama=%s\n", st.name, pa.c_str(),
                        pb.c_str());
            if (!firstFail) firstFail = st.name;
            break;
        }
        const Cmp c = cmp(a.data(), b.data(), H);
        printCmp(st.name, c, H);
        if (std::strcmp(st.name, "L1_ATTN_OUT") == 0) attnOutGap = c.maxAbs;
        if (std::strcmp(c.gate, "FAIL") == 0) {
            if (!firstFail) firstFail = st.name;
            // Continue once for residual self-check context after ATTN_OUT FAIL.
            if (std::strcmp(st.name, "L1_ATTN_OUT") != 0) break;
        }
    }

    // Deep2 residual identity at L1 (independent of llama contamination).
    {
        std::vector<float> l0, a1, f1, recon(H);
        if (loadF32((d2 + "deep2_LAYER_OUT_0_pos0_layer0_full_n2048_seq018.bin").c_str(), H, l0) &&
            loadF32((d2 + "deep2_ATTN_OUT_1_pos0_layer0_full_n2048_seq020.bin").c_str(), H, a1) &&
            loadF32((d2 + "deep2_FFN_INP_1_pos0_layer0_full_n2048_seq021.bin").c_str(), H, f1)) {
            for (size_t i = 0; i < H; ++i) recon[i] = l0[i] + a1[i];
            std::printf("\n=== deep2 L1 residual: FFN_INP_1 vs (LAYER_OUT_0 + ATTN_OUT_1) ===\n");
            printCmp("L1_residual", cmp(f1.data(), recon.data(), H), H);
        }
    }

    std::printf("\nFIRST_FAIL=%s\n", firstFail ? firstFail : "none");
    if (!firstFail) {
        std::printf("DISPOSITION: L1 entry available rungs PASS under clean oracle.\n");
        std::printf("NEXT: sparse layer tips L2/L4/L8/L12/L16/L21 → FINAL_NORM → LOGITS.\n");
    } else if (std::strcmp(firstFail, "L1_ATTN_OUT") == 0) {
        std::printf("DISPOSITION: FIRST_FAIL=L1_ATTN_OUT max_abs~%.3e.\n", attnOutGap);
        std::printf("CLASSIFY: same-order gap as L0 native ATTN_OUT (~8e-5) after FORCE_PRE_O "
                    "only on L0 — treat as suspect L1 PRE_O/oracle contamination until "
                    "same-operands L1 PRE_O or O_PROJ clean compare.\n");
        std::printf("DO_NOT: jump to sparse tips; DO_NOT reopen L0.\n");
        std::printf("NEXT: L1_ATTN_PRE_O / same-operands wo @ L1 (BATCH2_L1_ATTN_OUT_LOC).\n");
    } else {
        std::printf("DISPOSITION: stop at FIRST_FAIL; localize before sparse tips.\n");
    }
    return firstFail ? 1 : 0;
}
