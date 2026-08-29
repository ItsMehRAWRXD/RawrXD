// BATCH2_L1_FFN_LADDER_001 — clean-oracle L1 FFN after ATTN_OUT CLOSED
// Authority: BATCH2_L1_CLEAN_001 (FORCE_PRE_O_EXPAND_V L0+L1)
// Do not reopen L0 / QKV / PRE_O / wo.
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

static int argmax(const float* a, size_t n) {
    int best = 0;
    float mv = a[0];
    for (size_t i = 1; i < n; ++i) {
        if (a[i] > mv) {
            mv = a[i];
            best = (int)i;
        }
    }
    return best;
}

int main(int argc, char** argv) {
    const char* root = argc > 1 ? argv[1]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L1_CLEAN_001)";
    const std::string d2 = std::string(root) + "\\deep2\\";
    const std::string ll = std::string(root) + "\\llama\\";

    std::printf("BATCH2_L1_FFN_LADDER_001\n");
    std::printf("authority=%s\n", root);
    std::printf("ids=[1,21521,9312] pos=0 abs_eps=1e-6\n");
    std::printf("prereq: L1_ATTN_OUT CLOSED (BATCH2_L1_ATTN_OUT_LOC)\n");
    std::printf("DO_NOT_REOPEN: L0 | QKV | PRE_O | wo\n\n");

    struct Step {
        const char* name;
        const char* deep2;
        const char* llama;
        size_t n;
        bool optional;
    };

    const Step ffn[] = {
        {"L1_FFN_INP",
         "deep2_FFN_INP_1_pos0_layer0_full_n2048_seq024.bin",
         "llama_FFN_INP_1_pos0_layer0_full_n2048_seq238.bin", 2048, false},
        {"L1_FFN_NORM",
         "deep2_FFN_NORM_1_pos0_layer0_full_n2048_seq025.bin",
         "llama_FFN_NORM_1_pos0_layer0_full_n2048_seq241.bin", 2048, false},
        {"L1_FFN_GATE",
         "deep2_FFN_GATE_1_pos0_layer0_full_n5632_seq026.bin",
         "llama_FFN_GATE_1_pos0_layer0_full_n5632_seq244.bin", 5632, false},
        {"L1_FFN_UP",
         "deep2_FFN_UP_1_pos0_layer0_full_n5632_seq027.bin",
         "llama_FFN_UP_1_pos0_layer0_full_n5632_seq247.bin", 5632, false},
        {"L1_FFN_ACT",
         "deep2_FFN_ACT_1_pos0_layer0_full_n5632_seq028.bin",
         "llama_FFN_ACT_1_pos0_layer0_full_n5632_seq250.bin", 5632, false},
        {"L1_FFN_DOWN",
         "deep2_FFN_DOWN_1_pos0_layer0_full_n2048_seq029.bin",
         "llama_FFN_DOWN_1_pos0_layer0_full_n2048_seq253.bin", 2048, false},
        {"L1_LAYER_OUT",
         "deep2_LAYER_OUT_1_pos0_layer0_full_n2048_seq031.bin",
         "llama_LAYER1_OUT_pos0_layer0_full_n2048_seq256.bin", 2048, false},
    };

    // Residual confirmation (oracle-independent)
    {
        std::vector<float> l0, a1, f1, recon(2048);
        if (loadF32((d2 + "deep2_LAYER_OUT_0_pos0_layer0_full_n2048_seq017.bin").c_str(), 2048, l0) &&
            loadF32((d2 + "deep2_ATTN_OUT_1_pos0_layer0_full_n2048_seq023.bin").c_str(), 2048, a1) &&
            loadF32((d2 + "deep2_FFN_INP_1_pos0_layer0_full_n2048_seq024.bin").c_str(), 2048, f1)) {
            for (size_t i = 0; i < 2048; ++i) recon[i] = l0[i] + a1[i];
            std::printf("=== residual confirm: FFN_INP_1 vs (L0_OUT + ATTN_OUT_1) ===\n");
            printCmp("L1_residual", cmp(f1.data(), recon.data(), 2048), 2048);
            std::printf("\n");
        }
    }

    const char* firstFail = nullptr;
    std::printf("=== L1 FFN ladder ===\n");
    for (const Step& st : ffn) {
        std::vector<float> a, b;
        if (!loadF32((d2 + st.deep2).c_str(), st.n, a) ||
            !loadF32((ll + st.llama).c_str(), st.n, b)) {
            std::printf("%-16s LOAD_FAIL\n", st.name);
            if (!firstFail) firstFail = st.name;
            break;
        }
        const Cmp c = cmp(a.data(), b.data(), st.n);
        printCmp(st.name, c, st.n);
        if (std::strcmp(c.gate, "FAIL") == 0) {
            firstFail = st.name;
            break;
        }
    }

    // POST_FFN identity with LAYER_OUT on deep2
    if (!firstFail) {
        std::vector<float> post, lout;
        if (loadF32((d2 + "deep2_POST_FFN_1_pos0_layer0_full_n2048_seq030.bin").c_str(), 2048, post) &&
            loadF32((d2 + "deep2_LAYER_OUT_1_pos0_layer0_full_n2048_seq031.bin").c_str(), 2048, lout)) {
            std::printf("\n=== deep2 POST_FFN_1 vs LAYER_OUT_1 ===\n");
            printCmp("POST_eq_LAYER", cmp(post.data(), lout.data(), 2048), 2048);
        }
    }

    bool tipsOk = false;
    if (!firstFail) {
        tipsOk = true;
        std::printf("\n=== sparse tips (stop at first FAIL) ===\n");
        struct Tip {
            const char* name;
            const char* deep2;
            const char* llama;
            size_t n;
        };
        // Llama L1_CLEAN only dumped L0/L1 layer outs (REF_CB_MAX_LAYER=1).
        // Sparse mid-layers: deep2 present; llama MISSING until re-dump.
        const Tip tips[] = {
            {"L2_OUT", "deep2_LAYER_OUT_2_pos0_layer0_full_n2048_seq038.bin", nullptr, 2048},
            {"L4_OUT", "deep2_LAYER_OUT_4_pos0_layer0_full_n2048_seq040.bin", nullptr, 2048},
            {"L8_OUT", "deep2_LAYER_OUT_8_pos0_layer0_full_n2048_seq044.bin", nullptr, 2048},
            {"L12_OUT", "deep2_LAYER_OUT_12_pos0_layer0_full_n2048_seq048.bin", nullptr, 2048},
            {"L16_OUT", "deep2_LAYER_OUT_16_pos0_layer0_full_n2048_seq052.bin", nullptr, 2048},
            {"L21_OUT", "deep2_LAYER_OUT_21_pos0_layer0_full_n2048_seq057.bin", nullptr, 2048},
            {"FINAL_NORM",
             "deep2_PROMPT_FINAL_NORM_pos0_layer0_full_n2048_seq059.bin",
             "llama_FINAL_NORM_pos0_layer0_full_n2048_seq259.bin", 2048},
        };

        for (const Tip& t : tips) {
            if (!t.llama) {
                std::vector<float> a;
                if (loadF32((d2 + t.deep2).c_str(), t.n, a))
                    std::printf("%-16s MISSING llama dump (deep2 present n=%zu) — tip OPEN\n",
                                t.name, a.size());
                else
                    std::printf("%-16s MISSING both\n", t.name);
                continue;
            }
            std::vector<float> a, b;
            if (!loadF32((d2 + t.deep2).c_str(), t.n, a) ||
                !loadF32((ll + t.llama).c_str(), t.n, b)) {
                std::printf("%-16s LOAD_FAIL\n", t.name);
                firstFail = t.name;
                tipsOk = false;
                break;
            }
            const Cmp c = cmp(a.data(), b.data(), t.n);
            printCmp(t.name, c, t.n);
            if (std::strcmp(c.gate, "FAIL") == 0) {
                firstFail = t.name;
                tipsOk = false;
                break;
            }
        }

        // LOGITS / ARGMAX if available
        std::vector<float> lLog;
        if (!firstFail &&
            loadF32((ll + "llama_LOGITS_pos0_layer0_full_n32000_seq260.bin").c_str(), 32000, lLog)) {
            std::printf("LOGITS            llama present n=32000 argmax=%d — deep2 LOGITS dump MISSING\n",
                        argmax(lLog.data(), lLog.size()));
            std::printf("ARGMAX            OPEN (need deep2 logits dump)\n");
        }
    }

    std::printf("\nFIRST_FAIL=%s\n", firstFail ? firstFail : "none");
    if (!firstFail && tipsOk) {
        std::printf("DISPOSITION: L1 FFN → L1_LAYER_OUT CLOSED under clean oracle.\n");
        std::printf("NEXT: dump llama L2/L4/L8/L12/L16/L21 (raise REF_CB_MAX_LAYER) + deep2 LOGITS;\n");
        std::printf("      then sparse tip parity → FINAL_NORM (scored) → LOGITS/ARGMAX.\n");
    } else if (!firstFail) {
        std::printf("DISPOSITION: L1 FFN → L1_LAYER_OUT CLOSED; sparse mid-layer tips OPEN (llama missing).\n");
    } else {
        std::printf("DISPOSITION: stop at FIRST_FAIL under clean L1 oracle — genuine candidate.\n");
    }
    return firstFail && std::strncmp(firstFail, "L1_", 3) == 0 ? 1 : 0;
}
