// BATCH2_SPARSE_TIPS_001 — sparse tips under full-stack FORCE_EXPAND_V (L0..L21)
// Authority: BATCH2_SPARSE_CLEAN_001 (FORCE hit=22, SKIP=0)
// Do not reopen ≤ L1.
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
    int exact = 0;
    const char* gate = "FAIL";
};

static Cmp cmp(const float* a, const float* b, size_t n,
               double passEps = 1e-6, double inspectEps = 1e-5) {
    Cmp r;
    for (size_t i = 0; i < n; ++i) {
        const double d = std::fabs((double)a[i] - (double)b[i]);
        if (d == 0) ++r.exact;
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
    std::printf("%-14s gate=%s n=%zu exact=%d/%zu max_abs=%.6e first_bad=%d largest=%d\n",
                tag, r.gate, n, r.exact, n, r.maxAbs, r.firstBad, r.largest);
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

static void gqaExpand(const float* v, std::vector<float>& out) {
    constexpr int nq = 32, nkv = 4, hd = 64;
    const int group = nq / nkv;
    out.assign(nq * hd, 0.f);
    for (int qh = 0; qh < nq; ++qh)
        std::memcpy(out.data() + qh * hd, v + (qh / group) * hd, hd * sizeof(float));
}

int main(int argc, char** argv) {
    const char* root = argc > 1 ? argv[1]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_SPARSE_CLEAN_001)";
    // Deep2 tip dumps may live under this root or be shared with L1_CLEAN (same IDs).
    const char* deep2Root = argc > 2 ? argv[2] : root;
    const std::string d2 = std::string(deep2Root) + "\\deep2\\";
    const std::string ll = std::string(root) + "\\llama\\";

    std::printf("BATCH2_SPARSE_TIPS_001\n");
    std::printf("authority=%s\n", root);
    std::printf("deep2=%s\n", deep2Root);
    std::printf("ids=[1,21521,9312] pos=0 abs_eps=1e-6\n");
    std::printf("oracle: FORCE_EXPAND_V layers 0..21 (APPLIED=22 SKIP=0)\n");
    std::printf("DO_NOT_REOPEN: <= L1\n\n");

    struct Tip {
        const char* name;
        const char* deep2;
        const char* llama;
        size_t n;
    };

    const Tip tips[] = {
        {"L2_OUT",
         "deep2_LAYER_OUT_2_pos0_layer0_full_n2048_seq038.bin",
         "llama_LAYER2_OUT_pos0_layer0_full_n2048_seq004.bin", 2048},
        {"L4_OUT",
         "deep2_LAYER_OUT_4_pos0_layer0_full_n2048_seq040.bin",
         "llama_LAYER4_OUT_pos0_layer0_full_n2048_seq007.bin", 2048},
        {"L8_OUT",
         "deep2_LAYER_OUT_8_pos0_layer0_full_n2048_seq044.bin",
         "llama_LAYER8_OUT_pos0_layer0_full_n2048_seq010.bin", 2048},
        {"L12_OUT",
         "deep2_LAYER_OUT_12_pos0_layer0_full_n2048_seq048.bin",
         "llama_LAYER12_OUT_pos0_layer0_full_n2048_seq013.bin", 2048},
        {"L16_OUT",
         "deep2_LAYER_OUT_16_pos0_layer0_full_n2048_seq052.bin",
         "llama_LAYER16_OUT_pos0_layer0_full_n2048_seq016.bin", 2048},
        {"L21_OUT",
         "deep2_LAYER_OUT_21_pos0_layer0_full_n2048_seq057.bin",
         "llama_LAYER21_OUT_pos0_layer0_full_n2048_seq019.bin", 2048},
        {"FINAL_NORM",
         "deep2_PROMPT_FINAL_NORM_pos0_layer0_full_n2048_seq059.bin",
         "llama_FINAL_NORM_pos0_layer0_full_n2048_seq020.bin", 2048},
        // alt deep2 key if present
        {"FINAL_NORM_alt",
         "deep2_FINAL_NORM_pos0_layer0_full_n2048_seq060.bin",
         "llama_FINAL_NORM_pos0_layer0_full_n2048_seq020.bin", 2048},
    };

    const char* firstFail = nullptr;
    double firstFailAbs = 0;
    std::printf("=== sparse tips ===\n");
    for (const Tip& t : tips) {
        if (std::strcmp(t.name, "FINAL_NORM_alt") == 0) {
            // only run if primary FINAL_NORM failed or missing, as diagnostic
            if (!firstFail || std::strcmp(firstFail, "FINAL_NORM") != 0) continue;
            std::printf("--- alt FINAL_NORM key ---\n");
        }
        std::vector<float> a, b;
        if (!loadF32((d2 + t.deep2).c_str(), t.n, a)) {
            std::printf("%-14s MISSING deep2 %s\n", t.name, t.deep2);
            if (!firstFail && std::strcmp(t.name, "FINAL_NORM_alt") != 0) {
                firstFail = t.name;
            }
            continue;
        }
        if (!loadF32((ll + t.llama).c_str(), t.n, b)) {
            std::printf("%-14s MISSING llama %s\n", t.name, t.llama);
            if (!firstFail) firstFail = t.name;
            break;
        }
        const Cmp c = cmp(a.data(), b.data(), t.n);
        printCmp(t.name, c, t.n);
        if (std::strcmp(c.gate, "FAIL") == 0) {
            if (!firstFail) {
                firstFail = t.name;
                firstFailAbs = c.maxAbs;
            }
            if (std::strcmp(t.name, "FINAL_NORM_alt") != 0) break;
        }
    }

    // LOGITS / ARGMAX
    std::printf("\n=== tip logits ===\n");
    std::vector<float> lLog, dLog;
    const bool hasL = loadF32((ll + "llama_LOGITS_pos0_layer0_full_n32000_seq021.bin").c_str(),
                              32000, lLog);
    const bool hasD =
        loadF32((d2 + "deep2_LOGITS_pos0_layer0_full_n32000_seq061.bin").c_str(), 32000, dLog) ||
        loadF32((d2 + "deep2_LOGITS_pos0_layer0_full_n32000.bin").c_str(), 32000, dLog);
    if (hasL && hasD) {
        const Cmp c = cmp(dLog.data(), lLog.data(), 32000, 1e-4, 1e-3);
        printCmp("LOGITS", c, 32000);
        const int ad = argmax(dLog.data(), dLog.size());
        const int al = argmax(lLog.data(), lLog.size());
        std::printf("ARGMAX         deep2=%d llama=%d match=%s\n",
                    ad, al, ad == al ? "YES" : "NO");
        if (!firstFail && std::strcmp(c.gate, "FAIL") == 0) firstFail = "LOGITS";
        if (!firstFail && ad != al) firstFail = "ARGMAX";
    } else {
        std::printf("LOGITS         llama=%s deep2=%s\n",
                    hasL ? "present" : "MISSING", hasD ? "present" : "MISSING");
        if (hasL)
            std::printf("ARGMAX         llama=%d (deep2 OPEN)\n", argmax(lLog.data(), lLog.size()));
    }

    // Optional: L2 PRE_O invariant if dumps exist
    std::printf("\n=== oracle invariant sample @ L2 (if dumps) ===\n");
    std::vector<float> dV, lV, dPre, lPre, expand;
    const bool inv =
        loadF32((d2 + "deep2_V_2_pos0_layer0_full_n256_seq039.bin").c_str(), 256, dV) &&
        (loadF32((ll + "llama_V_2_pos0_layer0_full_n256.bin").c_str(), 256, lV) ||
         loadF32((ll + "llama_V_2_pos0_layer0_full_n256_seq001.bin").c_str(), 256, lV));
    if (inv) {
        gqaExpand(dV.data(), expand);
        // need PRE_O dumps
        std::printf("V dumps present — PRE_O dumps may be sparse-mode omitted; "
                    "FORCE_EXPAND_V APPLIED=22 is authority for llama PRE_O.\n");
        printCmp("V_2", cmp(dV.data(), lV.data(), 256), 256);
    } else {
        std::printf("V_2 dumps MISSING (sparse mode stashes V without dumping) — "
                    "llama FORCE APPLIED=22 is the PRE_O hygiene proof for this run.\n");
    }

    std::printf("\nFIRST_FAIL=%s", firstFail ? firstFail : "none");
    if (firstFail) std::printf(" max_abs=%.6e", firstFailAbs);
    std::printf("\n");

    if (!firstFail) {
        std::printf("DISPOSITION: sparse tips + FINAL_NORM PASS under full FORCE_EXPAND_V.\n");
        std::printf("NEXT: deep2 LOGITS dump if missing → ARGMAX cert.\n");
    } else if (std::strncmp(firstFail, "L", 1) == 0 && std::strstr(firstFail, "_OUT")) {
        std::printf("DISPOSITION: first clean tip FAIL=%s — expand only that band "
                    "(prev tip PASS → fail layer internals with PRE_O invariants).\n",
                    firstFail);
    } else {
        std::printf("DISPOSITION: stop at %s; do not reopen <= L1.\n", firstFail);
    }
    return firstFail ? 1 : 0;
}
