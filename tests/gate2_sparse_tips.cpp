// BATCH2_SPARSE_TIPS_001 — sparse tips under full-stack FORCE_EXPAND_V (L0..L21)
// Authority: BATCH2_SPARSE_CLEAN_001 llama + deep2_post_swiglu_fix
// Do not reopen ≤ L1.
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

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

static std::string findBin(const fs::path& dir, const std::string& prefix) {
    if (!fs::exists(dir)) return {};
    std::string best;
    for (const auto& e : fs::directory_iterator(dir)) {
        if (!e.is_regular_file()) continue;
        const auto name = e.path().filename().string();
        if (name.rfind(prefix, 0) == 0 && name.size() > 4 &&
            name.compare(name.size() - 4, 4, ".bin") == 0) {
            if (name.find("_pos0_") == std::string::npos &&
                name.find("_pos3_") == std::string::npos)
                continue;
            // Prefer pos0 when both exist
            if (!best.empty()) {
                const bool newPos0 = name.find("_pos0_") != std::string::npos;
                const bool oldPos0 = best.find("_pos0_") != std::string::npos;
                if (oldPos0 && !newPos0) continue;
                if (newPos0 == oldPos0 && name >= best) continue;
            }
            best = name;
        }
    }
    return best.empty() ? std::string{} : (dir / best).string();
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

int main(int argc, char** argv) {
    const char* root =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_SPARSE_CLEAN_001)";
    const char* deep2Sub = "deep2_post_swiglu_fix";
    bool continueAll = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--all") == 0) {
            continueAll = true;
            continue;
        }
        if (argv[i][0] == '-') continue;
        if (std::strcmp(root,
                        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_SPARSE_CLEAN_001)") == 0)
            root = argv[i];
        else
            deep2Sub = argv[i];
    }
    const fs::path d2 = fs::path(root) / deep2Sub;
    const fs::path ll = fs::path(root) / "llama";

    std::printf("BATCH2_SPARSE_TIPS_001\n");
    std::printf("authority=%s\n", root);
    std::printf("deep2=%s\n", d2.string().c_str());
    std::printf("ids=[1,21521,9312] pos=0 abs_eps=1e-6\n");
    std::printf("oracle: FORCE_EXPAND_V layers 0..21 (APPLIED=22 SKIP=0)\n");
    std::printf("DO_NOT_REOPEN: <= L1\n\n");

    struct Tip {
        const char* name;
        const char* dPref;
        const char* lPref;
        size_t n;
    };

    const Tip tips[] = {
        {"L2_OUT", "deep2_LAYER_OUT_2_", "llama_LAYER2_OUT_", 2048},
        {"L4_OUT", "deep2_LAYER_OUT_4_", "llama_LAYER4_OUT_", 2048},
        {"L8_OUT", "deep2_LAYER_OUT_8_", "llama_LAYER8_OUT_", 2048},
        {"L12_OUT", "deep2_LAYER_OUT_12_", "llama_LAYER12_OUT_", 2048},
        {"L16_OUT", "deep2_LAYER_OUT_16_", "llama_LAYER16_OUT_", 2048},
        {"L21_OUT", "deep2_LAYER_OUT_21_", "llama_LAYER21_OUT_", 2048},
        {"FINAL_NORM", "deep2_PROMPT_FINAL_NORM_", "llama_FINAL_NORM_", 2048},
        {"FINAL_NORM_alt", "deep2_FINAL_NORM_", "llama_FINAL_NORM_", 2048},
    };

    const char* firstFail = nullptr;
    double firstFailAbs = 0;
    std::printf("=== sparse tips (post SwiGLU fix)%s ===\n",
                continueAll ? " --all" : "");
    for (const Tip& t : tips) {
        if (std::strcmp(t.name, "FINAL_NORM_alt") == 0) {
            if (!firstFail || std::strcmp(firstFail, "FINAL_NORM") != 0) continue;
            std::printf("--- alt FINAL_NORM key ---\n");
        }
        const auto dp = findBin(d2, t.dPref);
        const auto lp = findBin(ll, t.lPref);
        std::vector<float> a, b;
        if (dp.empty() || !loadF32(dp.c_str(), t.n, a)) {
            std::printf("%-14s MISSING deep2 %s\n", t.name, t.dPref);
            if (!firstFail && std::strcmp(t.name, "FINAL_NORM_alt") != 0) firstFail = t.name;
            continue;
        }
        if (lp.empty() || !loadF32(lp.c_str(), t.n, b)) {
            std::printf("%-14s MISSING llama %s\n", t.name, t.lPref);
            if (!firstFail) firstFail = t.name;
            if (!continueAll) break;
            continue;
        }
        const Cmp c = cmp(a.data(), b.data(), t.n);
        printCmp(t.name, c, t.n);
        if (std::strcmp(c.gate, "FAIL") == 0) {
            if (!firstFail) {
                firstFail = t.name;
                firstFailAbs = c.maxAbs;
            }
            if (!continueAll && std::strcmp(t.name, "FINAL_NORM_alt") != 0) break;
        }
    }

    std::printf("\n=== tip logits ===\n");
    std::vector<float> lLog, dLog;
    const auto lp = findBin(ll, "llama_LOGITS_");
    const auto dp0 = findBin(d2, "deep2_LOGITS_");
    const bool hasL = !lp.empty() && loadF32(lp.c_str(), 32000, lLog);
    const bool hasD = !dp0.empty() && loadF32(dp0.c_str(), 32000, dLog);
    if (hasL && hasD) {
        const bool dPos0 = dp0.find("_pos0_") != std::string::npos;
        const bool lPos0 = lp.find("_pos0_") != std::string::npos;
        std::printf("LOGITS paths deep2=%s llama=%s aligned=%s\n",
                    dp0.c_str(), lp.c_str(), (dPos0 == lPos0) ? "YES" : "NO");
        if (dPos0 == lPos0) {
            const Cmp c = cmp(dLog.data(), lLog.data(), 32000, 1e-4, 1e-3);
            printCmp("LOGITS", c, 32000);
            const int ad = argmax(dLog.data(), dLog.size());
            const int al = argmax(lLog.data(), lLog.size());
            std::printf("ARGMAX         deep2=%d llama=%d match=%s\n",
                        ad, al, ad == al ? "YES" : "NO");
            if (!firstFail && std::strcmp(c.gate, "FAIL") == 0) firstFail = "LOGITS";
            if (!firstFail && ad != al) firstFail = "ARGMAX";
        } else {
            std::printf("LOGITS         SKIP (pos mismatch: deep2 not tip-aligned)\n");
            if (hasL)
                std::printf("ARGMAX         llama=%d (deep2 OPEN — need pos0 dump)\n",
                            argmax(lLog.data(), lLog.size()));
        }
    } else {
        std::printf("LOGITS         llama=%s deep2=%s\n",
                    hasL ? "present" : "MISSING", hasD ? "present" : "MISSING");
        if (hasL)
            std::printf("ARGMAX         llama=%d (deep2 OPEN)\n", argmax(lLog.data(), lLog.size()));
    }

    std::printf("\nFIRST_FAIL=%s", firstFail ? firstFail : "none");
    if (firstFail) std::printf(" max_abs=%.6e", firstFailAbs);
    std::printf("\n");

    if (!firstFail) {
        std::printf("DISPOSITION: sparse tips + FINAL_NORM PASS under full FORCE_EXPAND_V.\n");
        std::printf("NEXT: deep2 LOGITS pos0 dump → ARGMAX cert.\n");
    } else if (std::strncmp(firstFail, "L", 1) == 0 && std::strstr(firstFail, "_OUT")) {
        std::printf("DISPOSITION: first clean tip FAIL=%s — expand only that band "
                    "(prev tip PASS → fail layer internals with PRE_O invariants).\n",
                    firstFail);
    } else {
        std::printf("DISPOSITION: stop at %s; do not reopen <= L1.\n", firstFail);
    }
    return firstFail ? 1 : 0;
}
