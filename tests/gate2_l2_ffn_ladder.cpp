// BATCH2_L2_FFN_LADDER_001 — expand L2 band under FORCE_EXPAND_V
// Authority: BATCH2_L2_CLEAN_001 (llama) + deep2_swiglu_fix
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
            if (name.find("_pos0_") == std::string::npos) continue;
            if (best.empty() || name < best) best = name;
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

static void gqaExpand(const float* v, std::vector<float>& out) {
    constexpr int nq = 32, nkv = 4, hd = 64;
    const int group = nq / nkv;
    out.assign(nq * hd, 0.f);
    for (int qh = 0; qh < nq; ++qh)
        std::memcpy(out.data() + qh * hd, v + (qh / group) * hd, hd * sizeof(float));
}

int main(int argc, char** argv) {
    const char* root = argc > 1 ? argv[1]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L2_CLEAN_001)";
    const char* deep2Sub = argc > 2 ? argv[2] : "deep2_swiglu_fix";
    const fs::path d2 = fs::path(root) / deep2Sub;
    const fs::path ll = fs::path(root) / "llama";

    std::printf("BATCH2_L2_FFN_LADDER_001\n");
    std::printf("authority=%s\n", root);
    std::printf("deep2=%s\n", d2.string().c_str());
    std::printf("ids=[1,21521,9312] pos=0 abs_eps=1e-6\n");
    std::printf("DO_NOT_REOPEN: <= L1\n\n");

    struct Tip {
        const char* name;
        const char* dPref;
        const char* lPref;
        size_t n;
        double passEps;
        double inspectEps;
    };

    const Tip tips[] = {
        {"PRE_O_2", "deep2_ATTN_PRE_O_2_", "llama_ATTN_PRE_O_FORCED_2_", 2048, 1e-6, 1e-5},
        {"ATTN_NORM_2", "deep2_ATTN_NORM_2_", "llama_ATTN_NORM_2_", 2048, 1e-6, 1e-5},
        {"ATTN_OUT_2", "deep2_ATTN_OUT_2_", "llama_ATTN_OUT_2_", 2048, 1e-6, 1e-5},
        {"FFN_INP_2", "deep2_FFN_INP_2_", "llama_FFN_INP_2_", 2048, 1e-6, 1e-5},
        {"FFN_NORM_2", "deep2_FFN_NORM_2_", "llama_FFN_NORM_2_", 2048, 1e-6, 1e-5},
        {"FFN_GATE_2", "deep2_FFN_GATE_2_", "llama_FFN_GATE_2_", 5632, 1e-6, 1e-5},
        {"FFN_UP_2", "deep2_FFN_UP_2_", "llama_FFN_UP_2_", 5632, 1e-6, 1e-5},
        {"FFN_ACT_2", "deep2_FFN_ACT_2_", "llama_FFN_ACT_2_", 5632, 1e-6, 1e-5},
        {"FFN_DOWN_2", "deep2_FFN_DOWN_2_", "llama_FFN_DOWN_2_", 2048, 1e-6, 1e-5},
        {"LAYER2_OUT", "deep2_LAYER_OUT_2_", "llama_LAYER2_OUT_", 2048, 1e-6, 1e-5},
    };

    // Oracle: PRE_O == expand(V) on deep2 if V present
    std::printf("=== oracle PRE_O / expand(V) @ L2 ===\n");
    {
        const auto vPath = findBin(d2, "deep2_V_2_");
        const auto prePath = findBin(d2, "deep2_ATTN_PRE_O_2_");
        std::vector<float> v, pre, exp;
        if (!vPath.empty() && !prePath.empty() && loadF32(vPath.c_str(), 256, v) &&
            loadF32(prePath.c_str(), 2048, pre)) {
            gqaExpand(v.data(), exp);
            printCmp("d2 PRE_O==expV", cmp(pre.data(), exp.data(), 2048), 2048);
        } else {
            std::printf("V_2 or PRE_O_2 MISSING on deep2\n");
        }
        const auto lPre = findBin(ll, "llama_ATTN_PRE_O_FORCED_2_");
        const auto lPreN = findBin(ll, "llama_ATTN_PRE_O_2_");
        if (!lPre.empty() && !prePath.empty()) {
            std::vector<float> a, b;
            if (loadF32(prePath.c_str(), 2048, a) && loadF32(lPre.c_str(), 2048, b))
                printCmp("PRE_O vs FORCED", cmp(a.data(), b.data(), 2048), 2048);
        } else if (!lPreN.empty() && !prePath.empty()) {
            std::vector<float> a, b;
            if (loadF32(prePath.c_str(), 2048, a) && loadF32(lPreN.c_str(), 2048, b))
                printCmp("PRE_O vs native", cmp(a.data(), b.data(), 2048), 2048);
        }
    }

    const char* firstFail = nullptr;
    double firstFailAbs = 0;
    std::printf("\n=== L2 ladder ===\n");
    for (const Tip& t : tips) {
        const auto dp = findBin(d2, t.dPref);
        const auto lp = findBin(ll, t.lPref);
        std::vector<float> a, b;
        if (dp.empty() || !loadF32(dp.c_str(), t.n, a)) {
            std::printf("%-14s MISSING deep2 prefix %s\n", t.name, t.dPref);
            if (!firstFail) firstFail = t.name;
            continue;
        }
        if (lp.empty() || !loadF32(lp.c_str(), t.n, b)) {
            std::printf("%-14s MISSING llama prefix %s\n", t.name, t.lPref);
            if (!firstFail) firstFail = t.name;
            break;
        }
        const Cmp c = cmp(a.data(), b.data(), t.n, t.passEps, t.inspectEps);
        printCmp(t.name, c, t.n);
        if (std::strcmp(c.gate, "FAIL") == 0 && !firstFail) {
            firstFail = t.name;
            firstFailAbs = c.maxAbs;
        }
    }

    // Self-check: ACT == silu(GATE)*UP on deep2
    std::printf("\n=== Deep2 SwiGLU self-check ===\n");
    {
        std::vector<float> g, u, act;
        const auto gp = findBin(d2, "deep2_FFN_GATE_2_");
        const auto up = findBin(d2, "deep2_FFN_UP_2_");
        const auto ap = findBin(d2, "deep2_FFN_ACT_2_");
        if (!gp.empty() && !up.empty() && !ap.empty() &&
            loadF32(gp.c_str(), 5632, g) && loadF32(up.c_str(), 5632, u) &&
            loadF32(ap.c_str(), 5632, act)) {
            double maxAbs = 0;
            int largest = -1;
            auto silu1 = [](float x) -> float {
                if (x > 20.f) return x;
                if (x < -20.f) return 0.f;
                return x / (1.f + std::exp(-x));
            };
            for (size_t i = 0; i < 5632; ++i) {
                const float ref = silu1(g[i]) * u[i];
                const double d = std::fabs((double)act[i] - (double)ref);
                if (d > maxAbs) {
                    maxAbs = d;
                    largest = (int)i;
                }
            }
            std::printf("ACT==silu(G)*U max_abs=%.6e largest=%d gate=%s\n",
                        maxAbs, largest, maxAbs <= 1e-6 ? "PASS" : (maxAbs <= 1e-5 ? "INSPECT" : "FAIL"));
        } else {
            std::printf("GATE/UP/ACT missing for self-check\n");
        }
    }

    std::printf("\nFIRST_FAIL=%s", firstFail ? firstFail : "none");
    if (firstFail) std::printf(" max_abs=%.6e", firstFailAbs);
    std::printf("\n");
    if (!firstFail)
        std::printf("DISPOSITION: L2 band CLOSED under swiglu_fix.\n");
    else
        std::printf("DISPOSITION: stop at %s; SwiGLU clamp bug already fixed — "
                    "residual may be GATE/quant ULP; do not reopen <= L1.\n",
                    firstFail);
    return firstFail ? 1 : 0;
}
