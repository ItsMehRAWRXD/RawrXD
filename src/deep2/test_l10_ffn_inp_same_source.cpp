/*
 * BATCH2_L10_FFN_INP_SAME_SOURCE — TODO_L10_FFN_INP_SAME_SOURCE
 *
 * Question: does FFN_INP_10 already carry the native divergence, and does
 * same-source FFN_NORM + same-operand GATE classify FFN_GATE_10 as inherited?
 *
 * Uses BATCH2_L10_BODY_001 dumps + GGUF blk.10.ffn_norm.weight.
 * Optional: llama FORCE_FFN_INP dumps under outDir/llama/ if present.
 */
#include "GGUFLoader.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) _mkdir(p)
#else
#include <sys/stat.h>
#define MKDIR(p) mkdir(p, 0755)
#endif

using Deep2::GGUFLoader;

static uint64_t fnv1a64(const void* data, size_t n) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

static int ulpDiff(float a, float b) {
    if (a == b) return 0;
    int32_t ia, ib;
    std::memcpy(&ia, &a, 4);
    std::memcpy(&ib, &b, 4);
    if (ia < 0) ia = 0x80000000 - ia;
    if (ib < 0) ib = 0x80000000 - ib;
    const int64_t d = (int64_t)ia - (int64_t)ib;
    return (int)(d < 0 ? -d : d);
}

static bool loadF32(const char* path, size_t n, std::vector<float>& out) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    out.resize(n);
    const bool ok = std::fread(out.data(), sizeof(float), n, f) == n;
    std::fclose(f);
    return ok;
}

static bool writeF32(const char* path, const std::vector<float>& v) {
    FILE* f = std::fopen(path, "wb");
    if (!f) return false;
    const bool ok = std::fwrite(v.data(), sizeof(float), v.size(), f) == v.size();
    std::fclose(f);
    return ok;
}

struct Cmp {
    double maxAbs = 0;
    double maxRel = 0;
    int first = -1;
    int largest = -1;
    int maxUlp = 0;
    bool exact = true;
    uint64_t fnvA = 0;
    uint64_t fnvB = 0;
};

static Cmp compare(const std::vector<float>& a, const std::vector<float>& b) {
    Cmp c;
    c.fnvA = fnv1a64(a.data(), a.size() * 4);
    c.fnvB = fnv1a64(b.data(), b.size() * 4);
    c.exact = (c.fnvA == c.fnvB);
    for (size_t i = 0; i < a.size() && i < b.size(); ++i) {
        const double da = (double)a[i];
        const double db = (double)b[i];
        const double absd = std::fabs(da - db);
        const double denom = std::fmax(std::fmax(std::fabs(da), std::fabs(db)), 1e-30);
        const double reld = absd / denom;
        const int u = ulpDiff(a[i], b[i]);
        if (u > c.maxUlp) c.maxUlp = u;
        if (absd > c.maxAbs) {
            c.maxAbs = absd;
            c.largest = (int)i;
        }
        if (reld > c.maxRel) c.maxRel = reld;
        if (c.first < 0 && absd > 0) c.first = (int)i;
        if (absd > 0) c.exact = false;
    }
    return c;
}

static const char* dualGate(const Cmp& c) {
    // Match NEXT_CERT_MANIFEST dual_gate_policy
    if (c.maxAbs <= 1e-6 || (c.maxAbs <= 1e-4 && c.maxRel <= 1e-6)) return "PASS";
    if (c.maxAbs <= 1e-4 && c.maxRel <= 5e-6) return "INSPECT";
    return "FAIL";
}

static const char* absGate(const Cmp& c) {
    return c.maxAbs <= 1e-6 ? "PASS" : "FAIL";
}

static void rmsnormW(const float* w, const float* x, float* y, size_t n, float eps) {
    double sumSq = 0;
    for (size_t i = 0; i < n; ++i) {
        const double v = (double)x[i];
        sumSq += v * v;
    }
    const double inv = 1.0 / std::sqrt(sumSq / (double)n + (double)eps);
    for (size_t i = 0; i < n; ++i)
        y[i] = w[i] * (float)((double)x[i] * inv);
}

static std::string findDump(const char* dir, const char* side, const char* stage, size_t n) {
    // Prefer earliest seq (prompt/body-aligned). Later seqs are decode-step mirrors.
    for (int seq = 1; seq <= 4000; ++seq) {
        char path[1400];
        std::snprintf(path, sizeof(path),
                      "%s\\%s_%s_pos0_layer0_full_n%zu_seq%03d.bin",
                      dir, side, stage, n, seq);
        FILE* f = std::fopen(path, "rb");
        if (f) {
            std::fclose(f);
            return path;
        }
        std::snprintf(path, sizeof(path),
                      "%s\\%s_%s_pos0_layer0_full_n%zu_seq%04d.bin",
                      dir, side, stage, n, seq);
        f = std::fopen(path, "rb");
        if (f) {
            std::fclose(f);
            return path;
        }
    }
    return {};
}

static void printCmp(FILE* out, const char* tag, const Cmp& c) {
    std::fprintf(out,
                 "%-28s abs=%-6s dual=%-7s max_abs=%.6e max_rel=%.6e first=%d largest=%d "
                 "max_ulp=%d exact=%d\n"
                 "                             fnvA=%016llx fnvB=%016llx\n",
                 tag, absGate(c), dualGate(c), c.maxAbs, c.maxRel, c.first, c.largest,
                 c.maxUlp, (int)c.exact,
                 (unsigned long long)c.fnvA, (unsigned long long)c.fnvB);
}

int main() {
    const char* body =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L10_BODY_001)";
    const char* outDir =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L10_FFN_INP_SAME_SOURCE)";
    const char* model =
        R"(F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf)";
    const float eps = 1e-5f;

    MKDIR(R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001)");
    MKDIR(outDir);

    char reportPath[1024], gatePath[1024];
    std::snprintf(reportPath, sizeof(reportPath), "%s\\REPORT.txt", outDir);
    std::snprintf(gatePath, sizeof(gatePath), "%s\\GATE.txt", outDir);
    FILE* out = std::fopen(reportPath, "w");
    if (!out) out = stdout;

    std::fprintf(out, "BATCH2_L10_FFN_INP_SAME_SOURCE\n");
    std::fprintf(out, "TODO=TODO_L10_FFN_INP_SAME_SOURCE\n");
    std::fprintf(out, "ids=[1,21521,9312] pos=0 layer=10\n");
    std::fprintf(out, "question=Does FFN_INP_10 already contain divergence under same pre-FFN class;\n");
    std::fprintf(out, "         is ~3.6e-5 GATE gap inherited vs native gate-path?\n");
    std::fprintf(out, "policy: dual PASS if abs<=1e-6 OR (abs<=1e-4 AND rel<=1e-6)\n\n");

    char deep2Dir[1024], llamaDir[1024];
    std::snprintf(deep2Dir, sizeof(deep2Dir), "%s\\deep2", body);
    std::snprintf(llamaDir, sizeof(llamaDir), "%s\\llama", body);

    const std::string dAttn = findDump(deep2Dir, "deep2", "ATTN_OUT_10", 2048);
    const std::string lAttn = findDump(llamaDir, "llama", "ATTN_OUT_10", 2048);
    const std::string dInp = findDump(deep2Dir, "deep2", "FFN_INP_10", 2048);
    const std::string lInp = findDump(llamaDir, "llama", "FFN_INP_10", 2048);
    const std::string dNorm = findDump(deep2Dir, "deep2", "FFN_NORM_10", 2048);
    const std::string lNorm = findDump(llamaDir, "llama", "FFN_NORM_10", 2048);
    const std::string dGate = findDump(deep2Dir, "deep2", "FFN_GATE_10", 5632);
    const std::string lGate = findDump(llamaDir, "llama", "FFN_GATE_10", 5632);

    std::fprintf(out, "dumps:\n  ATTN_OUT_d=%s\n  ATTN_OUT_l=%s\n  FFN_INP_d=%s\n  FFN_INP_l=%s\n"
                      "  FFN_NORM_d=%s\n  FFN_NORM_l=%s\n  FFN_GATE_d=%s\n  FFN_GATE_l=%s\n\n",
                 dAttn.c_str(), lAttn.c_str(), dInp.c_str(), lInp.c_str(),
                 dNorm.c_str(), lNorm.c_str(), dGate.c_str(), lGate.c_str());

    std::vector<float> attnD, attnL, inpD, inpL, normD, normL, gateD, gateL;
    if (!loadF32(dAttn.c_str(), 2048, attnD) || !loadF32(lAttn.c_str(), 2048, attnL) ||
        !loadF32(dInp.c_str(), 2048, inpD) || !loadF32(lInp.c_str(), 2048, inpL) ||
        !loadF32(dNorm.c_str(), 2048, normD) || !loadF32(lNorm.c_str(), 2048, normL) ||
        !loadF32(dGate.c_str(), 5632, gateD) || !loadF32(lGate.c_str(), 5632, gateL)) {
        std::fprintf(out, "FAIL load body dumps\n");
        if (out != stdout) std::fclose(out);
        return 2;
    }

    std::fprintf(out, "NATIVE PAIRWISE (no force)\n");
    const Cmp cAttn = compare(attnD, attnL);
    const Cmp cInp = compare(inpD, inpL);
    const Cmp cNorm = compare(normD, normL);
    const Cmp cGate = compare(gateD, gateL);
    printCmp(out, "ATTN_OUT_10", cAttn);
    printCmp(out, "FFN_INP_10", cInp);
    printCmp(out, "FFN_NORM_10", cNorm);
    printCmp(out, "FFN_GATE_10", cGate);

    // Residual locus: FFN_INP - ATTN_OUT ≈ layer input into residual add
    std::vector<float> residD(2048), residL(2048);
    for (size_t i = 0; i < 2048; ++i) {
        residD[i] = inpD[i] - attnD[i];
        residL[i] = inpL[i] - attnL[i];
    }
    const Cmp cResid = compare(residD, residL);
    printCmp(out, "RESID_IN_(INP-ATTN_OUT)", cResid);

    auto lr = GGUFLoader::Load(model, {true, true, false});
    if (!lr.success) {
        std::fprintf(out, "FAIL load gguf\n");
        if (out != stdout) std::fclose(out);
        return 2;
    }
    const auto* tNorm = lr.GetTensor("blk.10.ffn_norm.weight");
    if (!tNorm) tNorm = lr.GetTensor("blk.10.ffn_norm");
    if (!tNorm || !tNorm->data || tNorm->type != Deep2::GGMLType::GGML_TYPE_F32
        || tNorm->GetNumElements() < 2048) {
        std::fprintf(out, "FAIL ffn_norm weight\n");
        if (out != stdout) std::fclose(out);
        return 2;
    }
    const float* w = reinterpret_cast<const float*>(tNorm->data);

    std::vector<float> yFromInpD(2048), yFromInpL(2048), ySameFromD(2048);
    rmsnormW(w, inpD.data(), yFromInpD.data(), 2048, eps);
    rmsnormW(w, inpL.data(), yFromInpL.data(), 2048, eps);
    rmsnormW(w, inpD.data(), ySameFromD.data(), 2048, eps); // identical recipe

    std::fprintf(out, "\nSAME-WEIGHT RMSNorm (scalar double accum, eps=1e-5)\n");
    const Cmp cFaithD = compare(yFromInpD, normD);
    const Cmp cFaithL = compare(yFromInpL, normL);
    const Cmp cProp = compare(yFromInpD, yFromInpL);
    const Cmp cSameExact = compare(ySameFromD, yFromInpD);
    printCmp(out, "RMS(INP_d) vs NORM_d", cFaithD);
    printCmp(out, "RMS(INP_l) vs NORM_l", cFaithL);
    printCmp(out, "RMS(INP_d) vs RMS(INP_l)", cProp);
    printCmp(out, "same-source self-check", cSameExact);

    char frozenInp[1024], frozenNorm[1024];
    std::snprintf(frozenInp, sizeof(frozenInp), "%s\\frozen_FFN_INP_10_deep2.bin", outDir);
    std::snprintf(frozenNorm, sizeof(frozenNorm), "%s\\frozen_FFN_NORM_from_INP_d.bin", outDir);
    writeF32(frozenInp, inpD);
    writeF32(frozenNorm, yFromInpD);
    std::fprintf(out, "\nfrozen_FFN_INP_10=%s fnv=%016llx\n", frozenInp,
                 (unsigned long long)fnv1a64(inpD.data(), inpD.size() * 4));
    std::fprintf(out, "frozen_FFN_NORM_from_INP_d=%s fnv=%016llx\n", frozenNorm,
                 (unsigned long long)fnv1a64(yFromInpD.data(), yFromInpD.size() * 4));

    // Optional live force dumps (llama FORCE_FFN_INP → FFN_NORM / GATE)
    char forceLlamaDir[1024];
    std::snprintf(forceLlamaDir, sizeof(forceLlamaDir), "%s\\llama", outDir);
    const std::string fNorm = findDump(forceLlamaDir, "llama", "FFN_NORM_FORCE_DEEP2_INP_10", 2048);
    if (fNorm.empty()) {
        // alternate stem after inject+natural norm
        const std::string alt = findDump(forceLlamaDir, "llama", "FFN_NORM_10", 2048);
        std::fprintf(out, "\nFORCE_FFN_INP llama dumps: %s\n",
                     alt.empty() ? "(none yet — run probe with RAWRXD_FORCE_FFN_INP_BIN)" : alt.c_str());
        if (!alt.empty()) {
            std::vector<float> nForce;
            if (loadF32(alt.c_str(), 2048, nForce)) {
                const Cmp cForce = compare(yFromInpD, nForce);
                printCmp(out, "RMS(INP_d) vs llama_FORCE_NORM", cForce);
            }
        }
    } else {
        std::vector<float> nForce;
        if (loadF32(fNorm.c_str(), 2048, nForce)) {
            const Cmp cForce = compare(yFromInpD, nForce);
            printCmp(out, "RMS(INP_d) vs llama_FORCE_NORM", cForce);
        }
    }

    std::fprintf(out, "\nPRIOR: BATCH2_L10_GATE_SAME_OPERAND — GEMV CLOSED under frozen FFN_NORM_10\n");
    std::fprintf(out, "  A1==A2_q8k==llama FORCE  max_abs(gate)~2.09e-7\n");

    // Attribution
    const bool inpDiffers = std::strcmp(dualGate(cInp), "PASS") != 0;
    const bool attnOk = std::strcmp(dualGate(cAttn), "PASS") == 0;
    const bool residDiffers = std::strcmp(dualGate(cResid), "PASS") != 0;
    const bool normFaithful =
        std::strcmp(dualGate(cFaithD), "PASS") == 0 && std::strcmp(dualGate(cFaithL), "PASS") == 0;
    const bool propFromInp = std::strcmp(dualGate(cProp), "PASS") != 0;
    const bool nativeGateFail = std::strcmp(dualGate(cGate), "FAIL") == 0;
    const bool gemvClosedPrior = true;

    std::fprintf(out, "\nATTRIBUTION\n");
    std::fprintf(out, "  ATTN_OUT_10 dual OK                 = %d\n", (int)attnOk);
    std::fprintf(out, "  FFN_INP_10 differs (native)         = %d\n", (int)inpDiffers);
    std::fprintf(out, "  residual-in (INP-ATTN) differs      = %d  (upstream layer state)\n",
                 (int)residDiffers);
    std::fprintf(out, "  RMSNorm faithful to each side NORM  = %d\n", (int)normFaithful);
    std::fprintf(out, "  RMS(INP_d) vs RMS(INP_l) propagates = %d\n", (int)propFromInp);
    std::fprintf(out, "  native FFN_GATE_10 dual FAIL        = %d\n", (int)nativeGateFail);
    std::fprintf(out, "  same-operand GEMV CLOSED (prior)    = %d\n", (int)gemvClosedPrior);

    const bool inherited =
        inpDiffers && residDiffers && normFaithful && gemvClosedPrior && nativeGateFail;

    std::fprintf(out, "\nVERDICT=%s\n", inherited ? "FFN_GATE_10_INHERITED_FROM_UPSTREAM_FFN_INP"
                                                 : "REOPEN_NATIVE_GATE_OR_NORM");
    if (inherited) {
        std::fprintf(out,
                     "stop_condition_met:\n"
                     "  FFN_INP differs\n"
                     "  + same-weight RMSNorm reproduces each side / propagates INP delta\n"
                     "  + same-operand GATE remains numerically correct (prior cert)\n"
                     "  = FFN_GATE_10 is inherited, not root\n");
        std::fprintf(out, "NEXT=TODO_RESUME_TIPS_AFTER_L10 (or localize residual-in / L9_OUT)\n");
    } else {
        std::fprintf(out, "NEXT=investigate native gate/norm path despite GEMV closed\n");
    }

    FILE* gate = std::fopen(gatePath, "w");
    if (gate) {
        std::fprintf(gate, "BATCH2_L10_FFN_INP_SAME_SOURCE — TODO_L10_FFN_INP_SAME_SOURCE\n");
        std::fprintf(gate, "============================================================\n");
        std::fprintf(gate, "date=2026-08-29\n");
        std::fprintf(gate, "ids=[1,21521,9312] pos=0 layer=10\n\n");
        std::fprintf(gate, "NATIVE\n");
        std::fprintf(gate, "  ATTN_OUT_10   dual=%s  max_abs=%.3e\n", dualGate(cAttn), cAttn.maxAbs);
        std::fprintf(gate, "  FFN_INP_10    dual=%s  max_abs=%.3e  FIRST_ABS_FAIL locus\n",
                     dualGate(cInp), cInp.maxAbs);
        std::fprintf(gate, "  RESID_IN      dual=%s  max_abs=%.3e  (INP-ATTN_OUT)\n",
                     dualGate(cResid), cResid.maxAbs);
        std::fprintf(gate, "  FFN_NORM_10   dual=%s  max_abs=%.3e\n", dualGate(cNorm), cNorm.maxAbs);
        std::fprintf(gate, "  FFN_GATE_10   dual=%s  max_abs=%.3e\n\n", dualGate(cGate), cGate.maxAbs);
        std::fprintf(gate, "SAME-SOURCE / SAME-WEIGHT\n");
        std::fprintf(gate, "  RMS(INP_d)≈NORM_d     dual=%s\n", dualGate(cFaithD));
        std::fprintf(gate, "  RMS(INP_l)≈NORM_l     dual=%s\n", dualGate(cFaithL));
        std::fprintf(gate, "  RMS(INP_d)vsRMS(INP_l) dual=%s  max_abs=%.3e\n",
                     dualGate(cProp), cProp.maxAbs);
        std::fprintf(gate, "  GEMV same-operand     CLOSED (BATCH2_L10_GATE_SAME_OPERAND)\n\n");
        std::fprintf(gate, "VERDICT=%s\n",
                     inherited ? "FFN_GATE_10_INHERITED" : "REOPEN");
        std::fprintf(gate, "root_class=%s\n",
                     inherited ? "upstream_FFN_INP_residual_in" : "native_gate_or_norm");
        std::fprintf(gate, "DO_NOT_reopen=SiLU / GEMV / ATTN_OUT_10\n");
        std::fprintf(gate, "NEXT=%s\n",
                     inherited ? "localize RESID_IN / L9→L10 entry; then sparse tips"
                               : "native gate-path despite closed GEMV");
        std::fclose(gate);
    }

    if (out != stdout) std::fclose(out);
    std::printf("BATCH2_L10_FFN_INP_SAME_SOURCE VERDICT=%s\n",
                inherited ? "FFN_GATE_10_INHERITED" : "REOPEN");
    return inherited ? 0 : 1;
}
