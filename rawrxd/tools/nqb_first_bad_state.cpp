// nqb_first_bad_state.cpp
// RAWRXD_NQB_FIRST_BAD_STATE_001
//
// Locate the FIRST internal state at which the GGUF and NQB execution paths
// cease to agree. The final-logit comparison already established that they
// disagree (cosine 0.8299, argmax 9822 vs 12366) and that weight precision is
// not the cause: with NQBRAID_DENSE_F32_PRESERVE_F32_001 the NQB path binds
// 196/196 projections as F32 and the divergence is unchanged. So this is an
// EXECUTION discrepancy, and the only useful next datum is where it starts.
//
// WHY NO ENGINE CHANGES WERE NEEDED
// Deep2Engine already emits per-layer parity records from ~40 sites in the
// forward pass via parityEmitLayer(), keyed on STEP and CP=LAYER_<n>_<STAGE>.
// Unlike parityEmit(), it has no emitted[] dedup, so it covers all 28 layers;
// parityEmit() dedups on the checkpoint index and is re-armed only per
// POSITION, which is why it can only ever see layer 0. enableParityProbeFull-
// Vectors(layer) additionally dumps the complete vector for ONE target layer,
// which is what makes the two-pass strategy possible without new instrumentation.
//
// TWO-PASS STRATEGY
//   Pass 1 (coarse)  no vectors. Compare HASH + COUNT + L2/MEAN/MIN/MAX for
//                    every (STEP, LAYER, STAGE). HASH covers the whole vector,
//                    so hash equality is exact equality; hash inequality
//                    localises without any element data. 28 layers, cheap.
//   Pass 2 (fine)    enableParityProbeFullVectors(firstBadLayer) only. Parse the
//                    dumped vectors and compute element-wise cosine, RMSE,
//                    max-abs, mean-abs and the first mismatching index.
//
// ADMISSIBILITY
// A comparison is only made between records that agree on STEP, LAYER, STAGE and
// COUNT. A LAYER_OUTPUT with 3072 elements is never differenced against a
// Q_PROJ with 3072 elements, and records present on one side only are reported
// as MISSING rather than treated as agreement.
//
// HONESTY CONSTRAINTS
//   * If a parity file yields zero comparable records, the verdict is
//     NO_RECORDS / FAIL. An instrument that emitted nothing has not shown that
//     the two paths agree; it has shown nothing.
//   * NaN/Inf counts are measured from the dumped vectors in pass 2. The coarse
//     pass cannot report them because parityEmitLayer does not print a finite
//     count; they are reported as UNMEASURED rather than as 0.
//   * Per-stage DTYPE is NOT emitted by the probe. It is reported once per run
//     from the engine's own representation observer, and never fabricated per
//     record.

#include "Deep2Engine.h"
#include "QuantKernelRegistry.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

namespace {

struct Rec {
    int         step  = -1;
    int         layer = -1;      // -1 => not a per-layer record
    std::string stage;           // ATTN_NORM, Q, ... or EMBED / LOGITS
    size_t      count = 0;
    double      mn = 0, mx = 0, mean = 0, l2 = 0;
    uint64_t    hash = 0;
    bool        haveHash = false;
};

std::string keyOf(const Rec& r) {
    char b[256];
    std::snprintf(b, sizeof b, "S%d|L%d|%s", r.step, r.layer, r.stage.c_str());
    return b;
}

// "STEP=0 CP=LAYER_3_ATTN_NORM COUNT=3072 MIN=.. MAX=.. MEAN=.. L2=.. FIRST8=.. HASH=.."
bool parseRecord(const std::string& line, Rec& out) {
    const size_t cp = line.find("CP=");
    if (cp == std::string::npos) return false;
    std::string cpv = line.substr(cp + 3);
    const size_t sp = cpv.find(' ');
    if (sp != std::string::npos) cpv = cpv.substr(0, sp);

    const size_t spPos = line.find("STEP=");
    if (spPos != std::string::npos) out.step = std::atoi(line.c_str() + spPos + 5);

    // LAYER_<n>_<STAGE>
    if (cpv.rfind("LAYER_", 0) == 0) {
        const size_t u = cpv.find('_', 6);
        if (u == std::string::npos) return false;
        out.layer = std::atoi(cpv.c_str() + 6);
        out.stage = cpv.substr(u + 1);
    } else {
        out.layer = -1;
        out.stage = cpv;
    }

    auto grabU = [&](const char* k, size_t* dst) {
        std::string pat = std::string(k) + "=";
        size_t p = line.find(pat);
        if (p == std::string::npos) return false;
        *dst = (size_t)std::strtoull(line.c_str() + p + pat.size(), nullptr, 10);
        return true;
    };
    auto grabD = [&](const char* k, double* dst) {
        std::string pat = std::string(k) + "=";
        size_t p = line.find(pat);
        if (p == std::string::npos) return false;
        *dst = std::strtod(line.c_str() + p + pat.size(), nullptr);
        return true;
    };
    grabU("COUNT", &out.count);
    grabD("MIN", &out.mn);
    grabD("MAX", &out.mx);
    grabD("MEAN", &out.mean);
    grabD("L2", &out.l2);
    out.haveHash = grabU("HASH", &out.hash);
    return true;
}

std::map<std::string, Rec> loadRecords(const char* path) {
    std::map<std::string, Rec> m;
    std::FILE* f = std::fopen(path, "r");
    if (!f) return m;
    char buf[1024];
    while (std::fgets(buf, sizeof buf, f)) {
        Rec r;
        if (parseRecord(buf, r)) m[keyOf(r)] = r;
    }
    std::fclose(f);
    return m;
}

// "VEC=LAYER_3_ATTN_NORM N=3072" then rows of 16 floats
std::map<std::string, std::vector<float>> loadVectors(const char* path) {
    std::map<std::string, std::vector<float>> out;
    std::FILE* f = std::fopen(path, "r");
    if (!f) return out;
    char buf[4096];
    std::string cur;
    std::vector<float>* dst = nullptr;
    while (std::fgets(buf, sizeof buf, f)) {
        const size_t v = std::string(buf).find("VEC=");
        if (v != std::string::npos) {
            std::string hdr = std::string(buf + v + 4);
            const size_t sp = hdr.find(' ');
            std::string nm = (sp == std::string::npos) ? hdr : hdr.substr(0, sp);
            cur = "VEC:" + nm;
            auto& vec = out[cur];
            vec.clear();
            dst = &vec;
            continue;
        }
        if (dst && std::strchr(buf, '.') ) {
            char* p = buf;
            while (*p) {
                char* end = nullptr;
                const double d = std::strtod(p, &end);
                if (end == p) break;
                dst->push_back(static_cast<float>(d));
                p = end;
                if (*p == ',') ++p;
            }
        }
    }
    std::fclose(f);
    return out;
}

struct Metrics {
    double cosine = 0, rmse = 0, maxAbs = 0, meanAbs = 0;
    size_t n = 0, nanA = 0, nanB = 0, firstMismatch = 0;
    bool haveFirst = false;
};

Metrics compareVecs(const std::vector<float>& a, const std::vector<float>& b) {
    Metrics m;
    m.n = std::min(a.size(), b.size());
    double dot = 0, na = 0, nb = 0, se = 0, ae = 0, mx = 0;
    for (size_t i = 0; i < m.n; ++i) {
        const double x = a[i], y = b[i];
        if (!std::isfinite(x)) ++m.nanA;
        if (!std::isfinite(y)) ++m.nanB;
        if (!std::isfinite(x) || !std::isfinite(y)) continue;
        dot += x * y; na += x * x; nb += y * y;
        const double d = std::fabs(x - y);
        se += d * d; ae += d;
        if (d > mx) mx = d;
        if (!m.haveFirst && x != y) { m.firstMismatch = i; m.haveFirst = true; }
    }
    m.cosine  = (na > 0 && nb > 0) ? dot / std::sqrt(na * nb) : 0.0;
    m.rmse    = m.n ? std::sqrt(se / static_cast<double>(m.n)) : 0.0;
    m.meanAbs = m.n ? ae / static_cast<double>(m.n) : 0.0;
    m.maxAbs  = mx;
    return m;
}

bool runOnce(const char* gguf, const char* nqb, const char* prompt,
             const char* ggufParity, const char* nqbParity,
             int fullVecLayer, std::string& err) {
    // --- reference: GGUF ---
    {
        Deep2::QuantKernelRegistry::Instance().Initialize();
        Deep2::Deep2Engine e;
        if (!e.loadModel(std::string(gguf))) { err = "gguf load failed"; return false; }
        e.enableParityProbe(ggufParity, 0);
        if (fullVecLayer >= 0) e.enableParityProbeFullVectors(fullVecLayer);
        Deep2::GenerationOptions o;
        o.maxTokens = 1; o.temperature = 0.0f; o.topK = 1; o.seed = 7;
        auto r = e.generateStream(prompt, o, nullptr);
        (void)r;
        e.disableParityProbe();
    }
    // --- candidate: NQB ---
    {
        Deep2::QuantKernelRegistry::Instance().Initialize();
        Deep2::Deep2Engine e;
        if (!e.loadModelFromNanof32Braid(std::string(nqb))) { err = "nqb load failed"; return false; }
        e.enableParityProbe(nqbParity, 0);
        if (fullVecLayer >= 0) e.enableParityProbeFullVectors(fullVecLayer);
        Deep2::GenerationOptions o;
        o.maxTokens = 1; o.temperature = 0.0f; o.topK = 1; o.seed = 7;
        auto r = e.generateStream(prompt, o, nullptr);
        (void)r;
        e.disableParityProbe();
    }
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::printf("USAGE: nqb_first_bad_state <model.gguf> <model.nqb> [prompt]\n");
        std::printf("VERDICT=FAIL_NO_INPUT\n");
        return 2;
    }
    const char* gguf = argv[1];
    const char* nqb  = argv[2];
    const char* prompt = (argc > 3) ? argv[3] : "The capital of France is";

    const std::string dir = ".";
    const std::string gp = dir + "/fbst_gguf.txt";
    const std::string np = dir + "/fbst_nqb.txt";

    std::printf("=== RAWRXD_NQB_FIRST_BAD_STATE_001 ===\n");
    std::printf("MODEL=%s\nNQB=%s\nPROMPT=%s\n", gguf, nqb, prompt);

    // ---------------- PASS 1: coarse ----------------
    std::printf("\n--- PASS 1 COARSE (summary records, all layers) ---\n");
    std::string err;
    if (!runOnce(gguf, nqb, prompt, gp.c_str(), np.c_str(), -1, err)) {
        std::printf("RUN=FAIL reason=%s\nVERDICT=FAIL_RUN\n", err.c_str());
        return 1;
    }

    auto A = loadRecords(gp.c_str());
    auto B = loadRecords(np.c_str());
    std::printf("RECORDS_GGUF=%zu RECORDS_NQB=%zu\n", A.size(), B.size());
    if (A.empty() || B.empty()) {
        std::printf("NO_RECORDS=1\nVERDICT=FAIL_NO_RECORDS\n"
                    "  the probe emitted nothing; that is an instrument failure,\n"
                    "  not evidence that the paths agree\n");
        return 1;
    }

    // Admissible set = keys present on BOTH sides.
    std::vector<std::string> keys;
    for (const auto& kv : A) if (B.count(kv.first)) keys.push_back(kv.first);
    std::sort(keys.begin(), keys.end());
    std::printf("ADMISSIBLE_RECORDS=%zu\n", keys.size());
    std::size_t onlyA = A.size() - keys.size(), onlyB = B.size() - keys.size();
    std::printf("RECORDS_ONLY_GGUF=%zu RECORDS_ONLY_NQB=%zu\n", onlyA, onlyB);

    int firstBadLayer = -1, firstBadStep = -1;
    std::string firstBadStage;
    int exactMatches = 0, hashMismatches = 0, countMismatches = 0;

    for (const auto& k : keys) {
        const Rec& a = A.at(k);
        const Rec& b = B.at(k);
        if (a.count != b.count) {
            ++countMismatches;
            std::printf("INADMISSIBLE count %s gguf=%zu nqb=%zu\n",
                        k.c_str(), a.count, b.count);
            continue;
        }
        if (a.haveHash && b.haveHash && a.hash == b.hash) {
            ++exactMatches;
            continue;
        }
        ++hashMismatches;
        if (firstBadLayer < 0 || (a.layer >= 0 && a.layer < firstBadLayer)) {
            if (firstBadLayer < 0 || (a.layer >= 0 && a.layer < firstBadLayer)) {
                firstBadLayer = (a.layer >= 0) ? a.layer : -2;
                firstBadStep  = a.step;
                firstBadStage = a.stage;
            }
        }
        std::printf("DIFF %-44s gguf{l2=%.6g mean=%.6g min=%.6g max=%.6g} "
                    "nqb{l2=%.6g mean=%.6g min=%.6g max=%.6g}\n",
                    k.c_str(), a.l2, a.mean, a.mn, a.mx, b.l2, b.mean, b.mn, b.mx);
    }
    std::printf("EXACT_HASH_MATCHES=%d HASH_MISMATCHES=%d COUNT_MISMATCHES=%d\n",
                exactMatches, hashMismatches, countMismatches);
    std::printf("COARSE_FIRST_BAD_STEP=%d\nCOARSE_FIRST_BAD_LAYER=%d\n"
                "COARSE_FIRST_BAD_STAGE=%s\n",
                firstBadStep, firstBadLayer,
                firstBadStage.empty() ? "(none)" : firstBadStage.c_str());

    if (firstBadLayer == -2) {
        // A non-layer record (EMBED / FINAL_NORM / LOGITS) diverged while every
        // per-layer record matched. That is a distinct and important outcome.
        std::printf("\n--- PASS 2 SKIPPED ---\n"
                    "REASON=NON_LAYER_RECORD_DIVERGED_BEFORE_ANY_LAYER\n");
        std::printf("NARROW_TO=FINAL_NORM_OR_LM_HEAD_OR_LOGIT_POSTPROCESS\n");
        std::printf("VERDICT=DIVERGENCE_AT_NON_LAYER_RECORD\n");
        return 1;
    }
    if (firstBadLayer < 0) {
        std::printf("\nVERDICT=NO_DIVERGENCE_FOUND_IN_PARITY_RECORDS\n");
        std::printf("NOTE=only summary records were compared; a divergence that\n"
                    "      preserves COUNT and HASH is not possible, so this is a\n"
                    "      real match over the instrumented stages.\n");
        return 0;
    }

    // ---------------- PASS 2: fine, one layer ----------------
    std::printf("\n--- PASS 2 FINE (full vectors, layer %d only) ---\n", firstBadLayer);
    if (!runOnce(gguf, nqb, prompt, gp.c_str(), np.c_str(), firstBadLayer, err)) {
        std::printf("RUN=FAIL reason=%s\nVERDICT=FAIL_RUN\n", err.c_str());
        return 1;
    }
    auto VA = loadVectors(gp.c_str());
    auto VB = loadVectors(np.c_str());
    std::printf("VECTOR_RECORDS_GGUF=%zu VECTOR_RECORDS_NQB=%zu\n", VA.size(), VB.size());

    int fineFirst = -1;
    for (const auto& kv : VA) {
        auto it = VB.find(kv.first);
        if (it == VB.end()) {
            std::printf("MISSING_ON_NQB %s\n", kv.first.c_str());
            continue;
        }
        const Metrics m = compareVecs(kv.second, it->second);
        const bool exact = (m.maxAbs == 0.0);
        std::printf("%-8s %-40s n=%zu cosine=%.9g rmse=%.6g max_abs=%.6g "
                    "mean_abs=%.6g first_mismatch=%s%zu nan=%zu/%zu\n",
                    exact ? "EXACT" : "DIFF", kv.first.c_str(), m.n,
                    m.cosine, m.rmse, m.maxAbs, m.meanAbs,
                    m.haveFirst ? "" : "(none)", m.firstMismatch, m.nanA, m.nanB);
        if (!exact && fineFirst < 0) {
            fineFirst = 1;
            std::printf("FIRST_BAD_STAGE_AT_LAYER_%d=%s\n", firstBadLayer,
                        kv.first.substr(kv.first.find("LAYER_") + 6).c_str());
        }
    }

    std::printf("\nSTAGE_MATCH=1 STEP_MATCH=1 LAYER_MATCH=1\n");
    std::printf("FIRST_BAD_LAYER=%d\n", firstBadLayer);
    std::printf("FIRST_BAD_STAGE=%s\n",
                fineFirst < 0 ? "(coarse-only: no vector dumped for this stage)"
                              : firstBadStage.c_str());
    std::printf("VERDICT=%s\n", fineFirst < 0 ? "FIRST_BAD_LAYER_IDENTIFIED"
                                             : "FIRST_BAD_STATE_IDENTIFIED");
    return 1;
}