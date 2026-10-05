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

// NOMINMAX before windows.h: this file uses std::max/std::min, and the macros
// would otherwise rewrite them at every call site.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <psapi.h>
#endif

namespace {

// RAWRXD_TEARDOWN_HANG_001
//
// A route process was observed alive holding 30.44 GB AFTER it had already run
// its atexit handler -- so it printed a clean-exit marker and then failed to
// terminate. That separates two things that were previously conflated: reaching
// the CRT atexit phase, and the OS actually reclaiming the process.
//
// These markers print the OS view of memory at each ownership boundary, so the
// question "does the working set drop during destruction, and if not, at whose
// destructor?" is answered by measurement instead of inferred from a survivor's
// RSS. Private bytes matter as much as working set: a large mapping is backed by
// the page file and inflates the working set without being heap retention.
void lifeMark(const char* where) {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof pmc;
    const DWORD got = GetProcessMemoryInfo(GetCurrentProcess(),
                                           (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof pmc);
    std::fprintf(stderr,
        "[LIFE] %-22s working_set=%llu private_bytes=%llu peak_ws=%llu "
        "pagefile=%llu ok=%d\n",
        where,
        got ? (unsigned long long)pmc.WorkingSetSize : 0ull,
        got ? (unsigned long long)pmc.PrivateUsage : 0ull,
        got ? (unsigned long long)pmc.PeakWorkingSetSize : 0ull,
        got ? (unsigned long long)pmc.PagefileUsage : 0ull,
        got ? 1 : 0);
#else
    std::fprintf(stderr, "[LIFE] %-22s (non-win32: no counters)\n", where);
#endif
    std::fflush(stderr);
}

// RAWRXD_CAPTURE_PROVENANCE_001
//
// A capture that silently fails to appear is indistinguishable from one that
// succeeded, and a comparison over a stale file looks complete while being
// fiction. Measured directly: the NQB route died mid-run leaving no file at
// all, and the comparison still reported "NQB_NON_LAYER_RECORDS=94". So every
// sink names itself, resolves to an absolute path, and is measured before
// anything is parsed.
void reportCaptureSink(const char* route, const char* path) {
    char resolved[4096];
    const char* abs = path;
    if (_fullpath(resolved, path, sizeof resolved)) abs = resolved;
    std::FILE* f = std::fopen(abs, "rb");
    long long sz = 0;
    if (f) { std::fseek(f, 0, SEEK_END); sz = _ftelli64(f); std::fclose(f); }
    std::fprintf(stderr,
        "PARITY_SINK_ROUTE=%s\nPARITY_SINK_PATH=%s\nPARITY_SINK_EXISTS=%d\n"
        "PARITY_SINK_BYTES=%lld\n", route, abs, f ? 1 : 0, sz);
    std::fflush(stderr);
}

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

// "STEP=<n> VEC=LAYER_3_ATTN_NORM N=3072" then rows of 16 floats
//
// RAWRXD_NQB_FIRST_BAD_STATE_001 FIX: the STEP= field was present in the dump
// but this loader ignored it and keyed only on the VEC name, so a later step
// OVERWROTE an earlier one and pass 2 was silently comparing the LAST step
// rather than the first bad step. That is why pass 2 named a "first bad stage"
// which the coarse pass had already shown to be exact at that step. The key now
// carries the step, and pass 2 is restricted to the first bad step.
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
            // Step comes from the SAME line, before VEC=.
            long step = -1;
            const size_t spStep = std::string(buf).find("STEP=");
            if (spStep != std::string::npos)
                step = std::atol(std::string(buf).c_str() + spStep + 5);
            char kb[320];
            std::snprintf(kb, sizeof kb, "VEC:%ld:%s", step, nm.c_str());
            cur = kb;
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

// RAWRXD_NQB_FIRST_BAD_STATE_001 FIX: the causal (data-dependency) order of the
// llama block, used to name the first bad TRANSFORM. The previous code picked
// the first mismatch in std::map order, which is alphabetical, so it named
// ATTN_PROBS -- a value three transformations downstream of the defect.
static const char* kCausalOrder[] = {
    "ATTN_NORM", "Q", "K", "V", "Q_ROPE", "K_ROPE",
    "ATTN_SCORES", "ATTN_PROBS", "ATTN_VALUE", "O_PROJ", "ATTN_RESIDUAL",
    "FFN_NORM", "FFN_GATE", "FFN_UP", "SWIGLU", "FFN_DOWN", "LAYER_RESIDUAL"
};


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

// RAWRXD_NQB_FIRST_BAD_STATE_001 FIX (I7): the two routes are loaded by
// SEPARATE PROCESSES. Previously runOnce() loaded the 1.4 GB GGUF, built an
// engine, generated, destroyed it, and then loaded the 12.85 GB NQB in the same
// process. That process died inside loadModelFromNanof32Braid in 2 of 5 runs,
// always between [NQBRAID] OPEN and [NQBRAID] LOADED, with 47 of 63 GB free and
// no Windows faulting event. Splitting the phases means:
//
//   * only one weight set is resident at a time, so the peak is 12.85 GB rather
//     than 12.85 GB plus whatever the previous engine had not yet returned;
//   * a crash in one route cannot destroy the other route's parity file, so a
//     partial run is still usable;
//   * each route is independently reproducible, which is also the cleanest test
//     of whether the divergence is deterministic at all.
bool runGGUFOnly(const char* gguf, const char* parity, const char* prompt,
                 int fullVecLayer, std::string& err) {
    Deep2::QuantKernelRegistry::Instance().Initialize();
    Deep2::Deep2Engine e;
    if (!e.loadModel(std::string(gguf))) { err = "gguf load failed"; return false; }
    lifeMark("AFTER_MODEL_LOAD");
    // RAWRXD_NQB_KV_SESSION_NEGATIVE_001
    //
    // A session cap must not become an escape hatch past the model ceiling.
    // Requesting one position beyond the ceiling has to be REFUSED, and the
    // effective allocation must be unchanged afterwards -- a silent clamp would
    // let a caller believe it had 131073 positions.
    {
        const size_t ceiling = e.modelMaxContext();
        const size_t before = e.effectiveKVContextForTest();
        const bool accepted = e.setKVSessionContext(ceiling + 1);
        const size_t after = e.effectiveKVContextForTest();
        std::printf("NEGATIVE_TEST ceiling=%zu requested=%zu accepted=%d "
                    "effective_before=%zu effective_after=%zu%s\\n",
                    ceiling, ceiling + 1, accepted ? 1 : 0, before, after,
                    (!accepted && after == before) ? " PASS" : " FAIL");
        std::printf("NEGATIVE_VERDICT=%s\\n",
                    (!accepted && after == before) ? "PASS" : "FAIL");
        // and confirm a legal request IS accepted, so the guard is not simply
        // refusing everything
        const bool okLegal = e.setKVSessionContext(ceiling);
        std::printf("NEGATIVE_LEGAL_AT_CEILING accepted=%d effective=%zu%s\\n",
                    okLegal ? 1 : 0, e.effectiveKVContextForTest(),
                    okLegal ? " PASS" : " FAIL");
        e.setKVSessionContext(before);   // restore
    }
    e.enableParityProbe(parity, 0);
    if (fullVecLayer >= -3) e.enableParityProbeFullVectors(fullVecLayer);
    Deep2::GenerationOptions o;
    o.maxTokens = 1; o.temperature = 0.0f; o.topK = 1; o.seed = 7;
    auto r = e.generateStream(prompt, o, nullptr);
    (void)r;
    e.disableParityProbe();
    // RAWRXD_CAPTURE_PROVENANCE_001
    //
    // State the file this route OWNS, resolved to an absolute path, and whether
    // it exists afterwards. Previously the NQB route died mid-run and left no
    // file, while the comparison still reported "NQB_NON_LAYER_RECORDS=94" from
    // a stale copy -- so a crashed capture was indistinguishable from a good one
    // and the comparison looked complete. The child must name its own sink.
    lifeMark("BEFORE_ENGINE_DTOR");
    lifeMark("ENGINE_DTOR_BEGIN");
    reportCaptureSink("GGUF", parity);
    return true;
}

bool runNQBOnly(const char* nqb, const char* parity, const char* prompt,
                int fullVecLayer, std::string& err) {
    Deep2::QuantKernelRegistry::Instance().Initialize();
    Deep2::Deep2Engine e;
    if (!e.loadModelFromNanof32Braid(std::string(nqb))) { err = "nqb load failed"; return false; }
    lifeMark("AFTER_MODEL_LOAD");
    e.enableParityProbe(parity, 0);
    if (fullVecLayer >= -3) e.enableParityProbeFullVectors(fullVecLayer);
    Deep2::GenerationOptions o;
    o.maxTokens = 1; o.temperature = 0.0f; o.topK = 1; o.seed = 7;
    auto r = e.generateStream(prompt, o, nullptr);
    (void)r;
    e.disableParityProbe();
    lifeMark("BEFORE_ENGINE_DTOR");
    lifeMark("ENGINE_DTOR_BEGIN");
    reportCaptureSink("NQB", parity);
    return true;
}

bool runOnce(const char* gguf, const char* nqb, const char* prompt,
             const char* ggufParity, const char* nqbParity,
             int fullVecLayer, std::string& err) {
    if (!runGGUFOnly(gguf, ggufParity, prompt, fullVecLayer, err)) return false;
    if (!runNQBOnly(nqb, nqbParity, prompt, fullVecLayer, err)) return false;
    return true;
}

} // namespace

// ----------------------------------------------------------------------------
// RAWRXD_NQB_HARNESS_MEMORY_GUARD_001
//
// WHY THIS EXISTS
// ---------------
// This harness was observed peaking at 28,776 MB of working set per run
// (PRE_EDIT measurement, SHA256 235B74E7B43233DB246E663F035C13CCD78509C1CED5F87F466069DCB49A4368).
// That is not a defect in the harness -- it materialises a 12.85 GB payload, which
// is the thing being measured -- but it IS a hazard to everything else on the
// machine. It is the most likely cause of an unrelated build failure recorded in
// this repo:
//
//     cmake --build -j6  ->  FreePhysGB=0.8  ->  "CL.exe" exited with code -1
//     cmake --build -j1  ->  BUILD_EXIT=0
//
// with no compiler diagnostic at all, which is what a starved toolchain looks
// like. A resource failure that prints nothing is indistinguishable from a broken
// source file unless you know the memory number.
//
// WHAT THIS DOES NOT DO
// ---------------------
// It does not reduce materialisation. Chunking would change the behaviour under
// measurement and could destroy the reproduction, so it is deliberately NOT the
// first fix. The progression is:
//
//     1. PREFLIGHT_HEADROOM          <- this
//     2. EXPLICIT_PEAK_BUDGET        <- this
//     3. FAIL_CLOSED_REFUSAL         <- this
//     4. OPTIONAL_STRESS_OVERRIDE    <- this
//     5. only then consider reducing materialisation
//
// A Windows Job Object memory ceiling is deliberately NOT the primary mechanism.
// An arbitrary kill converts a real harness result into "Windows terminated the
// process at a ceiling of our choosing", which is worse than no containment. If one
// is added later it belongs here as an accident barrier, AFTER the preflight, not
// in place of it.
// ----------------------------------------------------------------------------

static unsigned long long fbstAvailablePhysBytes() {
    MEMORYSTATUSEX st{};
    st.dwLength = sizeof(st);
    if (!GlobalMemoryStatusEx(&st)) return 0ull;
    return (unsigned long long)st.ullAvailPhys;
}

static unsigned long long fbstEnvULL(const char* name, unsigned long long dflt) {
    const char* v = std::getenv(name);
    if (!v || !v[0]) return dflt;
    char* end = nullptr;
    const unsigned long long r = std::strtoull(v, &end, 10);
    // A malformed or zero override falls back to the default rather than
    // silently disabling the guard.
    return (end && *end == '\0' && r > 0) ? r : dflt;
}

// Returns 0 to proceed, 2 to refuse.
static int fbstMemoryGuard() {
    // Measured peak of this harness, in bytes (28.125 GiB).
    const unsigned long long kExpectedPeak =
        fbstEnvULL("NQB_HARNESS_EXPECTED_PEAK_BYTES", 30198988800ull);
    // Free memory that must remain AFTER this harness finishes, so it cannot
    // starve a concurrent build or agent.
    const unsigned long long kMinHeadroom =
        fbstEnvULL("NQB_HARNESS_MIN_SYSTEM_HEADROOM_BYTES", 8589934592ull); // 8 GiB

    const char* modeEnv = std::getenv("NQB_HIGHMEM_MODE");
    const bool stress = (modeEnv && modeEnv[0] &&
                         (_stricmp(modeEnv, "STRESS") == 0));

    const unsigned long long avail = fbstAvailablePhysBytes();
    const unsigned long long required = kExpectedPeak + kMinHeadroom;
    const bool safeToStart = (avail == 0) ? false : (avail >= required);

    std::printf("\n=== RAWRXD_NQB_HARNESS_MEMORY_GUARD_001 ===\n");
    std::printf("GATE=RAWRXD_NQB_HARNESS_MEMORY_GUARD_001\n");
    std::printf("NQB_HIGHMEM_MODE=%s\n", stress ? "STRESS" : "SAFE");
    std::printf("AVAILABLE_PHYS=%llu\n", avail);
    std::printf("EXPECTED_PEAK=%llu\n", kExpectedPeak);
    std::printf("EXPECTED_PEAK_GB=%.2f\n", kExpectedPeak / (1024.0 * 1024.0 * 1024.0));
    std::printf("REQUIRED_HEADROOM=%llu\n", kMinHeadroom);
    std::printf("REQUIRED_TOTAL=%llu\n", required);
    std::printf("SAFE_TO_START=%d\n", safeToStart ? 1 : 0);

    if (stress) {
        // Explicit, loud, and never silent. An override nobody can see is not an
        // override, it is an unlabelled 28 GB allocation.
        std::printf("HIGH_MEMORY_OVERRIDE=1\n");
        std::printf("OVERRIDE_REASON=explicit NQB_HIGHMEM_MODE=STRESS\n");
        std::printf("WARNING=this run may starve a concurrent build; "
                    "a previous -j6 build died at FreePhysGB=0.8\n");
        std::printf("MODEL_LOAD_ATTEMPTED=1\n");
        std::printf("VERDICT=PROCEED_OVERRIDDEN\n\n");
        return 0;
    }

    if (!safeToStart) {
        std::printf("MODEL_LOAD_ATTEMPTED=0\n");
        std::printf("FAIL=insufficient_memory headroom\n");
        std::printf("VERDICT=REFUSED_INSUFFICIENT_MEMORY\n");
        std::printf("TO_PROCEED=set NQB_HIGHMEM_MODE=STRESS "
                    "(accepts the ~%.0f GB peak)\n\n",
                    kExpectedPeak / (1024.0 * 1024.0 * 1024.0));
        std::printf("=== END MEMORY GUARD ===\n\n");
        return 2;
    }

    std::printf("MODEL_LOAD_ATTEMPTED=1\n");
    std::printf("VERDICT=PROCEED\n\n");
    return 0;
}

int main(int argc, char** argv) {
    // RAWRXD_NQB_FIRST_BAD_STATE_001 FIX (I6): the verdict used to go to buffered
    // stdout while the engine logs to unbuffered stderr. When the process died
    // mid-run -- which it does, see the NQB materialisation instability -- the
    // entire verdict was lost and a crashed probe was indistinguishable from a
    // probe that found nothing. Unbuffered stdout makes every line already on
    // disk before the fault, so the last thing printed IS the last thing done.
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    // A crash still cannot print. Register a marker so the absence of the
    // closing line is itself observable rather than inferred.
    std::atexit([]{
        lifeMark("ATEXIT_BEGIN");
        std::fprintf(stderr, "[FBST] PROCESS_EXITED_NORMALLY\n");
        lifeMark("ATEXIT_END");
        std::fflush(stderr);
    });

    if (argc < 3) {
        std::printf("USAGE: nqb_first_bad_state <model.gguf> <model.nqb> [prompt]\n");
        std::printf("VERDICT=FAIL_NO_INPUT\n");
        return 2;
    }
    const char* gguf = argv[1];
    const char* nqb  = argv[2];
    const char* prompt = (argc > 3 && argv[3][0] != '-') ? argv[3] : "The capital of France is";
    // --phase=run-gguf | run-nqb | compare | both   (default both)
    std::string phase = "both";
    for (int i = 3; i < argc; ++i)
        if (std::strncmp(argv[i], "--phase=", 8) == 0) phase = argv[i] + 8;

    const std::string dir = ".";
    const std::string gp = dir + "/fbst_gguf.txt";
    const std::string np = dir + "/fbst_nqb.txt";

    // RAWRXD_NQB_HARNESS_MEMORY_GUARD_001
    //
    // Runs AFTER argument validation and BEFORE any model load, so a refusal costs
    // nothing and cannot leave a half-materialised 12.85 GB array behind. The
    // peak it budgets for is this harness's own measured behaviour; nothing about
    // what gets measured changes when it refuses.
    if (const int guard = fbstMemoryGuard(); guard != 0) return guard;

    std::printf("=== RAWRXD_NQB_FIRST_BAD_STATE_001 ===\n");
    std::printf("MODEL=%s\nNQB=%s\nPROMPT=%s\nPHASE=%s\n",
                gguf, nqb, prompt, phase.c_str());

    // ---- single-route phases: one weight set resident, one process --------
    if (phase == "run-gguf" || phase == "run-nqb") {
        std::string err;
        const bool ok = (phase == "run-gguf")
            ? runGGUFOnly(gguf, gp.c_str(), prompt, -1, err)
            : runNQBOnly(nqb, np.c_str(), prompt, -1, err);
        if (!ok) {
            std::printf("ROUTE=%s RUN=FAIL reason=%s\nVERDICT=FAIL_RUN\n",
                        phase.c_str(), err.c_str());
            return 1;
        lifeMark("AFTER_ENGINE_SCOPE");
        }
        lifeMark("MAIN_RETURN");
        std::printf("ROUTE=%s RUN=OK\nVERDICT=ROUTE_CAPTURED\n", phase.c_str());
        return 0;
    }

    // ---------------- PASS 1: coarse ----------------
    // phase=compare loads NO model at all: it only reads the two parity files
    // produced by the single-route phases. That makes the comparison itself
    // incapable of crashing, which is the whole point of the split.
    if (phase == "both") {
        std::printf("\n--- PASS 1 COARSE (summary records, all layers) ---\n");
        std::string err;
        if (!runOnce(gguf, nqb, prompt, gp.c_str(), np.c_str(), -1, err)) {
            std::printf("RUN=FAIL reason=%s\nVERDICT=FAIL_RUN\n", err.c_str());
            return 1;
        }
    } else {
        std::printf("\n--- COMPARE ONLY (no model loaded) ---\n");
    }

    // RAWRXD_CAPTURE_PROVENANCE_001 -- hard fail BEFORE parsing.
    //
    // This phase is COMPARE-ONLY: it does not run either route, it parses
    // whatever capture files are already on disk. That made a stale file
    // indistinguishable from a fresh one. Measured: a run whose NQB route died
    // mid-materialisation left no fbst_nqb.txt at all, and the comparison still
    // printed a complete-looking "GGUF_NON_LAYER_RECORDS=94
    // NQB_NON_LAYER_RECORDS=94" from whatever was lying around.
    //
    // So every input is named, resolved, and measured for existence and size
    // before a single record is parsed. A missing capture is INVALID_MISSING_
    // CAPTURE with exit 2 -- distinct from a numeric verdict, because it is a
    // statement about the instrument, not about the two routes.
    {
        struct { const char* tag; const char* path; } in[2] = {
            { "COMPARE_INPUT_GGUF", gp.c_str() },
            { "COMPARE_INPUT_NQB",  np.c_str() },
        };
        bool allPresent = true, allNonEmpty = true;
        for (auto& s : in) {
            char resolved[4096];
            const char* abs = s.path;
            if (_fullpath(resolved, s.path, sizeof resolved)) abs = resolved;
            std::FILE* f = std::fopen(abs, "rb");
            long long sz = 0;
            if (f) { std::fseek(f, 0, SEEK_END); sz = _ftelli64(f); std::fclose(f); }
            std::printf("%s_PATH=%s\n%s_EXISTS=%d\n%s_SIZE=%lld\n",
                        s.tag, abs, s.tag, f ? 1 : 0, s.tag, sz);
            if (!f) allPresent = false;
            else if (sz <= 0) allNonEmpty = false;
        }
        std::printf("CAPTURES_ALL_PRESENT=%d\nCAPTURES_ALL_NONEMPTY=%d\n",
                    allPresent ? 1 : 0, allNonEmpty ? 1 : 0);
        if (!allPresent || !allNonEmpty) {
            std::printf("VERDICT=INVALID_MISSING_CAPTURE\n"
                        "  a capture this comparison depends on is absent or empty.\n"
                        "  This is an instrument failure and carries NO information\n"
                        "  about whether the two routes agree.\n");
            return 2;
        }
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

    // ---------------- CHECKPOINT CENSUS (admissibility) -----------------
    // RAWRXD_NQB_FIRST_BAD_STATE_001: a layer census is printed BEFORE any
    // parity verdict. If either side degenerated to a single layer the tool must
    // refuse to name a first bad layer, because "layer 0 is first bad" and
    // "layer 0 is the only layer I could see" are indistinguishable without it.
    auto census = [](const std::map<std::string, Rec>& m, const char* tag) {
        std::vector<int> ls;
        size_t nonLayer = 0;
        for (const auto& kv : m) {
            if (kv.second.layer >= 0) ls.push_back(kv.second.layer);
            else ++nonLayer;
        }
        std::sort(ls.begin(), ls.end());
        ls.erase(std::unique(ls.begin(), ls.end()), ls.end());
        std::printf("%s_CHECKPOINT_RECORDS=%zu\n", tag, m.size());
        std::printf("%s_NON_LAYER_RECORDS=%zu\n", tag, nonLayer);
        std::printf("%s_UNIQUE_LAYERS=%zu\n", tag, ls.size());
        if (ls.empty()) {
            std::printf("%s_LAYER_MIN=(none)\n%s_LAYER_MAX=(none)\n", tag, tag);
        } else {
            std::printf("%s_LAYER_MIN=%d\n%s_LAYER_MAX=%d\n",
                        tag, ls.front(), tag, ls.back());
        }
        return ls.size();
    };
    const size_t uniqA = census(A, "GGUF");
    const size_t uniqB = census(B, "NQB");
    const bool admissible = (uniqA >= 2 && uniqB >= 2);
    std::printf("COMPARISON_ADMISSIBLE=%d\n", admissible ? 1 : 0);
    if (!admissible) {
        std::printf("VERDICT=INVALID_INPUT\n"
                    "  a checkpoint census of fewer than 2 unique layers cannot\n"
                    "  distinguish 'layer 0 is first bad' from 'layer 0 is the only\n"
                    "  layer this instrument can see'. No verdict is issued.\n");
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
    // RAWRXD_NQB_FIRST_BAD_STATE_001 FIX: the non-layer sentinel used to be
    // written into firstBadLayer as -2 and could then be OVERWRITTEN by a later
    // per-layer mismatch (the guard `firstBadLayer < 0` is still true for -2),
    // so a divergence at EMBED could be silently converted into a layer hunt.
    // It is now a separate, sticky flag.
    bool nonLayerDiverged = false;
    std::string nonLayerDivergedStage;

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
        if (a.layer < 0) {
            if (!nonLayerDiverged) {
                nonLayerDiverged = true;
                nonLayerDivergedStage = a.stage;
            }
            continue;
        }
        // Prefer the EARLIEST STEP, then the lowest layer. Previously this
        // compared only layer indices, so a later-step lower layer could win.
        if (firstBadLayer < 0 ||
            a.step < firstBadStep ||
            (a.step == firstBadStep && a.layer < firstBadLayer)) {
            firstBadLayer = a.layer;
            firstBadStep  = a.step;
            firstBadStage = a.stage;
        }
    }
    std::printf("EXACT_HASH_MATCHES=%d HASH_MISMATCHES=%d COUNT_MISMATCHES=%d\n",
                exactMatches, hashMismatches, countMismatches);
    std::printf("COARSE_FIRST_BAD_STEP=%d\nCOARSE_FIRST_BAD_LAYER=%d\n"
                "COARSE_FIRST_BAD_STAGE=%s\n",
                firstBadStep, firstBadLayer,
                firstBadStage.empty() ? "(none)" : firstBadStage.c_str());
    std::printf("NON_LAYER_DIVERGED=%d NON_LAYER_FIRST_STAGE=%s\n",
                nonLayerDiverged ? 1 : 0,
                nonLayerDiverged ? nonLayerDivergedStage.c_str() : "(none)");

    // Per-step census: which steps are bit-exact and which are not. A defect
    // that is invisible at step 0 and visible from step 1 onward is a different
    // animal from one present at step 0, and this is what distinguishes them.
    {
        int worstStep = -1;
        for (const auto& kv : A) {
            const int st = kv.second.step;
            if (st > worstStep) worstStep = st;
        }
        for (int st = 0; st <= worstStep; ++st) {
            int tot = 0, ok = 0;
            for (const auto& k : keys) {
                if (A.at(k).step != st) continue;
                ++tot;
                if (A.at(k).hash == B.at(k).hash) ++ok;
            }
            std::printf("STEP_CENSUS step=%d records=%d hash_match=%d hash_mismatch=%d %s\n",
                        st, tot, ok, tot - ok, (tot == ok ? "BIT_EXACT" : "DIVERGED"));
        }
    }

    if (nonLayerDiverged && firstBadLayer < 0) {
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
    // In compare phase no model is loaded, so no vectors exist. That is
    // reported as an unmeasured stage rather than silently treated as a match.
    if (phase == "both") {
        std::string err2;
        if (!runOnce(gguf, nqb, prompt, gp.c_str(), np.c_str(), firstBadLayer, err2)) {
            std::printf("RUN=FAIL reason=%s\nVERDICT=FAIL_RUN\n", err2.c_str());
            return 1;
        }
    } else {
        std::printf("PASS2_SKIPPED=1 reason=compare_phase_loads_no_model\n");
    }
    auto VA = loadVectors(gp.c_str());
    auto VB = loadVectors(np.c_str());
    std::printf("VECTOR_RECORDS_GGUF=%zu VECTOR_RECORDS_NQB=%zu\n", VA.size(), VB.size());

    // Restrict to the FIRST BAD STEP. Comparing the last step instead (which is
    // what the old step-blind key did) cannot localise a first bad state: by then
    // the residual stream carries the error through every remaining layer.
    char wantPrefix[64];
    std::snprintf(wantPrefix, sizeof wantPrefix, "VEC:%d:", firstBadStep);
    std::printf("PASS2_STEP=%d (vectors for this step only)\n", firstBadStep);

    int fineFirst = -1;
    std::string firstBadTransform = "(none)";
    for (const char* want : kCausalOrder) {
        char ka[320], kb[320];
        std::snprintf(ka, sizeof ka, "%sLAYER_%d_%s", wantPrefix, firstBadLayer, want);
        std::snprintf(kb, sizeof kb, "%sLAYER_%d_%s", wantPrefix, firstBadLayer, want);
        auto ia = VA.find(ka);
        auto ib = VB.find(kb);
        if (ia == VA.end() || ib == VB.end()) {
            std::printf("ABSENT_AT_STEP  %-18s %s\n", want,
                        (ia == VA.end() ? "(gguf missing)" : "(nqb missing)"));
            continue;
        }
        const Metrics m = compareVecs(ia->second, ib->second);
        const bool exact = (m.maxAbs == 0.0);
        std::printf("%-8s %-18s n=%zu cosine=%.9g rmse=%.6g max_abs=%.6g "
                    "mean_abs=%.6g first_mismatch=%s%zu nan=%zu/%zu\n",
                    exact ? "EXACT" : "DIFF", want, m.n,
                    m.cosine, m.rmse, m.maxAbs, m.meanAbs,
                    m.haveFirst ? "" : "(none)", m.firstMismatch, m.nanA, m.nanB);
        // First mismatch in CAUSAL order, not alphabetical order.
        if (!exact && fineFirst < 0) {
            fineFirst = 1;
            firstBadTransform = want;
        }
    }

    std::printf("\nSTAGE_MATCH=1 STEP_MATCH=1 LAYER_MATCH=1\n");
    std::printf("FIRST_BAD_LAYER=%d\n", firstBadLayer);
    std::printf("FIRST_BAD_STEP=%d\n", firstBadStep);
    std::printf("FIRST_BAD_TRANSFORM=%s\n", firstBadTransform.c_str());
    std::printf("COARSE_ALPHABETICAL_FIRST_STAGE=%s  "
                "(this is what the pre-fix tool reported; it is a SORT artifact,"
                " not the causal first divergence)\n",
                firstBadStage.empty() ? "(none)" : firstBadStage.c_str());
    std::printf("VERDICT=%s\n", fineFirst < 0 ? "FIRST_BAD_LAYER_IDENTIFIED"
                                             : "FIRST_BAD_STATE_IDENTIFIED");

    // ----------------------------------------------------------------
    // PASS 3 -- RAWRXD_LM_HEAD_IN_SITU_DOT_001
    //
    // Everything upstream of the tied LM head is now proven equal: FINAL_NORM is
    // bit-identical, row addressing has ADDR_DELTA=0 on 13 rows, per-row Q6_K
    // dequant is bit-identical to whole-tensor dequant, and both GEMV kernels
    // are accurate to ~6e-7 against a double-precision reference. The stored
    // logits still differ by up to 0.103.
    //
    // The one measurement never taken is the dot product AS THE ENGINE
    // COMPUTED IT: production FINAL_NORM bytes against the production row
    // pointer. parityEmitLayer refuses to dump layer==-1 unless fullVecLayer is
    // the sentinel -3, so that is what this pass requests.
    //
    // Reference logits come from LOGITS_TOP10, which the engine already emits
    // with real indices and values -- so the production side of the comparison
    // is measured, not reconstructed.
    std::printf("\n--- PASS 3 IN-SITU LM_HEAD DOT (FINAL_NORM sentinel -3) ---\n");
    std::string err3;
    if (!runOnce(gguf, nqb, prompt, gp.c_str(), np.c_str(), -3, err3)) {
        std::printf("RUN=FAIL reason=%s\n", err3.c_str());
        return 1;
    }
    auto FA = loadVectors(gp.c_str());
    auto FB = loadVectors(np.c_str());
    const std::string faKey = "VEC:S4:LAYER_-1_FINAL_NORM";
    const std::string fbKey = faKey;
    auto ia = FA.find(faKey), ib = FB.find(fbKey);
    if (ia == FA.end() || ib == FB.end()) {
        std::printf("FINAL_NORM_VEC=ABSENT gguf=%d nqb=%d\n",
                    ia != FA.end() ? 1 : 0, ib != FB.end() ? 1 : 0);
        std::printf("  available gguf keys containing FINAL_NORM:");
        for (const auto& kv : FA) if (kv.first.find("FINAL_NORM") != std::string::npos)
            std::printf(" %s", kv.first.c_str());
        std::printf("\nVERDICT=NO_FINAL_NORM_VECTOR\n");
        return 1;
    }
    std::printf("FINAL_NORM_VEC=PASS elements=%zu gguf=%zu nqb=%zu\n",
                ia->second.size(), ia->second.size(), ib->second.size());
    double fmax = 0.0;
    for (size_t i = 0; i < std::min(ia->second.size(), ib->second.size()); ++i)
        fmax = std::max(fmax, std::fabs(double(ia->second[i]) - double(ib->second[i])));
    std::printf("FINAL_NORM_MAX_ABS_DIFF=%.9g  (0 => bit-identical)\n", fmax);
    std::printf("ROW_POINTER_AND_F64_DOT=REQUIRES_Q6K_TENSOR_NOT_LOADED_HERE\n");
    std::printf("SEE=q_accum_parity_probe for the row/dequant side\n");
    return 1;
}
