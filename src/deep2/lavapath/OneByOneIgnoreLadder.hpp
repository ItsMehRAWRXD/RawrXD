#pragma once
/* ONE_BY_ONE_IGNORE_LADDER_001 — diagnostic only. Exactly one ignore per run.
 * Env: DEEP2_ISOLATION_RUN=A0..A12  (default A0)
 * PROMOTE=0 always. ≤99 lines core API. */
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace rawr::iso_ladder {

using Clock = std::chrono::high_resolution_clock;
inline uint64_t Ns(Clock::time_point t0) noexcept {
    return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
               Clock::now() - t0)
        .count();
}

enum class Run : int {
    A0 = 0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, N
};

inline const char* RunName(Run r) noexcept {
    static const char* n[] = {"A0","A1","A2","A3","A4","A5","A6","A7","A8",
                              "A9","A10","A11","A12"};
    int i = (int)r;
    return (i >= 0 && i < (int)Run::N) ? n[i] : "A0";
}

inline const char* IgnoredOwner(Run r) noexcept {
    switch (r) {
    case Run::A0: return "NONE";
    case Run::A1: return "BATCH007_RECEIPT_EMIT";
    case Run::A2: return "PRODUCT_PATH_SEAL_EMIT";
    case Run::A3: return "DETOKENIZER_TEXT";
    case Run::A4: return "CALLBACK_STREAM";
    case Run::A5: return "SAMPLER_COMPLEXITY";
    case Run::A6: return "LOGITS_PROJECTION";
    case Run::A7: return "KV_WRITE_UPDATE";
    case Run::A8: return "LAYER_FORWARD";
    case Run::A9: return "ATTENTION";
    case Run::A10: return "FFN";
    case Run::A11: return "LAYER_COUNT_CLAMP";
    case Run::A12: return "TOKEN_EMBED";
    default: return "NONE";
    }
}

inline Run ParseRun() noexcept {
    const char* e = std::getenv("DEEP2_ISOLATION_RUN");
    if (!e || !e[0]) return Run::A0;
    if (e[0] == 'A' || e[0] == 'a') {
        int n = std::atoi(e + 1);
        if (n >= 0 && n < (int)Run::N) return (Run)n;
    }
    return Run::A0;
}

struct Acc {
    Run run = Run::A0;
    int decodePhase = 0; /* 1 after prefill complete */
    uint64_t wall0 = 0;
    uint64_t prefillNs = 0, decodeNs = 0;
    uint64_t forwardNs = 0, logitsNs = 0, sampleNs = 0;
    uint64_t detokNs = 0, callbackNs = 0, receiptNs = 0, kvNs = 0;
    uint64_t tokensCommitted = 0, tokensRequested = 0, tokensDecoded = 0;
    double baselineTps = 0.0;
};

inline Acc& A() noexcept {
    static Acc a;
    return a;
}

inline void Reset(uint64_t req) noexcept {
    A() = Acc{};
    A().run = ParseRun();
    A().tokensRequested = req;
    A().wall0 = (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
                    Clock::now().time_since_epoch())
                    .count();
    const char* b = std::getenv("DEEP2_ISOLATION_BASELINE_TPS");
    if (b && b[0]) A().baselineTps = std::atof(b);
}

inline bool Ignore(Run r) noexcept { return A().run == r; }
inline bool DecodeOnly() noexcept { return A().decodePhase != 0; }

inline void Emit(FILE* f = stderr) noexcept {
    if (!f) return;
    const Acc& a = A();
    const uint64_t now =
        (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now().time_since_epoch())
            .count();
    const double wallMs = (now > a.wall0) ? (now - a.wall0) / 1e6 : 0.0;
    const double decodeMs = a.decodeNs / 1e6;
    const double tps =
        (a.tokensCommitted > 1 && decodeMs > 0.0)
            ? (a.tokensCommitted - 1) * 1000.0 / decodeMs
            : ((a.tokensCommitted > 0 && wallMs > 0.0)
                   ? a.tokensCommitted * 1000.0 / wallMs
                   : 0.0);
    double dPct = 0.0;
    if (a.baselineTps > 0.0 && tps > 0.0)
        dPct = (tps - a.baselineTps) * 100.0 / a.baselineTps;
    std::fprintf(f,
        "ONE_BY_ONE_IGNORE_LADDER_001\n"
        "ISOLATION_RUN=%s\n"
        "IGNORED_OWNER=%s\n"
        "DIAGNOSTIC_ONLY=1\n"
        "PROMOTE=0\n"
        "TOKENS_REQUESTED=%llu\n"
        "TOKENS_COMMITTED=%llu\n"
        "TOKENS_DECODED=%llu\n"
        "TOTAL_WALL_MS=%.3f\n"
        "PREFILL_MS=%.3f\n"
        "DECODE_MS=%.3f\n"
        "FORWARD_MS=%.3f\n"
        "LOGITS_MS=%.3f\n"
        "SAMPLE_MS=%.3f\n"
        "DETOK_MS=%.3f\n"
        "CALLBACK_MS=%.3f\n"
        "RECEIPT_MS=%.3f\n"
        "KV_MS=%.3f\n"
        "TPS=%.3f\n"
        "DELTA_VS_BASELINE_PCT=%.3f\n"
        "ONE_BY_ONE_IGNORE_LADDER_END=1\n",
        RunName(a.run), IgnoredOwner(a.run),
        (unsigned long long)a.tokensRequested,
        (unsigned long long)a.tokensCommitted,
        (unsigned long long)a.tokensDecoded,
        wallMs, a.prefillNs / 1e6, decodeMs, a.forwardNs / 1e6,
        a.logitsNs / 1e6, a.sampleNs / 1e6, a.detokNs / 1e6,
        a.callbackNs / 1e6, a.receiptNs / 1e6, a.kvNs / 1e6, tps, dPct);
    std::fflush(f);
}

} // namespace rawr::iso_ladder
