#pragma once
// ============================================================================
// DecodeBlockerAttribution.hpp
// Source-only Deep2 diagnostic timer for one-by-one decode owner isolation.
//
// Scope:
//   - Diagnostic authority only.
//   - Does not change execution results.
//   - Emits comparable per-run owner timing with PROMOTE=0.
// ============================================================================

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace Deep2::decode_blocker {

struct Acc {
    double forwardMs = 0.0;
    double logitsMs = 0.0;
    double sampleMs = 0.0;
    double detokMs = 0.0;
    double callbackMs = 0.0;
    double receiptMs = 0.0;
    double kvMs = 0.0;
    double otherMs = 0.0;
    std::uint64_t tokensRequested = 0;
    std::uint64_t tokensCommitted = 0;
    std::uint64_t tokensDecoded = 0;
    std::uint64_t singleDecodeCalls = 0;
    std::uint64_t sequenceDecodeCalls = 0;
};

inline Acc& A() {
    static Acc a;
    return a;
}

inline void Reset(std::uint64_t requested = 0) noexcept {
    A() = Acc{};
    A().tokensRequested = requested;
}

inline double NowMs() noexcept {
    using clock = std::chrono::high_resolution_clock;
    return (double)std::chrono::duration_cast<std::chrono::nanoseconds>(
        clock::now().time_since_epoch()).count() / 1000000.0;
}

struct Scope {
    double& slot;
    double t0;
    explicit Scope(double& s) noexcept : slot(s), t0(NowMs()) {}
    ~Scope() noexcept { slot += NowMs() - t0; }
};

inline const char* Owner(const Acc& a) noexcept {
    struct Pair { const char* n; double v; } p[] = {
        {"FORWARD", a.forwardMs}, {"LOGITS", a.logitsMs}, {"SAMPLE", a.sampleMs},
        {"DETOK", a.detokMs}, {"CALLBACK", a.callbackMs}, {"RECEIPT", a.receiptMs},
        {"KV", a.kvMs}, {"OTHER", a.otherMs}
    };
    const Pair* best = &p[0];
    for (const auto& x : p) if (x.v > best->v) best = &x;
    return best->n;
}

inline void NoteCommitted(std::uint64_t n = 1) noexcept { A().tokensCommitted += n; }
inline void NoteSingleDecode() noexcept { A().tokensDecoded += 1; A().singleDecodeCalls += 1; }
inline void NoteSequenceDecode(std::uint64_t ids) noexcept { A().tokensDecoded += ids; A().sequenceDecodeCalls += 1; }

inline void Emit(FILE* f, double totalWallMs, double prefillMs, double decodeMs,
                 const char* ignoredOwner = "NONE") noexcept {
    if (!f) f = stderr;
    const Acc& a = A();
    const double accounted = a.forwardMs + a.logitsMs + a.sampleMs + a.detokMs +
                             a.callbackMs + a.receiptMs + a.kvMs + a.otherMs;
    const double replay = a.tokensCommitted ?
        (double)a.tokensDecoded / (double)a.tokensCommitted : 0.0;
    std::fprintf(f, "DECODE_BLOCKER_ATTRIBUTION_BEGIN=1\n");
    std::fprintf(f, "IGNORED_OWNER=%s DIAGNOSTIC_ONLY=1 PROMOTE=0\n", ignoredOwner ? ignoredOwner : "NONE");
    std::fprintf(f, "TOKENS_REQUESTED=%llu TOKENS_COMMITTED=%llu TOKENS_DECODED=%llu\n",
        (unsigned long long)a.tokensRequested,
        (unsigned long long)a.tokensCommitted,
        (unsigned long long)a.tokensDecoded);
    std::fprintf(f, "TOKENIZER_SINGLE_CALLS=%llu TOKENIZER_SEQUENCE_CALLS=%llu DECODE_REPLAY_FACTOR=%.6f\n",
        (unsigned long long)a.singleDecodeCalls,
        (unsigned long long)a.sequenceDecodeCalls,
        replay);
    std::fprintf(f, "TOTAL_WALL_MS=%.3f PREFILL_MS=%.3f DECODE_MS=%.3f ACCOUNTED_MS=%.3f\n",
        totalWallMs, prefillMs, decodeMs, accounted);
    std::fprintf(f, "FORWARD_MS=%.3f LOGITS_MS=%.3f SAMPLE_MS=%.3f DETOK_MS=%.3f CALLBACK_MS=%.3f RECEIPT_MS=%.3f KV_MS=%.3f OTHER_MS=%.3f\n",
        a.forwardMs, a.logitsMs, a.sampleMs, a.detokMs, a.callbackMs,
        a.receiptMs, a.kvMs, a.otherMs);
    std::fprintf(f, "DECODE_OWNER=%s\n", Owner(a));
    std::fprintf(f, "DECODE_BLOCKER_ATTRIBUTION_END=1\n");
    std::fflush(f);
}

} // namespace Deep2::decode_blocker

#define RAWR_DECODE_SCOPE_FORWARD()  Deep2::decode_blocker::Scope _rawr_decode_forward_scope(Deep2::decode_blocker::A().forwardMs)
#define RAWR_DECODE_SCOPE_LOGITS()   Deep2::decode_blocker::Scope _rawr_decode_logits_scope(Deep2::decode_blocker::A().logitsMs)
#define RAWR_DECODE_SCOPE_SAMPLE()   Deep2::decode_blocker::Scope _rawr_decode_sample_scope(Deep2::decode_blocker::A().sampleMs)
#define RAWR_DECODE_SCOPE_DETOK()    Deep2::decode_blocker::Scope _rawr_decode_detok_scope(Deep2::decode_blocker::A().detokMs)
#define RAWR_DECODE_SCOPE_CALLBACK() Deep2::decode_blocker::Scope _rawr_decode_callback_scope(Deep2::decode_blocker::A().callbackMs)
#define RAWR_DECODE_SCOPE_RECEIPT()  Deep2::decode_blocker::Scope _rawr_decode_receipt_scope(Deep2::decode_blocker::A().receiptMs)
#define RAWR_DECODE_SCOPE_KV()       Deep2::decode_blocker::Scope _rawr_decode_kv_scope(Deep2::decode_blocker::A().kvMs)
