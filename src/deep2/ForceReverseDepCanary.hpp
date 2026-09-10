#pragma once
/* AUDIT-ONLY fail-closed dep corruption canary.
 * Production path never commits bad state. FORCE_REVERSE_DEP[_CORRUPTION]=1. */
#include "DepStamp.hpp"
#include "StreamPathTiming.hpp"
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace Deep2 {
namespace revdep {

enum class Edge : uint8_t { QbToAttention = 0 };

inline bool Wanted() noexcept {
    const char* e = std::getenv("FORCE_REVERSE_DEP");
    if (e && e[0] == '1') return true;
    e = std::getenv("FORCE_REVERSE_DEP_CORRUPTION");
    return e && e[0] == '1';
}

inline bool& FiredThisRun() noexcept {
    static bool f = false;
    return f;
}

inline uint64_t Fnv1a(const float* p, size_t n) noexcept {
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; ++i) {
        uint32_t u;
        std::memcpy(&u, &p[i], 4);
        h ^= u;
        h *= 1099511628211ull;
    }
    return h;
}

inline int FiniteAll(const float* p, size_t n) noexcept {
    for (size_t i = 0; i < n; ++i)
        if (!std::isfinite(p[i])) return 0;
    return 1;
}

inline int Argmax(const float* p, size_t n) noexcept {
    if (!p || !n) return -1;
    int b = 0;
    for (size_t i = 1; i < n; ++i)
        if (p[i] > p[b]) b = (int)i;
    return b;
}

inline uint64_t DiffBytes(const float* a, const float* b, size_t n) noexcept {
    uint64_t d = 0;
    for (size_t i = 0; i < n; ++i) {
        uint32_t ua, ub;
        std::memcpy(&ua, &a[i], 4);
        std::memcpy(&ub, &b[i], 4);
        if (ua != ub) d += 4;
    }
    return d;
}

struct Evidence {
    uint64_t producerIssue = 0, producerComplete = 0;
    uint64_t consumerStart = 0, consumerEnd = 0;
    uint64_t goodHash = 0, badHash = 0;
    int argmaxGood = -1, argmaxBad = -1;
    int finiteGood = 1, finiteBad = 1;
    uint64_t outputDiff = 0;
    int fault = 0;
    const char* classif = "NONE";
};

inline void Classify(Evidence& e) noexcept {
    const bool reversed = e.consumerStart < e.producerComplete;
    if (!reversed)
        e.classif = "DEPENDENCY_VALID";
    else if (e.fault)
        e.classif = "DEP_CORRUPTION_CRASHED";
    else if (e.goodHash != e.badHash || e.outputDiff)
        e.classif = "CORRUPTION_DEP_CONFIRMED";
    else
        e.classif = "VIOLATION_OBSERVED_NO_MANIFESTATION";
}

inline void Emit(FILE* f, const Evidence& e) noexcept {
    if (!f) f = stderr;
    std::fprintf(f,
        "EDGE=Q_B->ATTENTION\n"
        "PRODUCER_ISSUE=%llu PRODUCER_COMPLETE=%llu\n"
        "CONSUMER_START=%llu CONSUMER_END=%llu\n"
        "GOOD_HIDDEN_HASH=%llu BAD_HIDDEN_HASH=%llu\n"
        "ARGMAX_GOOD=%d ARGMAX_BAD=%d\n"
        "FINITE_GOOD=%d FINITE_BAD=%d\n"
        "OUTPUT_DIFF=%llu FAULT=%d CLASS=%s\n"
        "AUDIT_ONLY=1 PERSIST=0 PROMOTE=0 KV_COMMIT=0 TOKEN_COMMIT=0\n"
        "PRODUCTION_DEP=RESTORED SYNTHETIC=0 BAD_AUTHORITATIVE=0\n",
        (unsigned long long)e.producerIssue,
        (unsigned long long)e.producerComplete,
        (unsigned long long)e.consumerStart,
        (unsigned long long)e.consumerEnd,
        (unsigned long long)e.goodHash, (unsigned long long)e.badHash,
        e.argmaxGood, e.argmaxBad, e.finiteGood, e.finiteBad,
        (unsigned long long)e.outputDiff, e.fault, e.classif);
}

} // namespace revdep
} // namespace Deep2
