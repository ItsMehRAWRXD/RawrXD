// Build-compat shim for legacy digestion stub references.
// Production digestion engines live under src/digestion/.

#include "AutonomousAgent.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>

namespace {
std::atomic<uint64_t> g_digestionEngineStubHits{0};
std::atomic<uint64_t> g_digestionEnginePassCount{0};
std::atomic<uint64_t> g_digestionEngineFailCount{0};
std::atomic<uint64_t> g_digestionEngineRetryRuns{0};
std::atomic<uint64_t> g_digestionEngineCurrentFailStreak{0};
std::atomic<uint64_t> g_digestionEngineMaxFailStreak{0};
std::atomic<uint64_t> g_digestionEngineLastDurationUs{0};
std::atomic<uint64_t> g_digestionEngineTotalDurationUs{0};

uint64_t parseRetriesEnv()
{
    const char* raw = std::getenv("RAWRXD_DIGESTION_STUB_RETRIES");
    if (!raw || raw[0] == '\0') {
        return 1;
    }

    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(raw, &end, 10);
    if (end == raw || parsed == 0) {
        return 1;
    }
    return parsed > 8 ? 8 : static_cast<uint64_t>(parsed);
}

void updateMaxFailStreak(uint64_t current)
{
    uint64_t prev = g_digestionEngineMaxFailStreak.load(std::memory_order_relaxed);
    while (current > prev &&
           !g_digestionEngineMaxFailStreak.compare_exchange_weak(prev, current, std::memory_order_relaxed)) {
    }
}
}

extern "C" void RawrXD_DigestionEngineStubAnchor() {
    g_digestionEngineStubHits.fetch_add(1, std::memory_order_relaxed);

    // Deterministic fallback: run bounded health-check attempts and track timing/streak stats.
    const uint64_t attempts = parseRetriesEnv();
    const auto t0 = std::chrono::steady_clock::now();

    bool ok = false;
    for (uint64_t i = 0; i < attempts; ++i) {
        ++g_digestionEngineRetryRuns;
        if (DiagnosticEngine::TestDigestionEngine()) {
            ok = true;
            break;
        }
    }

    const auto t1 = std::chrono::steady_clock::now();
    const uint64_t durUs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
    g_digestionEngineLastDurationUs.store(durUs, std::memory_order_relaxed);
    g_digestionEngineTotalDurationUs.fetch_add(durUs, std::memory_order_relaxed);

    if (ok) {
        g_digestionEnginePassCount.fetch_add(1, std::memory_order_relaxed);
        g_digestionEngineCurrentFailStreak.store(0, std::memory_order_relaxed);
    } else {
        g_digestionEngineFailCount.fetch_add(1, std::memory_order_relaxed);
        const uint64_t streak = g_digestionEngineCurrentFailStreak.fetch_add(1, std::memory_order_relaxed) + 1;
        updateMaxFailStreak(streak);
    }
}

extern "C" uint64_t RawrXD_DigestionEngineStubHitCount() {
    return g_digestionEngineStubHits.load(std::memory_order_relaxed);
}

extern "C" uint64_t RawrXD_DigestionEngineStubPassCount() {
    return g_digestionEnginePassCount.load(std::memory_order_relaxed);
}

extern "C" uint64_t RawrXD_DigestionEngineStubFailCount() {
    return g_digestionEngineFailCount.load(std::memory_order_relaxed);
}

extern "C" uint64_t RawrXD_DigestionEngineStubStats() {
    // [63:56] max_fail_streak, [55:48] current_fail_streak, [47:40] fail,
    // [39:32] pass, [31:24] retry_runs, [23:16] hits, [15:0] last_duration_us(low16).
    const uint64_t maxStreak = g_digestionEngineMaxFailStreak.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t curStreak = g_digestionEngineCurrentFailStreak.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t fail = g_digestionEngineFailCount.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t pass = g_digestionEnginePassCount.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t retries = g_digestionEngineRetryRuns.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t hits = g_digestionEngineStubHits.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t lastDur = g_digestionEngineLastDurationUs.load(std::memory_order_relaxed) & 0xFFFFu;
    return (maxStreak << 56) | (curStreak << 48) | (fail << 40) | (pass << 32) | (retries << 24) |
           (hits << 16) | lastDur;
}

extern "C" uint64_t RawrXD_DigestionEngineStubTotalDurationUs() {
    return g_digestionEngineTotalDurationUs.load(std::memory_order_relaxed);
}
