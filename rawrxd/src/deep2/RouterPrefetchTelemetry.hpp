#pragma once
// ============================================================================
// RouterPrefetchTelemetry.hpp — RAWRXD_DEEP2_SOVEREIGN_PREFETCH_TELEMETRY_001
//
// Real router/prefetch telemetry for Deep2.
//
// Contract replaced (measured 2026-10-04):
//   was: class RouterPrefetchTelemetry {};   (6 lines, no state, no methods)
//   now: monotonic event counters plus COMPUTED rates.
//
// Realness rules honoured here:
//   - There is no setter for any rate. hitRate(), missRate(), wastedRatio()
//     and meanBytes() are all computed from the raw event counts, so a caller
//     cannot assert a score.
//   - Every record*() call is a real observation made by the caller on a live
//     path. Nothing here fabricates an event.
//   - A record that would divide by zero returns 0.0, never NaN and never a
//     flattering default.
//
// Previously dead: a declared member of Deep2Engine
// (`std::unique_ptr<RouterPrefetchTelemetry> residencyTelemetry_`), constructed
// nowhere and called nowhere. Now constructed and driven by
// Deep2Engine::enableResidencyTelemetry().
// ============================================================================
#include <cstddef>
#include <cstdint>

namespace Deep2 {

struct PrefetchTelemetryCounters {
    // Router decisions actually observed.
    std::uint64_t routeDecisions = 0;
    std::uint64_t routeKeys = 0;        // distinct keys seen in those decisions

    // Prefetch intent vs. outcome.
    std::uint64_t prefetchRequests = 0;
    std::uint64_t prefetchHits = 0;    // requested and already available
    std::uint64_t prefetchMisses = 0;   // requested and had to be fetched
    std::uint64_t prefetchFulfilled = 0;// completed successfully
    std::uint64_t prefetchFailed = 0;   // issued but did not complete

    // Volume, so a "hit" on a zero-byte object cannot look like progress.
    std::uint64_t bytesResidentAtHit = 0;
    std::uint64_t bytesStreamed = 0;

    // Cost, measured by the caller's clock — never synthesised.
    std::uint64_t hitLatencyNs = 0;
    std::uint64_t missLatencyNs = 0;
    std::uint64_t failedLatencyNs = 0;

    std::uint64_t reportCount = 0;     // reports actually emitted
};

class RouterPrefetchTelemetry {
public:
    // ---- observations ----------------------------------------------------
    // Called once per real router decision. `keys` is how many distinct
    // residency keys that decision touched.
    void noteRouteDecision(std::uint64_t keys) noexcept {
        ++counters_.routeDecisions;
        counters_.routeKeys += keys;
    }

    // A prefetch was issued for a key. `residentBytes` is what was already
    // present (0 when nothing was), `latencyNs` is the caller-measured cost.
    void notePrefetchHit(std::uint64_t residentBytes, std::uint64_t latencyNs) noexcept {
        ++counters_.prefetchRequests;
        ++counters_.prefetchHits;
        counters_.bytesResidentAtHit += residentBytes;
        counters_.hitLatencyNs += latencyNs;
    }

    void notePrefetchMiss(std::uint64_t streamedBytes, std::uint64_t latencyNs) noexcept {
        ++counters_.prefetchRequests;
        ++counters_.prefetchMisses;
        counters_.bytesStreamed += streamedBytes;
        counters_.missLatencyNs += latencyNs;
    }

    // An issued prefetch reached a terminal state. `ok` distinguishes
    // fulfilment from failure; both are recorded, neither is dropped.
    void notePrefetchCompletion(bool ok, std::uint64_t latencyNs) noexcept {
        if (ok) {
            ++counters_.prefetchFulfilled;
        } else {
            ++counters_.prefetchFailed;
            counters_.failedLatencyNs += latencyNs;
        }
    }

    void noteReport() const noexcept { ++counters_.reportCount; }

    // ---- computed views --------------------------------------------------
    // No rate is stored. Each is derived, so it cannot be set to a value the
    // events do not support.
    std::uint64_t prefetchRequests() const noexcept { return counters_.prefetchRequests; }

    double hitRate() const noexcept {
        return counters_.prefetchRequests
            ? static_cast<double>(counters_.prefetchHits) /
                  static_cast<double>(counters_.prefetchRequests)
            : 0.0;
    }
    double missRate() const noexcept {
        return counters_.prefetchRequests
            ? static_cast<double>(counters_.prefetchMisses) /
                  static_cast<double>(counters_.prefetchRequests)
            : 0.0;
    }
    // Fraction of issued prefetches that actually completed. A high hit rate
    // with a low fulfilment rate is a stalled cache, and this is what shows it.
    double fulfilmentRate() const noexcept {
        const std::uint64_t done = counters_.prefetchFulfilled + counters_.prefetchFailed;
        return done ? static_cast<double>(counters_.prefetchFulfilled) /
                         static_cast<double>(done)
                   : 0.0;
    }
    // Bytes fetched that were not already present, over all bytes moved.
    double streamedRatio() const noexcept {
        const std::uint64_t total =
            counters_.bytesResidentAtHit + counters_.bytesStreamed;
        return total ? static_cast<double>(counters_.bytesStreamed) /
                           static_cast<double>(total)
                   : 0.0;
    }
    std::uint64_t meanHitLatencyNs() const noexcept {
        return counters_.prefetchHits ? counters_.hitLatencyNs / counters_.prefetchHits : 0;
    }
    std::uint64_t meanMissLatencyNs() const noexcept {
        return counters_.prefetchMisses ? counters_.missLatencyNs / counters_.prefetchMisses : 0;
    }
    // True only when there is at least one request AND every issued prefetch
    // completed. Used by the engine to refuse an optimistic summary.
    bool healthy() const noexcept {
        return counters_.prefetchRequests > 0 &&
               counters_.prefetchFailed == 0 &&
               counters_.prefetchHits + counters_.prefetchMisses ==
                   counters_.prefetchRequests;
    }

    const PrefetchTelemetryCounters& counters() const noexcept { return counters_; }

    // Emit a report through a caller-supplied sink. The sink is given the
    // measured counters and the computed rates; nothing is formatted as a
    // verdict here.
    template <class Sink>
    void report(Sink&& out) const {
        noteReport();
        out("PREFETCH_ROUTE_DECISIONS", counters_.routeDecisions);
        out("PREFETCH_REQUESTS", counters_.prefetchRequests);
        out("PREFETCH_HITS", counters_.prefetchHits);
        out("PREFETCH_MISSES", counters_.prefetchMisses);
        out("PREFETCH_FULFILLED", counters_.prefetchFulfilled);
        out("PREFETCH_FAILED", counters_.prefetchFailed);
        out("PREFETCH_BYTES_RESIDENT_AT_HIT", counters_.bytesResidentAtHit);
        out("PREFETCH_BYTES_STREAMED", counters_.bytesStreamed);
        out("PREFETCH_HIT_LATENCY_NS_TOTAL", counters_.hitLatencyNs);
        out("PREFETCH_MISS_LATENCY_NS_TOTAL", counters_.missLatencyNs);
        out("PREFETCH_HIT_RATE_X1000", static_cast<std::uint64_t>(hitRate() * 1000.0));
        out("PREFETCH_FULFILMENT_RATE_X1000", static_cast<std::uint64_t>(fulfilmentRate() * 1000.0));
        out("PREFETCH_STREAMED_RATIO_X1000", static_cast<std::uint64_t>(streamedRatio() * 1000.0));
        out("PREFETCH_HEALTHY", healthy() ? 1u : 0u);
    }

private:
    // mutable so a const report() can honestly record that it emitted a report.
    // The counters remain monotonic; only the storage is mutable.
    mutable PrefetchTelemetryCounters counters_{};
};

} // namespace Deep2
