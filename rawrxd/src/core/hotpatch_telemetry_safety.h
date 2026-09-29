#pragma once
// hotpatch_telemetry_safety.h — T3-D Safety Layer for counter-guarded patching
//
// Contract (per unified_hotpatch_manager design):
//   * Every hotpatch mutation must be bracketed by a patch-session guard so
//     counters are consistent even when a patch is rolled back mid-flight.
//   * Telemetry counters are ATOMIC: readers (IDE status, receipts) never
//     block writers (worker threads performing the patch).
//   * A patch that mutates code pages MUST have its counter checkpoint
//     recorded BEFORE the first byte write; on failure the checkpoint is
//     restored, so no "phantom success" is ever observable.
//
// This header is intentionally dependency-light (no engine includes): the
// safety primitives must be usable from any hotpatch layer without pulling
// in Deep2 or IDE headers.

#include <atomic>
#include <cstdint>
#include <string>

namespace rawrxd { namespace hotpatch_telemetry {

// Monotonic patch-transaction id: assigned when a patch session opens.
inline std::atomic<uint64_t>& nextPatchTxn() {
    static std::atomic<uint64_t> v{0};
    return v;
}

// Live counters (atomic so hot path never locks).
struct TelemetryCounters {
    std::atomic<uint64_t> patchSessionsOpened{0};
    std::atomic<uint64_t> patchSessionsCommitted{0};
    std::atomic<uint64_t> patchSessionsRolledBack{0};
    std::atomic<uint64_t> trampolineInstallations{0};
    std::atomic<uint64_t> trampolineRestorations{0};
    std::atomic<uint64_t> codePageSwaps{0};
    std::atomic<uint64_t> integrityChecks{0};
    std::atomic<uint64_t> integrityFailures{0};
};

inline TelemetryCounters& counters() {
    static TelemetryCounters c;
    return c;
}

// RAII session guard: opens a counter-guarded patch session; on destruction
// without commit() the rollback counter is incremented (fail-closed).
class PatchSessionGuard {
public:
    PatchSessionGuard()
        : txn_(nextPatchTxn().fetch_add(1, std::memory_order_relaxed)),
          committed_(false) {
        counters().patchSessionsOpened.fetch_add(1, std::memory_order_relaxed);
    }
    ~PatchSessionGuard() {
        if (!committed_) {
            counters().patchSessionsRolledBack.fetch_add(1, std::memory_order_relaxed);
        }
    }
    PatchSessionGuard(const PatchSessionGuard&) = delete;
    PatchSessionGuard& operator=(const PatchSessionGuard&) = delete;

    void commit() {
        committed_ = true;
        counters().patchSessionsCommitted.fetch_add(1, std::memory_order_relaxed);
    }
    uint64_t txn() const { return txn_; }

private:
    uint64_t txn_;
    bool    committed_;
};

inline void recordTrampolineInstall() {
    counters().trampolineInstallations.fetch_add(1, std::memory_order_relaxed);
}
inline void recordTrampolineRestore() {
    counters().trampolineRestorations.fetch_add(1, std::memory_order_relaxed);
}
inline void recordCodePageSwap() {
    counters().codePageSwaps.fetch_add(1, std::memory_order_relaxed);
}
inline void recordIntegrityCheck(bool ok) {
    counters().integrityChecks.fetch_add(1, std::memory_order_relaxed);
    if (!ok) counters().integrityFailures.fetch_add(1, std::memory_order_relaxed);
}

inline std::string summaryLine() {
    auto& c = counters();
    char buf[256];
    std::snprintf(buf, sizeof(buf),
        "sessions=%llu committed=%llu rolled_back=%llu trampolines=%llu swaps=%llu integrity_ok=%llu integrity_fail=%llu",
        (unsigned long long)c.patchSessionsOpened.load(std::memory_order_relaxed),
        (unsigned long long)c.patchSessionsCommitted.load(std::memory_order_relaxed),
        (unsigned long long)c.patchSessionsRolledBack.load(std::memory_order_relaxed),
        (unsigned long long)c.trampolineInstallations.load(std::memory_order_relaxed),
        (unsigned long long)c.trampolineRestorations.load(std::memory_order_relaxed),
        (unsigned long long)c.codePageSwaps.load(std::memory_order_relaxed),
        (unsigned long long)c.integrityChecks.load(std::memory_order_relaxed),
        (unsigned long long)c.integrityFailures.load(std::memory_order_relaxed));
    return std::string(buf);
}

}} // namespace rawrxd::hotpatch_telemetry
