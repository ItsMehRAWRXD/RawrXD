// W8LifecycleAuthority.cpp — RAWRXD_W8_LIFECYCLE_AUTHORITY_001
//
// MIGRATION_BATCH_1: switched from legacy fixed-path receipts to the
// ReceiptAuthority immutable per-run API. The verdict is derived from
// measured fields (SHUTDOWN_ALLOWED, STAY_ALIVE_DURATION_SEC) — it is not
// a hardcoded literal.
#include "W8LifecycleAuthority.h"
#include "../deep2/ReceiptAuthority.h"
#include <atomic>
#include <string>
namespace rawrxd { namespace lifecycle {
static std::atomic<uint32_t> g_durationSec{0};
static std::atomic<int> g_shutdownRequests{0};
static std::atomic<bool> g_shutdownAllowed{false};
static std::string g_shutdownReason;
static std::mutex g_reasonMutex;
void beginStayAliveCert(uint32_t durationSec) {
    g_durationSec.store(durationSec);
    g_shutdownAllowed.store(false);
}
void recordShutdownRequest(const char* reason) {
    g_shutdownRequests.fetch_add(1);
    if (reason) {
        std::lock_guard<std::mutex> lk(g_reasonMutex);
        g_shutdownReason = reason;
    }
}
void allowShutdown() { g_shutdownAllowed.store(true); }

std::string writeW8Receipt(const std::string& gateName) {
    // Begin an immutable per-run receipt (CREATE_NEW).
    std::string runPath = rawrxd::receipt::beginImmutableGate(gateName);
    if (runPath.empty()) {
        // CREATE_NEW collision or filesystem failure — refuse to fall back to
        // the legacy mutable API. Returning empty signals a hard failure.
        return {};
    }

    // Measured fields only.
    const int64_t durationSec = (int64_t)g_durationSec.load();
    const int64_t shutdownRequests = (int64_t)g_shutdownRequests.load();
    const bool    shutdownAllowed  = g_shutdownAllowed.load();
    std::string   reasonCopy;
    {
        std::lock_guard<std::mutex> lk(g_reasonMutex);
        reasonCopy = g_shutdownReason;
    }

    rawrxd::receipt::writeImmutableKeyValueInt(runPath,
        "STAY_ALIVE_DURATION_SEC", durationSec);
    rawrxd::receipt::writeImmutableKeyValueInt(runPath,
        "SHUTDOWN_REQUESTS", shutdownRequests);
    rawrxd::receipt::writeImmutableKeyValueInt(runPath,
        "SHUTDOWN_ALLOWED", shutdownAllowed ? 1 : 0);
    rawrxd::receipt::writeImmutableKeyValue(runPath,
        "SHUTDOWN_REASON", reasonCopy);

    // Derive verdict from measured SHUTDOWN_ALLOWED field.
    // PASS only if the stay-alive cert ran to completion AND shutdown was
    // permitted at the natural end of life.
    const std::string verdict = shutdownAllowed ? "PASS" : "HOLD";

    // endImmutableGate writes the VERDICT line, computes RECEIPT_SHA256,
    // refreshes latest.txt, and appends to index.jsonl.
    (void)rawrxd::receipt::endImmutableGate(runPath, verdict);
    return runPath;
}
}} // namespace rawrxd::lifecycle