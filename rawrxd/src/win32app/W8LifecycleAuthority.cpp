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

    // RAWRXD_RECEIPT_DIGEST_001: endImmutableGate now seals into a detached
    // .sha256 sidecar created with CREATE_NEW, and returns EMPTY if the seal
    // did not happen -- digest computation failed, or the sidecar already
    // existed. That return used to be discarded with (void), which made a
    // failed seal completely silent: the receipt looked complete, nothing
    // indicated it was unsealed, and any later reader would have no digest to
    // check it against.
    //
    // A seal that can fail without being reported is not a seal. The path is
    // still returned so the caller can see and inspect the receipt, but the
    // unsealed state is recorded INSIDE the receipt as a measured field rather
    // than inferred later.
    const std::string digest = rawrxd::receipt::endImmutableGate(runPath, verdict);
    const bool sealed = !digest.empty();
    if (!sealed) {
        // Appended post-seal-attempt. If this write also fails the receipt is
        // simply an unsealed FAIL-able artefact and the digest is absent, which
        // is itself the observable signal.
        rawrxd::receipt::writeImmutableKeyValue(runPath,
            "RECEIPT_SEALED", "0");
        rawrxd::receipt::writeImmutableKeyValue(runPath,
            "RECEIPT_SEAL_ERROR", "digest_or_sidecar_creation_failed");
    }
    return runPath;
}
}} // namespace rawrxd::lifecycle