// W8LifecycleAuthority.cpp — RAWRXD_W8_LIFECYCLE_AUTHORITY_001
#include "W8LifecycleAuthority.h"
#include "../ReceiptAuthority.h"
#include <atomic>
#include <string>
namespace rawrxd { namespace lifecycle {
static std::atomic<uint32_t> g_durationSec{0};
static std::atomic<int> g_shutdownRequests{0};
static std::atomic<bool> g_shutdownAllowed{false};
static std::string g_shutdownReason;
static std::mutex g_reasonMutex;
void beginStayAliveCert(uint32_t durationSec) { g_durationSec.store(durationSec); g_shutdownAllowed.store(false); }
void recordShutdownRequest(const char* reason) {
    g_shutdownRequests.fetch_add(1);
    if (reason) {
        std::lock_guard<std::mutex> lk(g_reasonMutex);
        g_shutdownReason = reason;
    }
}
void allowShutdown() { g_shutdownAllowed.store(true); }
void writeW8Receipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_W8_LIFECYCLE_AUTHORITY_001");
    rawrxd::receipt::writeKeyValueInt(path, "STAY_ALIVE_DURATION_SEC", (int64_t)g_durationSec.load());
    rawrxd::receipt::writeKeyValueInt(path, "SHUTDOWN_REQUESTS", g_shutdownRequests.load());
    rawrxd::receipt::writeKeyValueInt(path, "SHUTDOWN_ALLOWED", g_shutdownAllowed.load() ? 1 : 0);
    rawrxd::receipt::writeKeyValue(path, "SHUTDOWN_REASON", g_shutdownReason);
    rawrxd::receipt::endGate(path, g_shutdownAllowed.load() ? "PASS" : "HOLD");
}
}} // namespace rawrxd::lifecycle