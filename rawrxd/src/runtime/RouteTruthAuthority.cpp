// RouteTruthAuthority.cpp — RAWRXD_ROUTE_TRUTH_AUTHORITY_001
#include "RouteTruthAuthority.h"
#include "ReceiptAuthority.h"
#include <atomic>
#include <string>

namespace rawrxd { namespace route {

static std::string g_requested = "auto";
static std::string g_actual = "unknown";
static std::atomic<int> g_fallbackCount{0};
static std::atomic<int> g_unplannedFallback{0};

void recordRequested(const std::string& route) { g_requested = route; }
void recordActual(const std::string& route) { g_actual = route; }
void recordFallback(const std::string& from, const std::string& to) {
    g_fallbackCount.fetch_add(1);
    if (from.find("vulkan") != std::string::npos && to.find("cpu") != std::string::npos)
        g_unplannedFallback.fetch_add(1);
}
int getFallbackCount() { return g_fallbackCount.load(); }
int getUnplannedFallbackCount() { return g_unplannedFallback.load(); }

void writeRouteTruthReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_ROUTE_TRUTH_AUTHORITY_001");
    rawrxd::receipt::writeKeyValue(path, "REQUESTED_ROUTE", g_requested);
    rawrxd::receipt::writeKeyValue(path, "ACTUAL_ROUTE", g_actual);
    rawrxd::receipt::writeKeyValueInt(path, "FALLBACK_COUNT", g_fallbackCount.load());
    rawrxd::receipt::writeKeyValueInt(path, "UNPLANNED_FALLBACK_COUNT", g_unplannedFallback.load());
    rawrxd::receipt::endGate(path, g_unplannedFallback.load() == 0 ? "PASS" : "FAIL");
}

}} // namespace rawrxd::route