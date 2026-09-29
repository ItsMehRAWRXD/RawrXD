// ScalarFallbackAuthority.cpp — RAWRXD_SCALAR_FALLBACK_AUTHORITY_001
#include "ScalarFallbackAuthority.h"
#include "../deep2/ReceiptAuthority.h"
#include <cstdio>
#include <cstring>
#include <atomic>
#include <string>
#include <vector>
#include <mutex>

namespace rawrxd { namespace scalar {

struct FallbackEntry {
    std::string quantType;
    std::string reason;
};

static std::mutex g_fbMutex;
static std::vector<FallbackEntry> g_entries;
static std::atomic<int> g_count{0};

void recordFallback(const char* quantType, const char* reason) {
    FallbackEntry e;
    e.quantType = quantType ? quantType : "";
    e.reason    = reason ? reason : "";
    {
        std::lock_guard<std::mutex> lock(g_fbMutex);
        g_entries.push_back(e);
    }
    g_count.fetch_add(1, std::memory_order_acq_rel);
}

int getFallbackCount() {
    return g_count.load(std::memory_order_acquire);
}

void writeFallbackReceipt(const std::string& path) {
    using namespace rawrxd::receipt;
    beginGate(path, "RAWRXD_SCALAR_FALLBACK_AUTHORITY_001");
    writeKeyValueInt(path, "FALLBACK_COUNT", getFallbackCount());

    std::lock_guard<std::mutex> lock(g_fbMutex);
    for (size_t i = 0; i < g_entries.size(); ++i) {
        const FallbackEntry& e = g_entries[i];
        char prefix[64];
        std::snprintf(prefix, sizeof(prefix), "FB[%zu]", i);
        writeKeyValue(path, std::string(prefix) + "_QUANT", e.quantType);
        writeKeyValue(path, std::string(prefix) + "_REASON", e.reason);
    }

    const char* verdict = (getFallbackCount() == 0) ? "PASS" : "FAIL";
    endGate(path, verdict);
}

}} // namespace rawrxd::scalar