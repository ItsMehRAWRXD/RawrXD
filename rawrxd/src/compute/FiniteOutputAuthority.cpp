// FiniteOutputAuthority.cpp — RAWRXD_FINITE_OUTPUT_AUTHORITY_001
#include "FiniteOutputAuthority.h"
#include "../deep2/ReceiptAuthority.h"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <atomic>
#include <string>
#include <vector>
#include <mutex>
#include <cfloat>

namespace rawrxd { namespace finite {

struct FailureEntry {
    std::string stage;
    size_t      firstBadIndex;
    float       badValue;
};

static std::mutex g_failMutex;
static std::vector<FailureEntry> g_failures;
static std::atomic<int> g_totalChecks{0};
static std::atomic<int> g_totalNonFinite{0};

FiniteResult check(const float* data, size_t count) {
    FiniteResult r;
    r.count = count;
    r.finite = 0;
    r.nan = 0;
    r.inf = 0;
    r.minVal =  FLT_MAX;
    r.maxVal = -FLT_MAX;
    if (!data || count == 0) {
        r.allFinite = false;
        return r;
    }
    for (size_t i = 0; i < count; ++i) {
        float v = data[i];
        if (std::isnan(v)) {
            r.nan++;
        } else if (std::isinf(v)) {
            r.inf++;
        } else {
            r.finite++;
            if (v < r.minVal) r.minVal = v;
            if (v > r.maxVal) r.maxVal = v;
        }
    }
    r.allFinite = (r.nan == 0 && r.inf == 0);
    g_totalChecks.fetch_add(1, std::memory_order_acq_rel);
    if (!r.allFinite) g_totalNonFinite.fetch_add(1, std::memory_order_acq_rel);
    if (r.minVal ==  FLT_MAX) r.minVal = 0.0f;
    if (r.maxVal == -FLT_MAX) r.maxVal = 0.0f;
    return r;
}

void recordFailure(const char* stage, size_t firstBadIndex, float badValue) {
    FailureEntry e;
    e.stage         = stage ? stage : "";
    e.firstBadIndex = firstBadIndex;
    e.badValue      = badValue;
    std::lock_guard<std::mutex> lock(g_failMutex);
    g_failures.push_back(e);
}

void writeFiniteReceipt(const std::string& path) {
    using namespace rawrxd::receipt;
    beginGate(path, "RAWRXD_FINITE_OUTPUT_AUTHORITY_001");
    writeKeyValueInt(path, "TOTAL_CHECKS",    g_totalChecks.load(std::memory_order_acquire));
    writeKeyValueInt(path, "TOTAL_NON_FINITE",g_totalNonFinite.load(std::memory_order_acquire));

    std::lock_guard<std::mutex> lock(g_failMutex);
    for (size_t i = 0; i < g_failures.size(); ++i) {
        const FailureEntry& f = g_failures[i];
        char prefix[64];
        std::snprintf(prefix, sizeof(prefix), "FAIL[%zu]", i);
        writeKeyValue(path, std::string(prefix) + "_STAGE", f.stage);
        writeKeyValueInt(path, std::string(prefix) + "_INDEX", (int64_t)f.firstBadIndex);
        writeKeyValueFloat(path, std::string(prefix) + "_VALUE", (double)f.badValue);
    }

    const char* verdict = (g_totalNonFinite.load(std::memory_order_acquire) == 0) ? "PASS" : "FAIL";
    endGate(path, verdict);
}

}} // namespace rawrxd::finite