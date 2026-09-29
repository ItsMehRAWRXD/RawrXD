// GpuCacheResidencyAuthority.cpp — RAWRXD_GPU_CACHE_RESIDENCY_001
#include "GpuCacheResidencyAuthority.h"
#include "../deep2/ReceiptAuthority.h"
#include <cstdio>
#include <cstring>
#include <atomic>
#include <string>
#include <vector>
#include <mutex>

namespace rawrxd { namespace gpu_residency {

static std::atomic<long long> g_uploadBytes{0};
static std::atomic<long long> g_cacheHits{0};
static std::atomic<long long> g_cacheMisses{0};
static std::atomic<long long> g_evictions{0};
static std::mutex g_pinMutex;
static std::vector<std::string> g_pinnedWeights;

void recordUpload(size_t bytes) { g_uploadBytes.fetch_add((long long)bytes, std::memory_order_acq_rel); }
void recordCacheHit()           { g_cacheHits.fetch_add(1, std::memory_order_acq_rel); }
void recordCacheMiss()          { g_cacheMisses.fetch_add(1, std::memory_order_acq_rel); }
void recordEviction()           { g_evictions.fetch_add(1, std::memory_order_acq_rel); }

void pinWeight(const char* name) {
    std::lock_guard<std::mutex> lock(g_pinMutex);
    std::string n = name ? name : "";
    for (const auto& w : g_pinnedWeights)
        if (w == n) return;
    g_pinnedWeights.push_back(n);
}

void writeResidencyReceipt(const std::string& path) {
    using namespace rawrxd::receipt;
    beginGate(path, "RAWRXD_GPU_CACHE_RESIDENCY_001");
    writeKeyValueInt(path, "UPLOAD_BYTES", g_uploadBytes.load(std::memory_order_acquire));
    writeKeyValueInt(path, "CACHE_HITS",   g_cacheHits.load(std::memory_order_acquire));
    writeKeyValueInt(path, "CACHE_MISSES", g_cacheMisses.load(std::memory_order_acquire));
    writeKeyValueInt(path, "EVICTIONS",    g_evictions.load(std::memory_order_acquire));

    std::lock_guard<std::mutex> lock(g_pinMutex);
    writeKeyValueInt(path, "PINNED_COUNT", (int64_t)g_pinnedWeights.size());
    for (size_t i = 0; i < g_pinnedWeights.size(); ++i) {
        char key[64];
        std::snprintf(key, sizeof(key), "PINNED[%zu]", i);
        writeKeyValue(path, key, g_pinnedWeights[i]);
    }

    long long misses = g_cacheMisses.load(std::memory_order_acquire);
    long long evicts = g_evictions.load(std::memory_order_acquire);
    const char* verdict = (misses == 0 && evicts == 0) ? "PASS" : "FAIL";
    endGate(path, verdict);
}

}} // namespace rawrxd::gpu_residency