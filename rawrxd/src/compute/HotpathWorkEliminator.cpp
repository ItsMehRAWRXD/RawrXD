// HotpathWorkEliminator.cpp — RAWRXD_HOTPATH_WORK_ELIMINATOR_001
#include "HotpathWorkEliminator.h"
#include "../deep2/ReceiptAuthority.h"
#include <cstdio>
#include <cstring>
#include <atomic>
#include <string>

namespace rawrxd { namespace hotpath {

static std::atomic<long long> g_allocBytes{0};
static std::atomic<long long> g_memcpyBytes{0};
static std::atomic<long long> g_memsetBytes{0};
static std::atomic<long long> g_uploadBytes{0};
static std::atomic<long long> g_flushCount{0};
static std::atomic<long long> g_fullScanCount{0};

void recordAlloc(size_t bytes)   { g_allocBytes.fetch_add((long long)bytes, std::memory_order_acq_rel); }
void recordMemcpy(size_t bytes)  { g_memcpyBytes.fetch_add((long long)bytes, std::memory_order_acq_rel); }
void recordMemset(size_t bytes)  { g_memsetBytes.fetch_add((long long)bytes, std::memory_order_acq_rel); }
void recordUpload(size_t bytes)  { g_uploadBytes.fetch_add((long long)bytes, std::memory_order_acq_rel); }
void recordFlush()               { g_flushCount.fetch_add(1, std::memory_order_acq_rel); }
void recordFullScan(size_t count){ g_fullScanCount.fetch_add((long long)count, std::memory_order_acq_rel); }

void writeHotpathReceipt(const std::string& path) {
    using namespace rawrxd::receipt;
    beginGate(path, "RAWRXD_HOTPATH_WORK_ELIMINATOR_001");
    writeKeyValueInt(path, "ALLOC_BYTES",    g_allocBytes.load(std::memory_order_acquire));
    writeKeyValueInt(path, "MEMCPY_BYTES",   g_memcpyBytes.load(std::memory_order_acquire));
    writeKeyValueInt(path, "MEMSET_BYTES",   g_memsetBytes.load(std::memory_order_acquire));
    writeKeyValueInt(path, "UPLOAD_BYTES",   g_uploadBytes.load(std::memory_order_acquire));
    writeKeyValueInt(path, "FLUSH_COUNT",    g_flushCount.load(std::memory_order_acquire));
    writeKeyValueInt(path, "FULLSCAN_COUNT", g_fullScanCount.load(std::memory_order_acquire));

    long long total =
        g_allocBytes.load(std::memory_order_acquire) +
        g_memcpyBytes.load(std::memory_order_acquire) +
        g_memsetBytes.load(std::memory_order_acquire) +
        g_uploadBytes.load(std::memory_order_acquire) +
        g_flushCount.load(std::memory_order_acquire) +
        g_fullScanCount.load(std::memory_order_acquire);

    const char* verdict = (total == 0) ? "PASS" : "FAIL";
    endGate(path, verdict);
}

}} // namespace rawrxd::hotpath