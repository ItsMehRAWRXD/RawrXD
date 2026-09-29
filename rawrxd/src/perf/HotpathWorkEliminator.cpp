// HotpathWorkEliminator.cpp — RAWRXD_HOTPATH_WORK_ELIMINATOR_001
#include "HotpathWorkEliminator.h"
#include "../deep2/ReceiptAuthority.h"
#include <atomic>
namespace rawrxd { namespace hotpath {
static std::atomic<int> g_allocations{0};
static std::atomic<uint64_t> g_memcpyBytes{0};
static std::atomic<uint64_t> g_uploadBytes{0};
static std::atomic<int> g_flushes{0};
static std::atomic<int> g_fullScans{0};
void recordAllocation() { g_allocations.fetch_add(1); }
void recordMemcpy(uint64_t bytes) { g_memcpyBytes.fetch_add(bytes); }
void recordUpload(uint64_t bytes) { g_uploadBytes.fetch_add(bytes); }
void recordFlush() { g_flushes.fetch_add(1); }
void recordFullScan() { g_fullScans.fetch_add(1); }
void writeHotpathReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_HOTPATH_WORK_ELIMINATOR_001");
    rawrxd::receipt::writeKeyValueInt(path, "ALLOCATIONS", g_allocations.load());
    rawrxd::receipt::writeKeyValueInt(path, "MEMCPY_BYTES", (int64_t)g_memcpyBytes.load());
    rawrxd::receipt::writeKeyValueInt(path, "UPLOAD_BYTES", (int64_t)g_uploadBytes.load());
    rawrxd::receipt::writeKeyValueInt(path, "FLUSHES", g_flushes.load());
    rawrxd::receipt::writeKeyValueInt(path, "FULL_SCANS", g_fullScans.load());
    // Goal: zero hotpath work on the steady-state token path
    bool clean = (g_allocations.load() == 0 && g_memcpyBytes.load() == 0 &&
                  g_uploadBytes.load() == 0 && g_flushes.load() == 0 &&
                  g_fullScans.load() == 0);
    rawrxd::receipt::endGate(path, clean ? "PASS" : "FAIL");
}
}} // namespace rawrxd::hotpath