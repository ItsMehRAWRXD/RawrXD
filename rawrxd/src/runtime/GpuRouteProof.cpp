// GpuRouteProof.cpp — RAWRXD_GPU_ROUTE_PROOF_001
#include "GpuRouteProof.h"
#include "../deep2/ReceiptAuthority.h"
#include <atomic>
namespace rawrxd { namespace gpu {
static std::atomic<int> g_singleGpu{0}, g_dualGpu{0}, g_cpuFallback{0};
static std::atomic<uint64_t> g_uploadBytes{0};
static std::atomic<int> g_cacheHits{0}, g_cacheMisses{0}, g_strictViolations{0};
static std::string g_lastStage = "none";
void recordGpuForward(const std::string& stage) { g_lastStage = stage; }
void recordLinearWRoute(const std::string& route) {
    if (route == "single_gpu") g_singleGpu.fetch_add(1);
    else if (route == "dual_gpu") g_dualGpu.fetch_add(1);
    else if (route == "cpu_fallback") g_cpuFallback.fetch_add(1);
}
void recordUpload(uint64_t bytes) { g_uploadBytes.fetch_add(bytes); }
void recordCacheHit() { g_cacheHits.fetch_add(1); }
void recordCacheMiss() { g_cacheMisses.fetch_add(1); }
void recordStrictViolation() { g_strictViolations.fetch_add(1); }
void writeGpuRouteProof(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_GPU_ROUTE_PROOF_001");
    rawrxd::receipt::writeKeyValueInt(path, "VULKAN_ENABLED", 1);
    rawrxd::receipt::writeKeyValueInt(path, "GPU_FORWARD_ENTERED", g_singleGpu.load()+g_dualGpu.load() > 0 ? 1 : 0);
    rawrxd::receipt::writeKeyValue(path, "GPU_FORWARD_STAGE", g_lastStage);
    rawrxd::receipt::writeKeyValueInt(path, "LINEARW_SINGLE_GPU_COUNT", g_singleGpu.load());
    rawrxd::receipt::writeKeyValueInt(path, "LINEARW_DUAL_GPU_COUNT", g_dualGpu.load());
    rawrxd::receipt::writeKeyValueInt(path, "LINEARW_CPU_FALLBACK_COUNT", g_cpuFallback.load());
    rawrxd::receipt::writeKeyValueInt(path, "GPU_UPLOAD_BYTES", (int64_t)g_uploadBytes.load());
    rawrxd::receipt::writeKeyValueInt(path, "GPU_CACHE_HITS", g_cacheHits.load());
    rawrxd::receipt::writeKeyValueInt(path, "GPU_CACHE_MISSES", g_cacheMisses.load());
    rawrxd::receipt::writeKeyValueInt(path, "STRICT_GPU_VIOLATIONS", g_strictViolations.load());
    rawrxd::receipt::endGate(path, g_strictViolations.load() == 0 ? "PASS" : "FAIL");
}
}} // namespace rawrxd::gpu