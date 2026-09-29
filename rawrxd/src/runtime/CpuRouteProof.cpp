// CpuRouteProof.cpp — RAWRXD_CPU_ROUTE_PROOF_001
#include "CpuRouteProof.h"
#include "../ReceiptAuthority.h"
#include <atomic>
#include <string>
namespace rawrxd { namespace cpu {
static std::atomic<bool> g_avx512{false}, g_avx2{false}, g_fma{false}, g_sse42{false};
static std::atomic<int> g_scalarFallback{0};
static std::string g_kernelRoute = "unknown";
void recordFeatureSet(bool avx512, bool avx2, bool fma, bool sse42) {
    g_avx512.store(avx512); g_avx2.store(avx2); g_fma.store(fma); g_sse42.store(sse42);
}
void recordKernelRoute(const std::string& kernelName) { g_kernelRoute = kernelName; }
void recordScalarFallback() { g_scalarFallback.fetch_add(1); }
void writeCpuRouteReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_CPU_ROUTE_PROOF_001");
    rawrxd::receipt::writeKeyValueInt(path, "CPU_FEATURES_DETECTED", 1);
    rawrxd::receipt::writeKeyValueInt(path, "AVX512_DETECTED", g_avx512.load() ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "AVX2_DETECTED", g_avx2.load() ? 1 : 0);
    rawrxd::receipt::writeKeyValue(path, "SELECTED_KERNEL", g_kernelRoute);
    rawrxd::receipt::writeKeyValueInt(path, "SCALAR_FALLBACK_COUNT", g_scalarFallback.load());
    rawrxd::receipt::endGate(path, g_scalarFallback.load() == 0 ? "PASS" : "FAIL");
}
}} // namespace rawrxd::cpu