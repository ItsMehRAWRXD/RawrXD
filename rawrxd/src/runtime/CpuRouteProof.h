// CpuRouteProof.h — RAWRXD_CPU_ROUTE_PROOF_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace cpu {
void recordFeatureSet(bool avx512, bool avx2, bool fma, bool sse42);
void recordKernelRoute(const std::string& kernelName);
void recordScalarFallback();
void writeCpuRouteReceipt(const std::string& path);
}} // namespace rawrxd::cpu