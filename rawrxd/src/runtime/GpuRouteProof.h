// GpuRouteProof.h — RAWRXD_GPU_ROUTE_PROOF_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace gpu {
void recordGpuForward(const std::string& stage);
void recordLinearWRoute(const std::string& route); // single_gpu, dual_gpu, cpu_fallback
void recordUpload(uint64_t bytes);
void recordCacheHit();
void recordCacheMiss();
void recordStrictViolation();
void writeGpuRouteProof(const std::string& path);
}} // namespace rawrxd::gpu