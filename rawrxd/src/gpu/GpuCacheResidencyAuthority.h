// GpuCacheResidencyAuthority.h — RAWRXD_GPU_CACHE_RESIDENCY_AUTHORITY_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace gpu {
void recordUpload(uint64_t bytes);
void recordCacheHit();
void recordCacheMiss();
void recordEviction();
void recordPinned(const std::string& tensor, bool pinned);
void writeResidencyReceipt(const std::string& path);
}} // namespace rawrxd::gpu