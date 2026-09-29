// GpuCacheResidencyAuthority.h — RAWRXD_GPU_CACHE_RESIDENCY_001
// Tracks GPU cache residency: weight uploads, cache hits/misses,
// evictions, and pinned weights so that the hot path can prove
// it stays resident without redundant re-upload.
#pragma once
#include <cstddef>
#include <string>

namespace rawrxd { namespace gpu_residency {

void recordUpload(size_t bytes);
void recordCacheHit();
void recordCacheMiss();
void recordEviction();
void pinWeight(const char* name);

void writeResidencyReceipt(const std::string& path);

}} // namespace rawrxd::gpu_residency