#pragma once
/* StickGpuLocal — private DualStick worker counters (merge after join). */
#include <cstdint>

namespace Deep2 {

struct StickGpuLocal {
    uint64_t device_down_vectors = 0;
    uint64_t device_partial_accums = 0;
    uint64_t d2h_partial_vectors = 0;
    uint64_t host_expert_down_vectors = 0;
    uint64_t expert_gpu_exec = 0;
    uint64_t gpu_submits = 0;
    uint64_t gpu_waits = 0;
    uint64_t acquire_hits = 0;
    uint64_t acquire_misses = 0;
    uint64_t h2d_bytes = 0;
    uint64_t d2h_bytes = 0;
    uint64_t gpu0_experts = 0;
    uint64_t gpu1_experts = 0;
    uint64_t bundle_lookups = 0;
    uint64_t bundle_hits = 0;
    uint64_t bundle_misses = 0;
    uint64_t hit_bytes = 0;
    uint64_t compulsory_miss_bytes = 0;
    uint64_t reload_miss_bytes = 0;
    uint64_t seen_bundle_keys = 0;
};

inline void StickGpuMerge(StickGpuLocal& dst, const StickGpuLocal& s) {
    dst.device_down_vectors += s.device_down_vectors;
    dst.device_partial_accums += s.device_partial_accums;
    dst.d2h_partial_vectors += s.d2h_partial_vectors;
    dst.host_expert_down_vectors += s.host_expert_down_vectors;
    dst.expert_gpu_exec += s.expert_gpu_exec;
    dst.gpu_submits += s.gpu_submits;
    dst.gpu_waits += s.gpu_waits;
    dst.acquire_hits += s.acquire_hits;
    dst.acquire_misses += s.acquire_misses;
    dst.h2d_bytes += s.h2d_bytes;
    dst.d2h_bytes += s.d2h_bytes;
    dst.gpu0_experts += s.gpu0_experts;
    dst.gpu1_experts += s.gpu1_experts;
    dst.bundle_lookups += s.bundle_lookups;
    dst.bundle_hits += s.bundle_hits;
    dst.bundle_misses += s.bundle_misses;
    dst.hit_bytes += s.hit_bytes;
    dst.compulsory_miss_bytes += s.compulsory_miss_bytes;
    dst.reload_miss_bytes += s.reload_miss_bytes;
    dst.seen_bundle_keys += s.seen_bundle_keys;
}

void StickGpuCommit(const StickGpuLocal& s);

bool K2MoEStickBeginDevice(unsigned stick, const float* hidden, size_t H,
                           size_t I);
bool K2MoEStickBeginFused(unsigned stick);
bool K2MoEStickPinExpert(unsigned stick, int gt, const uint8_t* g, size_t gb,
                         int ut, const uint8_t* u, size_t ub, int dt,
                         const uint8_t* d, size_t db, size_t H, size_t I,
                         uint32_t layer, int expertId, int acquireMiss,
                         StickGpuLocal& c);
bool K2MoEStickExpertDevice(unsigned stick, int gt, const uint8_t* g, size_t gb,
                            int ut, const uint8_t* u, size_t ub, int dt,
                            const uint8_t* d, size_t db, float weight, size_t H,
                            size_t I, uint32_t layer, int expertId,
                            int acquireMiss, StickGpuLocal& c);
bool K2MoEStickEndFused(unsigned stick, StickGpuLocal& c);
bool K2MoEStickEndDevice(unsigned stick, float* hostPartial, size_t H,
                         StickGpuLocal& c);

} // namespace Deep2
