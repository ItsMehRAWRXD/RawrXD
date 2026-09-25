#pragma once
#include "ExpertCache.h"
#include <cstdlib>
#include <cstring>

namespace rawrxd::deep2 {

inline uint64_t parseU64(const char* s, uint64_t defv) {
    if (!s || !*s) return defv;
    char* end = nullptr;
    unsigned long long v = std::strtoull(s, &end, 10);
    return (end && *end == '\0') ? static_cast<uint64_t>(v) : defv;
}

inline size_t expertStagingBytesFromEnv() {
    const char* mb = std::getenv("DEEP2_EXPERT_STAGING_MB");
    return static_cast<size_t>(parseU64(mb, 64)) * 1024ull * 1024ull;
}

inline ExpertCacheConfig expertCacheConfigFromEnv() {
    ExpertCacheConfig c{};
    const char* mb = std::getenv("DEEP2_EXPERT_CACHE_MB");
    const char* dev = std::getenv("DEEP2_EXPERT_CACHE_DEVICE");
    const char* pol = std::getenv("DEEP2_EXPERT_CACHE_POLICY");
    const char* dep = std::getenv("DEEP2_EXPERT_PREFETCH_DEPTH");

    c.budgetBytes = static_cast<size_t>(parseU64(mb, 0)) * 1024ull * 1024ull;
    c.deviceOrdinal = static_cast<uint32_t>(parseU64(dev, 0));
    c.prefetchDepth = static_cast<uint32_t>(parseU64(dep, 1));
    if (pol && std::strcmp(pol, "LRU") == 0) c.policy = ExpertCachePolicy::Lru;
    else c.policy = ExpertCachePolicy::EmaLfu;
    return c;
}

} // namespace rawrxd::deep2
