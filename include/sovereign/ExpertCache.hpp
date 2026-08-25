#pragma once
#include <cstdint>

namespace Sovereign {
namespace ExpertCache {
    inline void Reset() {}
    inline void WarmupRouting() {}
    inline void Save(const char* path) {}
    inline void Load(const char* path) {}
    inline void ResetRouter() {}
    inline void RouteBatch(size_t count) {}
    inline bool ValidateMoERouting() { return true; }
    inline uint32_t GetActiveExpertCount() { return 1; }
}
}
