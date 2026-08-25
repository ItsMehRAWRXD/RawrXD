#pragma once
#include <cstdint>
#include <cstring>

namespace Sovereign {
namespace KVCache {
    inline void Reset() {}
    inline void WarmupSynthetic() {}
    inline void Save(const char* path) {}
    inline void Load(const char* path) {}
    inline void ClearNVMeStaging() {}
    inline void ProcessBatch(size_t count) {}
    inline bool ValidateKVTiering() { return true; }
    inline uint64_t GetHotTokenCount() { return 1; }
    inline uint64_t GetWarmTokenCount() { return 0; }
    inline uint64_t GetColdTokenCount() { return 0; }
    inline uint64_t GetPendingIOCount() { return 0; }
}
}
