#include <atomic>
#include <cstdint>

namespace
{
std::atomic<uint64_t> g_modeCallCount{0};
std::atomic<uint32_t> g_lastModeHash{0};

inline uint32_t fnv1a32(const char* text)
{
    uint32_t hash = 2166136261u;
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(text); *p != '\0'; ++p)
    {
        hash ^= static_cast<uint32_t>(*p);
        hash *= 16777619u;
    }
    return hash;
}

inline void noteModeCall(const char* modeName)
{
    g_modeCallCount.fetch_add(1, std::memory_order_relaxed);
    g_lastModeHash.store(fnv1a32(modeName), std::memory_order_relaxed);
}
}  // namespace

extern "C" void AgentTraceMode(void)
{
    noteModeCall("AgentTraceMode");
}
extern "C" void GapFuzzMode(void)
{
    noteModeCall("GapFuzzMode");
}
extern "C" void IntelPTMode(void)
{
    noteModeCall("IntelPTMode");
}
extern "C" void DiffCovMode(void)
{
    noteModeCall("DiffCovMode");
}
extern "C" void AD_ProcessGGUF(void)
{
    noteModeCall("AD_ProcessGGUF");
}

// The six SO_* entry points that used to be defined here are NOT repeated.
// src/core/rawrxd_subsystem_api.cpp already defines and uses the real ones:
//
//   api.cpp:111  int    SO_LoadExecFile(const char*)
//   api.cpp:123  bool   SO_InitializeVulkan()
//   api.cpp:128  bool   SO_InitializeStreaming()
//   api.cpp:137  void*  SO_CreateMemoryArena(uint64_t)
//   api.cpp:148  void*  SO_CreateComputePipelines(void*, uint64_t)
//   api.cpp:166  void   SO_PrintStatistics(void)
//
// and calls them from api.cpp:523-590. The copies here had different parameter
// lists, and because they are `extern "C"` the linker compares the bare symbol
// name only, so the two definitions collided as LNK2005 even though the
// signatures differ. Nothing is lost by dropping them: the implemented
// definitions remain, and the mode entry points above are untouched.
