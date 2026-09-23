#include <atomic>
#include <cstdint>

// Strict-build definition for extern symbol referenced by Deep2Engine_Speculative.cpp
std::atomic<uint32_t> g_strictGpuViolations{0};
