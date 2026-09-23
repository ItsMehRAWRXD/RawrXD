// strict_gpu_violations.cpp — provides definition for g_strictGpuViolations referenced by Deep2Engine_Speculative.cpp
#include <atomic>
#include <cstdint>

std::atomic<uint32_t> g_strictGpuViolations{0};
