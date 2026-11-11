#include <atomic>

// Deep2Engine_Speculative.cpp keeps this counter external so product and
// benchmark hosts can own their strict-fallback policy independently.
std::atomic<unsigned int> g_strictGpuViolations{0};
