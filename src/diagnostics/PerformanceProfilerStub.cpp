// PerformanceProfilerStub.cpp — Compilation verification stub for header-only profiler
#include "PerformanceProfiler.hpp"

// Explicit template instantiation / compilation verification
void VerifyProfilerCompiles() {
    PerformanceProfiler profiler;
    profiler.StartSession();
    // EndSession would print to stdout; we just verify linkage here
}
