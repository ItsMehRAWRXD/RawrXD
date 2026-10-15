// ============================================================================
// Single entry point for the production-hardening test binary.
//
// Each test translation unit exposes a `run*Suite()` function; this file is the
// only place that defines main(), so adding another hardening suite means
// declaring one extern here rather than fighting over the entry point.
// ============================================================================
#ifndef _CRT_SECURE_NO_WARNINGS
#  define _CRT_SECURE_NO_WARNINGS
#endif

#include <cstdio>

extern "C" int runInputSanitizerSuite();
extern "C" int runCrashResilienceSuite();

int main()
{
    int rc = 0;

    std::printf("\n##################################################################\n");
    std::printf("# Suite 1/2: input validation, sanitization, secure memory\n");
    std::printf("##################################################################\n");
    if (runInputSanitizerSuite() != 0) rc = 1;

    std::printf("\n##################################################################\n");
    std::printf("# Suite 2/2: crash containment, diagnostics, graceful degradation\n");
    std::printf("##################################################################\n");
    if (runCrashResilienceSuite() != 0) rc = 1;

    std::printf("\n##################################################################\n");
    if (rc == 0) std::printf("# RESULT: ALL HARDENING TESTS PASSED\n");
    else          std::printf("# RESULT: HARDENING TESTS FAILED\n");
    std::printf("##################################################################\n");
    return rc;
}
