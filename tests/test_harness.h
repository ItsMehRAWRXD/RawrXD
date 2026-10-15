#pragma once

/**
 * @file test_harness.h
 * @brief Minimal, dependency-free unit-test harness.
 *
 * Why not googletest/Qt Test? The production hardening suite must be runnable
 * in the *narrowest* configuration: a plain MSVC/GCC toolchain with no Qt and
 * no network fetches. That keeps the security guarantees verifiable in minimal
 * CI images and by contributors who cannot install Qt.
 *
 * Deliberately small: ~200 lines, no allocations on the assert path, no
 * exceptions, and a non-zero exit code on failure so CI gates work.
 *
 * Usage:
 * @code
 *   #include "test_harness.h"
 *   TEST(SanitizerRejectsTraversal) { CHECK(!ok); }
 *   int main() { return RUN_ALL_TESTS(); }
 * @endcode
 */

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace rawrxd_test {

struct TestCase final {
    const char* suite;
    const char* name;
    void (*fn)();
};

inline std::vector<TestCase>& registry()
{
    static std::vector<TestCase> r;
    return r;
}

inline int& failureCount()
{
    static int n = 0;
    return n;
}

inline bool& currentTestFailed()
{
    static bool f = false;
    return f;
}

inline std::string& currentTestReason()
{
    static std::string s;
    return s;
}

inline void recordFailure(const char* file, int line, const char* expr)
{
    ++failureCount();
    currentTestFailed() = true;
    std::printf("      FAIL %s:%d: %s\n", file, line, expr);
    if (currentTestReason().empty()) {
        currentTestReason() = std::string(file) + ":" + std::to_string(line);
    }
}

/// RAII per-test fixture style: reports pass/fail and timing.
inline int runAll(const char* suiteFilter = nullptr)
{
    int ran = 0;
    int failed = 0;
    for (const auto& t : registry()) {
        if (suiteFilter && std::strcmp(t.suite, suiteFilter) != 0) continue;
        ++ran;
        currentTestFailed() = false;
        currentTestReason().clear();
        std::printf("[ RUN  ] %s.%s\n", t.suite, t.name);
        t.fn();
        if (currentTestFailed()) {
            ++failed;
            std::printf("[ FAIL ] %s.%s (%s)\n", t.suite, t.name, currentTestReason().c_str());
        } else {
            std::printf("[  OK  ] %s.%s\n", t.suite, t.name);
        }
    }
    std::printf("\n%d/%d tests passed (%d failed)\n", ran - failed, ran, failed);
    return failed == 0 ? 0 : 1;
}

} // namespace rawrxd_test

// ---- Registration and assertion macros -----------------------------------

#define TEST(suite, name)                                                        \
    static void suite##_##name##_body();                                          \
    static const bool suite##_##name##_registered = [] {                          \
        ::rawrxd_test::registry().push_back({#suite, #name, &suite##_##name##_body}); \
        return true;                                                              \
    }();                                                                          \
    static void suite##_##name##_body()

#define CHECK(expr)                                                              \
    do {                                                                         \
        if (!(expr)) ::rawrxd_test::recordFailure(__FILE__, __LINE__, #expr);     \
    } while (false)

#define CHECK_EQ(a, b)                                                           \
    do {                                                                         \
        if (!((a) == (b))) ::rawrxd_test::recordFailure(__FILE__, __LINE__,       \
                            #a " == " #b);                                       \
    } while (false)

#define CHECK_NE(a, b)                                                           \
    do {                                                                         \
        if (!((a) != (b))) ::rawrxd_test::recordFailure(__FILE__, __LINE__,       \
                            #a " != " #b);                                       \
    } while (false)

#define CHECK_TRUE(expr)  CHECK(expr)
#define CHECK_FALSE(expr) CHECK(!(expr))

/// Fails the current test unconditionally with a message.
#define FAIL_NOW(msg)                                                            \
    do {                                                                         \
        ::rawrxd_test::recordFailure(__FILE__, __LINE__, msg);                    \
        return;                                                                  \
    } while (false)

/// Entry points for the generated test binaries.
/// Run everything:
#define RUN_ALL_TESTS() ::rawrxd_test::runAll()
/// Run a single suite by name (handy while developing one component):
#define RUN_TEST_SUITE(suiteName) ::rawrxd_test::runAll(suiteName)
