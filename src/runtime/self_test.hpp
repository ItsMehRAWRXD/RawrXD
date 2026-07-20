/*===========================================================================
 * self_test.hpp
 *
 * Runtime Self-Test Framework (Gate C)
 *
 * Validates all runtime components on startup:
 *   - GGUF parser
 *   - Tensor registry
 *   - Q4 kernel
 *   - Flash attention
 *   - KV cache alignment
 *   - IOCP spill manager
 *   - Telemetry
 *
 * Usage:
 *   RawrXD_Engine.exe --self-test
 *===========================================================================*/

#pragma once

#include <string>
#include <vector>
#include <functional>

namespace RawrXD {
namespace Runtime {

// Test result
struct TestResult {
    std::string name;
    bool passed;
    std::string message;
    double durationMs;

    TestResult(const std::string& n, bool p, const std::string& m, double d = 0.0)
        : name(n), passed(p), message(m), durationMs(d) {}
};

// Self-test suite
class SelfTestSuite {
public:
    SelfTestSuite();
    ~SelfTestSuite();

    // Run all tests
    std::vector<TestResult> RunAllTests();

    // Run specific test category
    std::vector<TestResult> RunParserTests();
    std::vector<TestResult> RunKernelTests();
    std::vector<TestResult> RunMemoryTests();
    std::vector<TestResult> RunIOTests();

    // Print formatted results
    static void PrintResults(const std::vector<TestResult>& results);

    // Get summary
    static bool AllPassed(const std::vector<TestResult>& results);
    static size_t CountPassed(const std::vector<TestResult>& results);
    static size_t CountFailed(const std::vector<TestResult>& results);

private:
    // Individual tests
    TestResult TestGGUFParser();
    TestResult TestTensorRegistry();
    TestResult TestQ4Kernel();
    TestResult TestFlashAttention();
    TestResult TestKVCacheAlignment();
    TestResult TestIOCPSpillManager();
    TestResult TestTelemetry();
    TestResult TestPathResolution();
    TestResult TestAVX512Detection();
    TestResult TestMemoryAllocation();

    // Test utilities
    bool CheckAVX512Support();
    bool Check64ByteAlignment();
    bool CheckKernelBinaries();
};

// C API exports
extern "C" {
    __declspec(dllexport) int RawrXD_RunSelfTest();
    __declspec(dllexport) int RawrXD_RunSelfTestCategory(const char* category);
}

} // namespace Runtime
} // namespace RawrXD
