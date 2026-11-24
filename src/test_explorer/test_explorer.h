// =============================================================================
// test_explorer.h — I5/T3 test discovery + execution (TOP50 I5/T3).
// =============================================================================
// Discovers tests (CMake add_test, ctest, pytest, *.cmd/*.ps1 test scripts)
// and runs them in isolated job objects (no orphaned children). Exit code is
// the verdict; output is captured for the UI.
// =============================================================================
#pragma once
#include <string>
#include <vector>

namespace rawrxd::testing {

struct TestCase {
    std::string name;
    std::string file;       // source file or script
    std::string command;    // full command line to run
    std::string kind;       // "ctest" | "pytest" | "script"
};

struct TestResult {
    std::string name;
    int exit_code = -1;
    bool timed_out = false;
    std::string output;
};

class TestExplorer {
public:
    // Discover tests under a workspace root (bounded).
    std::vector<TestCase> Discover(const std::string& root,
                                   int max_tests = 2000) const;

    // Run one test with a timeout (ms). Uses the isolated job runner.
    TestResult Run(const TestCase& test, unsigned long long timeout_ms = 120000) const;

    static std::string ToJson(const std::vector<TestResult>& results);
};

}  // namespace rawrxd::testing