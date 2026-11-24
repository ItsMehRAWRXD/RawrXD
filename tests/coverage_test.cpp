// =============================================================================
// coverage_test.cpp — T2 certification: lcov parsing + percentages.
// =============================================================================
#include <cstdio>
#include <string>

#include "testing/coverage_report.h"

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1] : "tests/fixtures/coverage.info";
    rawrxd::testing::CoverageReport report;
    int failures = 0;
    if (!report.LoadLcov(path) || report.Files().size() != 2) {
        std::printf("[FAIL] lcov parse (files=%zu)\n", report.Files().size());
        ++failures;
    }
    if (report.Files().size() == 2) {
        const auto& a = report.Files()[0];
        if (a.lines_found != 5 || a.lines_hit != 3) {
            std::printf("[FAIL] file0 counts %d/%d\n", a.lines_hit,
                        a.lines_found);
            ++failures;
        }
    }
    const double overall = report.OverallPercent();
    if (overall < 59.9 || overall > 60.1) {
        std::printf("[FAIL] overall %.1f expected 60.0\n", overall);
        ++failures;
    }
    // llvm-cov JSON path.
    rawrxd::testing::CoverageReport j;
    if (!j.LoadLlvmJson("tests/fixtures/coverage_llvm.json") ||
        j.Files().size() != 1) {
        std::printf("[FAIL] llvm-cov parse\n");
        ++failures;
    }
    std::printf("coverage_test: failures=%d\n", failures);
    std::printf("COVERAGE_TEST %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}