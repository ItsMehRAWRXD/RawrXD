// =============================================================================
// coverage_report.cpp CLI — T2: report per-file coverage from lcov/llvm-cov.
// usage: coverage_report <coverage.info|llvm.json>
// =============================================================================
#include <cstdio>
#include <string>

#include "testing/coverage_report.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
                     "usage: coverage_report <coverage.info|llvm-cov.json>\n");
        return 2;
    }
    rawrxd::testing::CoverageReport report;
    bool ok = report.LoadLcov(argv[1]);
    if (!ok || report.Files().empty()) {
        ok = report.LoadLlvmJson(argv[1]);
    }
    if (!ok) {
        std::fprintf(stderr, "coverage_report: cannot parse %s\n", argv[1]);
        return 2;
    }
    std::fputs(rawrxd::testing::CoverageReport::ToJson(report.Files()).c_str(),
               stdout);
    std::fprintf(stderr, "coverage: %zu files, overall %.1f%%\n",
                 report.Files().size(), report.OverallPercent());
    return 0;
}