// =============================================================================
// Win32IDE_CoverageBridge.cpp — T2 IDE bridge (TOP50 T2).
// =============================================================================
// showCoverageReport (command 12090): parses <workspace>/coverage.info (lcov)
// or coverage_llvm.json, prints overall %, and pushes files below 80% line
// coverage into the unified Problems panel (source "Coverage").
// =============================================================================
#include "Win32IDE.h"

#include <cstdio>
#include <string>

#include "core/problems_aggregator.hpp"
#include "testing/coverage_report.h"

void Win32IDE::showCoverageReport() {
    const std::string root = m_gitRepoPath.empty() ? std::string(".")
                                                   : m_gitRepoPath;
    rawrxd::testing::CoverageReport report;
    bool ok = report.LoadLcov(root + "/coverage.info");
    if (!ok || report.Files().empty()) {
        ok = report.LoadLlvmJson(root + "/coverage_llvm.json");
    }
    if (!ok || report.Files().empty()) {
        appendToOutput("[Coverage] No coverage.info / coverage_llvm.json in " +
                           root + "\n",
                       "Test", OutputSeverity::Warning);
        return;
    }
    auto& agg = RawrXD::ProblemsAggregator::instance();
    agg.clear("Coverage");
    int low = 0;
    for (const auto& f : report.Files()) {
        if (f.percent() < 80.0) {
            ++low;
            char pct[32];
            std::snprintf(pct, sizeof(pct), "%.1f", f.percent());
            agg.add("Coverage", f.file, 0, 0, 2, "COVERAGE",
                    std::string("line coverage ") + pct + "% (threshold 80%)",
                    "coverage");
        }
    }
    refreshProblemsView();
    char summary[128];
    std::snprintf(summary, sizeof(summary),
                  "[Coverage] %zu files, overall %.1f%% (%d below 80%%)\n",
                  report.Files().size(), report.OverallPercent(), low);
    appendToOutput(summary, "Test", OutputSeverity::Info);
}