// =============================================================================
// Win32IDE_TestExplorerTree.cpp — I5/T3 IDE bridge (TOP50 I5/T3).
// =============================================================================
// runTestExplorer (command 12070): discovers tests in the workspace, runs each
// in an isolated job, prints a summary to Output, and pushes failures into the
// unified Problems panel (source "Test").
// =============================================================================
#include "Win32IDE.h"

#include <cstdio>
#include <string>

#include "core/problems_aggregator.hpp"
#include "test_explorer/test_explorer.h"

void Win32IDE::runTestExplorer() {
    const std::string root = m_gitRepoPath.empty() ? std::string(".")
                                                   : m_gitRepoPath;
    rawrxd::testing::TestExplorer explorer;
    const auto tests = explorer.Discover(root);
    if (tests.empty()) {
        appendToOutput("[Test] No tests discovered under " + root + "\n",
                       "Test", OutputSeverity::Warning);
        return;
    }
    appendToOutput("[Test] Discovered " + std::to_string(tests.size()) +
                   " test(s); running...\n", "Test", OutputSeverity::Info);
    auto& agg = RawrXD::ProblemsAggregator::instance();
    agg.clear("Test");
    int failed = 0;
    for (const auto& t : tests) {
        const auto r = explorer.Run(t);
        if (r.exit_code == 0) {
            appendToOutput("[Test] PASS " + t.name + "\n", "Test",
                           OutputSeverity::Info);
        } else {
            ++failed;
            appendToOutput("[Test] FAIL " + t.name + " (exit " +
                           std::to_string(r.exit_code) +
                           (r.timed_out ? ", timeout" : "") + ")\n",
                           "Test", OutputSeverity::Error);
            agg.add("Test", t.file, 0, 0, 1, "TESTFAIL",
                    t.name + " failed (exit " + std::to_string(r.exit_code) +
                        ")",
                    "test");
        }
    }
    refreshProblemsView();
    appendToOutput("[Test] Done: " + std::to_string(tests.size() - failed) +
                   " passed, " + std::to_string(failed) + " failed\n",
                   "Test", failed == 0 ? OutputSeverity::Info
                                       : OutputSeverity::Warning);
}