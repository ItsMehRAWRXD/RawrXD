// =============================================================================
// test_explorer.cpp CLI — I5/T3: discover and run tests, JSON results.
// usage: test_explorer <workspace-root>
// =============================================================================
#include <cstdio>
#include <string>

#include "test_explorer/test_explorer.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: test_explorer <workspace-root>\n");
        return 2;
    }
    rawrxd::testing::TestExplorer explorer;
    const auto tests = explorer.Discover(argv[1]);
    std::vector<rawrxd::testing::TestResult> results;
    int failed = 0;
    for (const auto& t : tests) {
        auto r = explorer.Run(t);
        if (r.exit_code != 0) ++failed;
        results.push_back(std::move(r));
    }
    std::fputs(rawrxd::testing::TestExplorer::ToJson(results).c_str(), stdout);
    std::fprintf(stderr, "test_explorer: %zu tests, %d failed\n",
                 tests.size(), failed);
    return failed == 0 && !tests.empty() ? 0 : 1;
}