// =============================================================================
// process_runner_test.cpp — deterministic RunProcess exit-code certification.
// =============================================================================
// No MSVC, no model: verifies the production runner propagates child exit
// codes exactly (0,1,2,42) and captures output.
// =============================================================================
#include <cstdio>
#include <string>

#include "process_runner.h"

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    using rawrxd::agentic::RunProcess;
    int failures = 0;
    struct Case { const char* cmd; int expect; };
    const Case cases[] = {
        {"exit /b 0", 0},
        {"exit /b 1", 1},
        {"exit /b 2", 2},
        {"exit /b 42", 42},
        {"echo PASS && exit /b 0", 0},
    };
    for (const auto& c : cases) {
        int code = -1;
        const std::string out = RunProcess(c.cmd, &code);
        const bool ok = code == c.expect;
        std::printf("[%s] '%s' exit=%d expected=%d out=%s\n",
                    ok ? "PASS" : "FAIL", c.cmd, code, c.expect,
                    out.c_str());
        if (!ok) ++failures;
    }
    std::printf("PROCESS_RUNNER_TEST %s (failures=%d)\n",
                failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}