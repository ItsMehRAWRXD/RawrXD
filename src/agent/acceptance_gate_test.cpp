// Unit tests for the acceptance gate.
// Build: cl /nologo /std:c++17 /EHsc /W4 /MT acceptance_gate_test.cpp

#include "src/agent/acceptance_gate.hpp"

#include <cstdio>

using namespace rawrxd;

static int g_fail = 0;

static void Expect(const char* name, bool cond)
{
    if (!cond) {
        std::printf("FAIL: %s\n", name);
        ++g_fail;
    }
}

int main()
{
    // 1. A run with the right exit and markers passes.
    {
        ProcessOutcome o;
        o.launched = true; o.exitCode = 0;
        o.stdoutText = "EXIT_HEX=0x00000000";
        o.stderrText = "[BRIDGE_GEN] chars=740";
        AcceptanceCriteria c;
        c.expectedExit = 0;
        c.stdoutMustContain = "EXIT_HEX=0x00000000";
        c.stderrMustContain = "[BRIDGE_GEN]";
        auto r = EvaluateAcceptance(o, c);
        Expect("valid run passes", r.passed);
        Expect("no failure text", r.firstFailure.empty());
    }

    // 2. A successful exit with no generation witness must FAIL.
    {
        ProcessOutcome o;
        o.launched = true; o.exitCode = 0;
        o.stdoutText = "EXIT_HEX=0x00000000";
        o.stderrText = "[BACKEND_SELECTOR_ITEM] 0='Deep2 (Vulkan)'";
        AcceptanceCriteria c;
        c.expectedExit = 0;
        c.stderrMustContain = "[BRIDGE_GEN]";
        auto r = EvaluateAcceptance(o, c);
        Expect("missing marker fails", !r.passed);
        Expect("failure names the marker",
               r.firstFailure.find("missing_stderr_marker=[BRIDGE_GEN]") != std::string::npos);
    }

    // 3. Nonzero exit fails with the actual vs expected code.
    {
        ProcessOutcome o;
        o.launched = true; o.exitCode = 1;
        o.stderrText = "STRATA_NOT_ROUTABLE";
        AcceptanceCriteria c; c.expectedExit = 0;
        auto r = EvaluateAcceptance(o, c);
        Expect("nonzero exit fails", !r.passed);
        Expect("exit mismatch reported",
               r.firstFailure == "exit=1 expected=0");
    }

    // 4. Timeout and launch failure are distinct failures.
    {
        ProcessOutcome o; o.launched = true; o.timedOut = true;
        AcceptanceCriteria c;
        Expect("timeout fails", !EvaluateAcceptance(o, c).passed);

        ProcessOutcome n;  // launched = false
        auto r = EvaluateAcceptance(n, c);
        Expect("not launched fails", !r.passed && r.firstFailure == "not_launched");
    }

    // 5. A nonzero exit with an empty body still fails on exit first.
    {
        ProcessOutcome o; o.launched = true; o.exitCode = 3;
        AcceptanceCriteria c; c.expectedExit = 0; c.minStdoutLen = 10;
        auto r = EvaluateAcceptance(o, c);
        Expect("exit checked before length", r.firstFailure == "exit=3 expected=0");
    }

    if (g_fail == 0) {
        std::printf("ACCEPTANCE_GATE_TESTS=PASS\n");
        return 0;
    }
    std::printf("ACCEPTANCE_GATE_TESTS=FAIL count=%d\n", g_fail);
    return 1;
}