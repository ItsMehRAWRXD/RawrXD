// agent_acceptance_smoke.cpp — RAWRXD_AGENT_ACCEPTANCE_001 (Qt-free)
//
// Headless acceptance harness for the NATIVE action executor.
//
// Proves that a process which exits 0 but omits its required evidence is
// reported as a FAILED acceptance, not as success. Uses the native
// RunWithAcceptance() path (NativeProcess::execute + EvaluateAcceptance) with
// no Qt dependency.
//
// Usage:
//   agent_acceptance_smoke.exe [--marker TEXT]
//
// Exit codes: 0 = gate behaved correctly (rejected the no-evidence success),
//             1 = gate did not reject, 2 = usage/harness error.

#include "agent/native_acceptance.hpp"

#include <cstdio>
#include <string>

int main(int argc, char** argv)
{
    std::string marker = "[BRIDGE_GEN]";
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--marker" && i + 1 < argc) marker = argv[++i];
    }

    // A command that succeeds (exit 0) but produces NO evidence on stderr.
    rawrxd::AcceptanceCriteria criteria;
    criteria.expectedExit = 0;
    criteria.stderrMustContain = marker;   // required evidence marker
    criteria.failOnTimeout = true;

    const rawrxd::NativeAcceptanceResult r =
        rawrxd::RunWithAcceptance("cmd.exe", {"/c", "exit 0"}, ".", 30000, criteria);

    std::printf("EXIT=%d\n", r.exitCode);
    std::printf("TIMED_OUT=%s\n", r.timedOut ? "true" : "false");
    std::printf("ACCEPTED=%s\n", r.accepted ? "true" : "false");
    std::printf("FIRST_FAILURE=%s\n", r.firstFailure.c_str());

    // The gate behaved correctly only if it REJECTED the no-evidence success.
    if (r.accepted) {
        std::fprintf(stderr, "FAIL: gate accepted a no-evidence success\n");
        return 1;
    }
    if (r.firstFailure.empty()) {
        std::fprintf(stderr, "FAIL: rejected without a firstFailure reason\n");
        return 1;
    }
    std::printf("PASS: gate rejected no-evidence success (firstFailure=%s)\n",
                r.firstFailure.c_str());
    return 0;
}