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
    std::string marker = "BRIDGE_GEN_MARKER";
    bool positive = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--marker" && i + 1 < argc) marker = argv[++i];
        else if (a == "--positive") positive = true;
    }

    // Negative (default): exit 0 but NO evidence marker -> must be rejected.
    // Positive: emit the marker on stderr and exit 0 -> must be accepted.
    rawrxd::AcceptanceCriteria criteria;
    criteria.expectedExit = 0;
    criteria.stderrMustContain = marker;   // required evidence marker
    criteria.failOnTimeout = true;

    const std::string cmd = "cmd.exe";
    const std::vector<std::string> args = positive
        ? std::vector<std::string>{"/c", "echo " + marker + " 1>&2"}
        : std::vector<std::string>{"/c", "exit 0"};

    const rawrxd::NativeAcceptanceResult r =
        rawrxd::RunWithAcceptance(cmd, args, ".", 30000, criteria);

    std::printf("MODE=%s\n", positive ? "positive" : "negative");
    std::printf("EXIT=%d\n", r.exitCode);
    std::printf("TIMED_OUT=%s\n", r.timedOut ? "true" : "false");
    std::printf("ACCEPTED=%s\n", r.accepted ? "true" : "false");
    std::printf("FIRST_FAILURE=%s\n", r.firstFailure.c_str());

    // Negative: the gate must REJECT. Positive: the gate must ACCEPT.
    if (positive) {
        if (!r.accepted) {
            std::fprintf(stderr, "FAIL: gate rejected a genuine pass\n");
            return 1;
        }
        std::printf("PASS: gate accepted genuine pass\n");
        return 0;
    }
    if (r.accepted) {
        std::fprintf(stderr, "FAIL: gate accepted a no-evidence success\n");
        return 1;
    }
    std::printf("PASS: gate rejected no-evidence success (firstFailure=%s)\n",
                r.firstFailure.c_str());
    return 0;
}