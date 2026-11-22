// native_acceptance.hpp -- RAWRXD_NATIVE_ACCEPTANCE_001
//
// Qt-free acceptance execution: run a process, then decide whether the *task*
// succeeded rather than merely whether the command ran.
//
// Reuses the existing process runner (native_process.hpp) and the acceptance
// evaluator (acceptance_gate.hpp). No Qt and no duplicated policy, so this
// compiles and runs on any MSVC host without the Qt application build.
//
// This does NOT verify the Qt ActionExecutor or its planCompleted propagation;
// that boundary still requires a Qt-enabled build.

#pragma once

#include "acceptance_gate.hpp"
#include "native_process.hpp"

#include <string>
#include <vector>

namespace rawrxd {

struct NativeAcceptanceResult {
    bool accepted = false;
    int exitCode = -1;
    bool timedOut = false;
    std::string firstFailure;
    std::string stdoutText;
    std::string stderrText;
};

inline NativeAcceptanceResult RunWithAcceptance(
    const std::string& command,
    const std::vector<std::string>& args,
    const std::string& workingDir,
    int timeoutMs,
    const AcceptanceCriteria& criteria)
{
    const NativeProcessResult proc =
        NativeProcess::execute(command, args, workingDir, timeoutMs);

    ProcessOutcome outcome;
    // A launched process always has a real exit code; -1 means it never started.
    // NativeProcess stores a "NONZERO_EXIT_CODE:N" annotation in error for a
    // nonzero exit; that is a real exit, not a launch failure, so surface the
    // exit code itself and only keep genuine launch/timeout errors.
    outcome.launched   = (proc.exitCode != -1);
    outcome.exitCode   = proc.exitCode;
    outcome.timedOut   = proc.timedOut;
    outcome.error.clear();
    if (proc.exitCode == -1)
        outcome.error = proc.error;              // genuine launch/pipe failure
    else if (proc.timedOut)
        outcome.error = "COMMAND_TIMEOUT";       // timeout stays distinguishable
    outcome.stdoutText = proc.stdoutOutput;
    outcome.stderrText = proc.stderrOutput;

    const AcceptanceResult gate = EvaluateAcceptance(outcome, criteria);

    NativeAcceptanceResult r;
    r.accepted     = gate.passed;
    r.exitCode     = proc.exitCode;
    r.timedOut     = proc.timedOut;
    r.firstFailure = gate.firstFailure;
    r.stdoutText   = proc.stdoutOutput;
    r.stderrText   = proc.stderrOutput;
    return r;
}

}  // namespace rawrxd