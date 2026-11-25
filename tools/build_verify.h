// =============================================================================
// build_verify.h — shared build+run+verify core (P0: CREATE/REPAIR/tests).
// =============================================================================
// One authoritative verification implementation with explicit outcomes.
// The runner is injected (RunFn) so the production loop passes its isolated
// job runner and the deterministic test passes a file-based runner - no
// model calls required to certify the verification logic.
// =============================================================================
#pragma once
#include <cstdio>
#include <string>

namespace rawrxd::agentic {

enum class VerifyOutcome {
    Pass,
    BuildFailure,
    OutputMismatch,
    CaptureFailure,
    Timeout,
    Canceled
};

struct BuildRunVerifyResult {
    int buildExit = -1;
    int runExit = -1;
    VerifyOutcome outcome = VerifyOutcome::CaptureFailure;
    std::string buildOut;
    std::string runOut;
    bool verified() const { return outcome == VerifyOutcome::Pass; }
};

// run(cmd, &exit) must execute the command and return its combined output.
template <typename RunFn>
BuildRunVerifyResult VerifyBuildRunWith(RunFn run, const std::string& workdir,
                                        const std::string& buildCmd,
                                        const std::string& runCmd,
                                        const std::string& buildPrefix,
                                        const std::string& expected)
{
    BuildRunVerifyResult r;
    r.buildOut = run("cd /d \"" + workdir + "\" && " + buildPrefix + buildCmd +
                         " 2>&1", &r.buildExit);
    if (r.buildExit != 0) {
        r.outcome = VerifyOutcome::BuildFailure;
        return r;
    }
    r.runOut = run("cd /d \"" + workdir + "\" && " + runCmd + " 2>&1",
                   &r.runExit);
    if (r.runExit == 0 && r.runOut.empty()) {
        // Infrastructure retry: the pipe may have drained before the child
        // flushed. Re-run once; if still empty it is a capture failure.
        r.runOut = run("cd /d \"" + workdir + "\" && " + runCmd + " 2>&1",
                       &r.runExit);
        if (r.runOut.empty()) {
            r.outcome = VerifyOutcome::CaptureFailure;
            return r;
        }
    }
    if (r.runExit != 0) {
        r.outcome = VerifyOutcome::OutputMismatch;
        return r;
    }
    r.outcome = r.runOut.find(expected) != std::string::npos
                    ? VerifyOutcome::Pass
                    : VerifyOutcome::OutputMismatch;
    return r;
}

}  // namespace rawrxd::agentic