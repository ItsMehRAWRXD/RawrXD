// =============================================================================
// process_runner.cpp — shared native process execution (extracted from
// deep2_agentic_loop.cpp RunCmd; the production implementation).
// =============================================================================
#include "process_runner.h"

#include "agentic/tool_security.hpp"

namespace rawrxd::agentic {

std::string RunProcess(const std::string& cmd, int* exitCode) {
    std::string out, err;
    bool timedOut = false;
    int code = -1;
    // cmd.exe /d /c: callers pass shell syntax (cd /d ... && ..., 2>&1)
    // that CreateProcess alone does not interpret. The job object contains
    // the whole tree (P0 isolation preserved).
    const std::string wrapped = "cmd.exe /d /c " + cmd;
    if (!rawrxd::agentic::security::JobIsolation::RunIsolated(
            wrapped, std::string(), 0ULL, out, err, code, timedOut))
    {
        *exitCode = -1;
        return "CreateProcess failed";
    }
    std::string combined = out;
    if (!err.empty())
    {
        if (!combined.empty()) combined += "\n";
        combined += err;
    }
    if (timedOut)
    {
        combined += "\n[host] command timed out; job tree terminated";
        code = -1;
    }
    *exitCode = code;
    return combined;
}

}  // namespace rawrxd::agentic