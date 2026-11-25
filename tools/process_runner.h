// =============================================================================
// process_runner.h — shared native process execution (P0 consolidation).
// =============================================================================
// ONE authoritative runner for the production agent AND the regression
// harness: Win32 Job Object isolation (KILL_ON_JOB_CLOSE, tree-kill on
// timeout/cancel), cmd.exe /d /c shell semantics, stdout+stderr capture.
// =============================================================================
#pragma once
#include <string>

namespace rawrxd::agentic {

// Execute a command line. Returns combined stdout+stderr; exitCode receives
// the child exit code (-1 on launch failure). The child runs inside a job
// object so a timeout/cancel kills the whole tree.
std::string RunProcess(const std::string& cmd, int* exitCode);

}  // namespace rawrxd::agentic