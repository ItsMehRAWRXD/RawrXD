// ============================================================================
// CommandExecutor.h — RAWRXD_AGENTIC_COMMAND_EXECUTOR_001
// Child process execution with bounded, concurrently drained output capture.
//
// Correctness note: stdout and stderr are drained on their own threads *while*
// the child runs. Draining only after WaitForSingleObject deadlocks as soon as
// the child fills the pipe buffer, which is the common case for any command
// producing more than a few KiB.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd {
namespace agentic {

class CommandExecutor {
public:
    struct Options {
        std::wstring workingDir;
        std::uint32_t timeoutMs = 30000;
        // When false the command string is tokenised and executed directly
        // without cmd.exe, so shell metacharacters are inert.
        bool allowShell = false;
        std::size_t maxCaptureBytes = 1u << 20;  // per stream
        bool inheritEnvironment = true;
    };

    struct Result {
        bool success = false;
        bool timedOut = false;
        std::uint32_t exitCode = 0;
        std::string stdoutText;
        std::string stderrText;
        std::string error;  // spawn/wait failure, distinct from child stderr
        std::size_t stdoutBytesDropped = 0;
        std::size_t stderrBytesDropped = 0;
        std::uint64_t elapsedMicros = 0;
    };

    // Runs `command`. With Options::allowShell false the string is split into
    // an argv vector with Windows quoting rules and CreateProcessW is called
    // directly; no shell is involved.
    static Result Run(const std::string& command, const Options& options);

    // Runs an explicit argv with no shell parsing at all.
    static Result RunArgv(const std::vector<std::wstring>& argv, const Options& options);

    // Splits a command string into argv, honouring double quotes and backslash
    // escaping. Exposed for testing the quoting rules directly.
    static std::vector<std::wstring> SplitCommand(const std::string& command);

    // Quotes a single argument using the CommandLineToArgvW rules.
    static std::wstring QuoteArg(const std::wstring& arg);

    static bool PathExists(const std::string& path);
    static bool IsDirectory(const std::string& path);
    static std::uint64_t FileSizeBytes(const std::string& path);
};

} // namespace agentic
} // namespace rawrxd
