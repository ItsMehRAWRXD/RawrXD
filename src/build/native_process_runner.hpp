#pragma once
#ifdef _WIN32
#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD::Build {
struct ProcessResult {
    unsigned long exit_code = 0;
    bool launched = false;
    bool timed_out = false;
    std::string stdout_text;
    std::string stderr_text;
    std::string error;
};

// No shell: argv[0] is the executable, remaining elements are literal arguments.
// Both streams are drained concurrently. A job object terminates child processes
// when the deadline expires. No model, Ollama, or network service required.
ProcessResult RunProcess(const std::vector<std::wstring>& argv,
                         const std::wstring& working_directory,
                         std::uint32_t timeout_ms);
}
#endif
