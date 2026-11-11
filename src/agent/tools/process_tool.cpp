#include "process_tool.hpp"
#include <cstdio>
#include <memory>
#include <array>
#include <chrono>
#include <iostream>

namespace rawrxd {
namespace agent {

ToolResult ProcessTool::execute(const ToolRequest& request) {
    auto start = std::chrono::high_resolution_clock::now();
    ToolResult result;

    if (request.action == "execute" || request.action == "run") {
        result = handleExecute(request.target, request.timeout_ms);
    } else if (request.action == "terminate") {
        result = handleTerminate(request.target);
    } else {
        result.success = false;
        result.error = "Unknown process action: " + request.action;
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    return result;
}

ToolResult ProcessTool::handleExecute(const std::string& command, uint64_t timeout_ms) {
    ToolResult result;

#ifdef _WIN32
    // Use _popen for Windows
    FILE* pipe = _popen(command.c_str(), "r");
#else
    FILE* pipe = popen(command.c_str(), "r");
#endif

    if (!pipe) {
        result.success = false;
        result.error = "Failed to execute command: " + command;
        return result;
    }

    std::string output;
    std::array<char, 4096> buffer;
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        output += buffer.data();
    }

#ifdef _WIN32
    int exit_code = _pclose(pipe);
#else
    int exit_code = pclose(pipe);
#endif

    result.success = (exit_code == 0);
    result.output = output;
    if (exit_code != 0) {
        result.error = "Command exited with code: " + std::to_string(exit_code);
    }

    return result;
}

ToolResult ProcessTool::handleTerminate(const std::string& pid) {
    ToolResult result;
#ifdef _WIN32
    std::string cmd = "taskkill /F /PID " + pid;
#else
    std::string cmd = "kill -9 " + pid;
#endif
    return handleExecute(cmd, 5000);
}

} // namespace agent
} // namespace rawrxd
