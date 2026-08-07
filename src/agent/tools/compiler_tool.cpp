#include "compiler_tool.hpp"
#include <iostream>
#include <chrono>

namespace rawrxd {
namespace agent {

ToolResult CompilerTool::execute(const ToolRequest& request) {
    auto start = std::chrono::high_resolution_clock::now();
    ToolResult result;

    if (request.action == "build") {
        result = handleBuild(request.target);
    } else if (request.action == "test") {
        result = handleTest(request.target);
    } else if (request.action == "configure") {
        result = handleConfigure(request.parameters);
    } else {
        result.success = false;
        result.error = "Unknown compiler action: " + request.action;
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    return result;
}

ToolResult CompilerTool::handleBuild(const std::string& target) {
    ToolResult result;
    std::string cmd;

    // Detect build system
    if (target.find("CMakeLists.txt") != std::string::npos || target.find("cmake") != std::string::npos) {
        cmd = "cmake --build . --config Release 2>&1";
    } else if (target.find("Makefile") != std::string::npos || target.find("makefile") != std::string::npos) {
        cmd = "make -j$(nproc) 2>&1";
    } else if (target.find(".sln") != std::string::npos) {
        cmd = "msbuild " + target + " /p:Configuration=Release 2>&1";
    } else {
        // Default: try cl.exe or g++
#ifdef _WIN32
        cmd = "cl.exe " + target + " 2>&1";
#else
        cmd = "g++ -std=c++17 " + target + " -o build_output 2>&1";
#endif
    }

    // Execute build command via process tool
    ProcessTool process;
    ToolRequest req;
    req.tool_name = "process";
    req.action = "execute";
    req.target = cmd;
    req.timeout_ms = 120000;

    auto process_result = process.execute(req);
    result.success = process_result.success;
    result.output = process_result.output;
    result.error = process_result.error;

    return result;
}

ToolResult CompilerTool::handleTest(const std::string& target) {
    ToolResult result;
    std::string cmd;

    if (target.find("ctest") != std::string::npos || target.find("CMake") != std::string::npos) {
        cmd = "ctest --output-on-failure 2>&1";
    } else {
        cmd = target + " --test 2>&1";
    }

    ProcessTool process;
    ToolRequest req;
    req.tool_name = "process";
    req.action = "execute";
    req.target = cmd;
    req.timeout_ms = 120000;

    auto process_result = process.execute(req);
    result.success = process_result.success;
    result.output = process_result.output;
    result.error = process_result.error;

    return result;
}

ToolResult CompilerTool::handleConfigure(const std::string& params) {
    ToolResult result;
    std::string cmd = "cmake -S . -B build " + params + " 2>&1";

    ProcessTool process;
    ToolRequest req;
    req.tool_name = "process";
    req.action = "execute";
    req.target = cmd;
    req.timeout_ms = 60000;

    auto process_result = process.execute(req);
    result.success = process_result.success;
    result.output = process_result.output;
    result.error = process_result.error;

    return result;
}

} // namespace agent
} // namespace rawrxd
