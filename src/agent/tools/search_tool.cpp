#include "search_tool.hpp"
#include <iostream>
#include <chrono>
#include <cstdio>
#include <array>
#include <sstream>

namespace rawrxd {
namespace agent {

ToolResult SearchTool::execute(const ToolRequest& request) {
    auto start = std::chrono::high_resolution_clock::now();
    ToolResult result;

    if (request.action == "grep" || request.action == "text") {
        result = handleGrep(request.target, request.parameters);
    } else if (request.action == "symbol") {
        result = handleSymbol(request.target);
    } else {
        result.success = false;
        result.error = "Unknown search action: " + request.action;
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    return result;
}

ToolResult SearchTool::handleGrep(const std::string& pattern, const std::string& root) {
    ToolResult result;
    std::string cmd;

#ifdef _WIN32
    cmd = "findstr /s /n /c:\"" + pattern + "\" " + root + "\\*.* 2>&1";
#else
    cmd = "grep -rn \"" + pattern + "\" " + root + " 2>&1";
#endif

    std::array<char, 4096> buffer;
    std::string output;
#ifdef _WIN32
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    FILE* pipe = popen(cmd.c_str(), "r");
#endif

    if (!pipe) {
        result.success = false;
        result.error = "Search command failed";
        return result;
    }

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        output += buffer.data();
    }

#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif

    result.success = true;
    result.output = output;
    return result;
}

ToolResult SearchTool::handleSymbol(const std::string& name) {
    // Symbol search - would integrate with project intelligence
    ToolResult result;
    result.success = true;
    result.output = "Symbol search for: " + name;
    return result;
}

} // namespace agent
} // namespace rawrxd
