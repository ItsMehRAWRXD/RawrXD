#include "filesystem_tool.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <iostream>
#include <chrono>

namespace rawrxd {
namespace agent {

ToolResult FilesystemTool::execute(const ToolRequest& request) {
    auto start = std::chrono::high_resolution_clock::now();
    ToolResult result;

    if (request.action == "read") {
        result = handleRead(request.target);
    } else if (request.action == "write") {
        result = handleWrite(request.target, request.parameters);
    } else if (request.action == "delete") {
        result = handleDelete(request.target);
    } else if (request.action == "list") {
        result = handleList(request.target);
    } else if (request.action == "search") {
        result = handleSearch(request.target, request.parameters);
    } else {
        result.success = false;
        result.error = "Unknown filesystem action: " + request.action;
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    return result;
}

ToolResult FilesystemTool::handleRead(const std::string& path) {
    ToolResult result;
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        result.success = false;
        result.error = "Cannot read file: " + path;
        return result;
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    result.success = true;
    result.output = buffer.str();
    result.mime_type = "text/plain";
    return result;
}

ToolResult FilesystemTool::handleWrite(const std::string& path, const std::string& content) {
    ToolResult result;
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        result.success = false;
        result.error = "Cannot write file: " + path;
        return result;
    }
    file << content;
    result.success = true;
    result.output = "Wrote " + std::to_string(content.size()) + " bytes to " + path;
    return result;
}

ToolResult FilesystemTool::handleDelete(const std::string& path) {
    ToolResult result;
    std::error_code ec;
    if (std::filesystem::remove(path, ec)) {
        result.success = true;
        result.output = "Deleted: " + path;
    } else {
        result.success = false;
        result.error = "Cannot delete: " + path + " (" + ec.message() + ")";
    }
    return result;
}

ToolResult FilesystemTool::handleList(const std::string& path) {
    ToolResult result;
    try {
        std::string listing;
        for (const auto& entry : std::filesystem::directory_iterator(path)) {
            listing += entry.path().filename().string();
            if (entry.is_directory()) listing += "/";
            listing += "\n";
        }
        result.success = true;
        result.output = listing;
    } catch (const std::exception& e) {
        result.success = false;
        result.error = std::string("Cannot list directory: ") + e.what();
    }
    return result;
}

ToolResult FilesystemTool::handleSearch(const std::string& pattern, const std::string& root) {
    ToolResult result;
    try {
        std::string matches;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
            if (entry.path().filename().string().find(pattern) != std::string::npos) {
                matches += entry.path().string() + "\n";
            }
        }
        result.success = true;
        result.output = matches;
    } catch (const std::exception& e) {
        result.success = false;
        result.error = std::string("Search failed: ") + e.what();
    }
    return result;
}

} // namespace agent
} // namespace rawrxd
