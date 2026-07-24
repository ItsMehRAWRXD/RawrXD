// Tool System - Implementation
// Comprehensive tool bridge for the Sovereign Agent

#include "tool_system.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <regex>
#include <cstdlib>
#include <array>
#include <chrono>

namespace RawrXD {
namespace Tools {

// ============================================================================
// Utility Functions
// ============================================================================

static std::string ExecuteCommand(const std::string& cmd, int& exitCode) {
    std::array<char, 4096> buffer;
    std::string result;
    
    #ifdef _WIN32
        FILE* pipe = _popen(cmd.c_str(), "r");
    #else
        FILE* pipe = popen(cmd.c_str(), "r");
    #endif
    
    if (!pipe) {
        exitCode = -1;
        return "Failed to execute command";
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    
    #ifdef _WIN32
        exitCode = _pclose(pipe);
    #else
        exitCode = pclose(pipe);
    #endif
    
    return result;
}

static bool ValidatePath(const std::string& path, bool mustExist, std::string& error) {
    if (path.empty()) {
        error = "Path cannot be empty";
        return false;
    }
    
    // Check for path traversal
    if (path.find("..") != std::string::npos) {
        error = "Path traversal detected";
        return false;
    }
    
    if (mustExist && !std::filesystem::exists(path)) {
        error = "Path does not exist: " + path;
        return false;
    }
    
    return true;
}

// ============================================================================
// ReadFileTool Implementation
// ============================================================================

std::vector<ToolParameter> ReadFileTool::GetParameters() const {
    return {
        {"file_path", "Path to file to read", ParamType::FILE_PATH, true, {}},
        {"offset", "Byte offset to start reading", ParamType::INTEGER, false, 0},
        {"limit", "Maximum bytes to read", ParamType::INTEGER, false, 100000}
    };
}

ToolResult ReadFileTool::Execute(const std::unordered_map<std::string, std::string>& params) {
    auto start = std::chrono::steady_clock::now();
    
    auto it = params.find("file_path");
    if (it == params.end()) {
        return {ToolStatus::VALIDATION_FAILED, "", "Missing required parameter: file_path", 1};
    }
    
    std::string error;
    if (!ValidatePath(it->second, true, error)) {
        return {ToolStatus::ERROR, "", error, 1};
    }
    
    std::ifstream file(it->second, std::ios::binary);
    if (!file.is_open()) {
        return {ToolStatus::ERROR, "", "Failed to open file: " + it->second, 1};
    }
    
    // Get offset and limit
    size_t offset = 0;
    size_t limit = 100000;
    
    auto offsetIt = params.find("offset");
    if (offsetIt != params.end()) {
        offset = std::stoull(offsetIt->second);
    }
    
    auto limitIt = params.find("limit");
    if (limitIt != params.end()) {
        limit = std::stoull(limitIt->second);
    }
    
    // Seek to offset
    file.seekg(offset);
    
    // Read content
    std::vector<char> buffer(limit);
    file.read(buffer.data(), limit);
    size_t bytesRead = file.gcount();
    
    std::string content(buffer.data(), bytesRead);
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    ToolResult result;
    result.status = ToolStatus::SUCCESS;
    result.output = content;
    result.exitCode = 0;
    result.duration = duration;
    result.metadata["bytes_read"] = std::to_string(bytesRead);
    result.metadata["file_size"] = std::to_string(std::filesystem::file_size(it->second));
    
    return result;
}

// ============================================================================
// WriteFileTool Implementation
// ============================================================================

std::vector<ToolParameter> WriteFileTool::GetParameters() const {
    return {
        {"file_path", "Path to file to write", ParamType::FILE_PATH, true, {}},
        {"content", "Content to write", ParamType::STRING, true, {}},
        {"append", "Append to file instead of overwrite", ParamType::BOOLEAN, false, false}
    };
}

ToolResult WriteFileTool::Execute(const std::unordered_map<std::string, std::string>& params) {
    auto start = std::chrono::steady_clock::now();
    
    auto pathIt = params.find("file_path");
    auto contentIt = params.find("content");
    
    if (pathIt == params.end()) {
        return {ToolStatus::VALIDATION_FAILED, "", "Missing required parameter: file_path", 1};
    }
    if (contentIt == params.end()) {
        return {ToolStatus::VALIDATION_FAILED, "", "Missing required parameter: content", 1};
    }
    
    std::string error;
    if (!ValidatePath(pathIt->second, false, error)) {
        return {ToolStatus::ERROR, "", error, 1};
    }
    
    // Create parent directories if needed
    std::filesystem::path filePath(pathIt->second);
    std::filesystem::create_directories(filePath.parent_path());
    
    bool append = false;
    auto appendIt = params.find("append");
    if (appendIt != params.end()) {
        append = (appendIt->second == "true" || appendIt->second == "1");
    }
    
    std::ios::openmode mode = std::ios::binary;
    if (append) {
        mode |= std::ios::app;
    } else {
        mode |= std::ios::trunc;
    }
    
    std::ofstream file(pathIt->second, mode);
    if (!file.is_open()) {
        return {ToolStatus::ERROR, "", "Failed to open file for writing: " + pathIt->second, 1};
    }
    
    file.write(contentIt->second.data(), contentIt->second.size());
    file.close();
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    ToolResult result;
    result.status = ToolStatus::SUCCESS;
    result.output = "File written successfully";
    result.exitCode = 0;
    result.duration = duration;
    result.metadata["bytes_written"] = std::to_string(contentIt->second.size());
    result.metadata["file_path"] = pathIt->second;
    
    return result;
}

// ============================================================================
// ListDirectoryTool Implementation
// ============================================================================

std::vector<ToolParameter> ListDirectoryTool::GetParameters() const {
    return {
        {"directory_path", "Path to directory", ParamType::DIRECTORY_PATH, true, {}},
        {"recursive", "List recursively", ParamType::BOOLEAN, false, false},
        {"include_hidden", "Include hidden files", ParamType::BOOLEAN, false, false}
    };
}

ToolResult ListDirectoryTool::Execute(const std::unordered_map<std::string, std::string>& params) {
    auto start = std::chrono::steady_clock::now();
    
    auto pathIt = params.find("directory_path");
    if (pathIt == params.end()) {
        return {ToolStatus::VALIDATION_FAILED, "", "Missing required parameter: directory_path", 1};
    }
    
    std::string error;
    if (!ValidatePath(pathIt->second, true, error)) {
        return {ToolStatus::ERROR, "", error, 1};
    }
    
    bool recursive = false;
    bool includeHidden = false;
    
    auto recIt = params.find("recursive");
    if (recIt != params.end()) {
        recursive = (recIt->second == "true" || recIt->second == "1");
    }
    
    auto hiddenIt = params.find("include_hidden");
    if (hiddenIt != params.end()) {
        includeHidden = (hiddenIt->second == "true" || hiddenIt->second == "1");
    }
    
    std::stringstream output;
    int fileCount = 0;
    int dirCount = 0;
    
    try {
        if (recursive) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(pathIt->second)) {
                std::string filename = entry.path().filename().string();
                
                // Skip hidden files
                if (!includeHidden && !filename.empty() && filename[0] == '.') {
                    continue;
                }
                
                std::string type = entry.is_directory() ? "[DIR]" : "[FILE]";
                std::string size = entry.is_regular_file() 
                    ? std::to_string(std::filesystem::file_size(entry.path())) + " bytes"
                    : "";
                
                output << type << " " << entry.path().string();
                if (!size.empty()) {
                    output << " (" << size << ")";
                }
                output << "\n";
                
                if (entry.is_directory()) dirCount++;
                else fileCount++;
            }
        } else {
            for (const auto& entry : std::filesystem::directory_iterator(pathIt->second)) {
                std::string filename = entry.path().filename().string();
                
                // Skip hidden files
                if (!includeHidden && !filename.empty() && filename[0] == '.') {
                    continue;
                }
                
                std::string type = entry.is_directory() ? "[DIR]" : "[FILE]";
                std::string size = entry.is_regular_file() 
                    ? std::to_string(std::filesystem::file_size(entry.path())) + " bytes"
                    : "";
                
                output << type << " " << filename;
                if (!size.empty()) {
                    output << " (" << size << ")";
                }
                output << "\n";
                
                if (entry.is_directory()) dirCount++;
                else fileCount++;
            }
        }
    } catch (const std::exception& e) {
        return {ToolStatus::ERROR, "", std::string("Failed to list directory: ") + e.what(), 1};
    }
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    ToolResult result;
    result.status = ToolStatus::SUCCESS;
    result.output = output.str();
    result.exitCode = 0;
    result.duration = duration;
    result.metadata["file_count"] = std::to_string(fileCount);
    result.metadata["directory_count"] = std::to_string(dirCount);
    
    return result;
}

// ============================================================================
// SearchFilesTool Implementation
// ============================================================================

std::vector<ToolParameter> SearchFilesTool::GetParameters() const {
    return {
        {"pattern", "Glob pattern to search for", ParamType::GLOB_PATTERN, true, {}},
        {"directory", "Directory to search in", ParamType::DIRECTORY_PATH, false, "."},
        {"recursive", "Search recursively", ParamType::BOOLEAN, false, true}
    };
}

ToolResult SearchFilesTool::Execute(const std::unordered_map<std::string, std::string>& params) {
    auto start = std::chrono::steady_clock::now();
    
    auto patternIt = params.find("pattern");
    if (patternIt == params.end()) {
        return {ToolStatus::VALIDATION_FAILED, "", "Missing required parameter: pattern", 1};
    }
    
    std::string directory = ".";
    auto dirIt = params.find("directory");
    if (dirIt != params.end()) {
        directory = dirIt->second;
    }
    
    bool recursive = true;
    auto recIt = params.find("recursive");
    if (recIt != params.end()) {
        recursive = (recIt->second == "true" || recIt->second == "1");
    }
    
    std::stringstream output;
    int matchCount = 0;
    
    try {
        std::regex globRegex;
        std::string regexPattern = patternIt->second;
        
        // Convert glob to regex
        regexPattern = std::regex_replace(regexPattern, std::regex("\\."), "\\.");
        regexPattern = std::regex_replace(regexPattern, std::regex("\\*"), ".*");
        regexPattern = std::regex_replace(regexPattern, std::regex("\\?"), ".");
        
        globRegex = std::regex(regexPattern, std::regex::icase);
        
        auto iterator = recursive 
            ? std::filesystem::recursive_directory_iterator(directory)
            : std::filesystem::directory_iterator(directory);
        
        for (const auto& entry : iterator) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                if (std::regex_match(filename, globRegex)) {
                    output << entry.path().string() << "\n";
                    matchCount++;
                }
            }
        }
    } catch (const std::exception& e) {
        return {ToolStatus::ERROR, "", std::string("Search failed: ") + e.what(), 1};
    }
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    ToolResult result;
    result.status = ToolStatus::SUCCESS;
    result.output = output.str();
    result.exitCode = 0;
    result.duration = duration;
    result.metadata["match_count"] = std::to_string(matchCount);
    
    return result;
}

// ============================================================================
// GrepSearchTool Implementation
// ============================================================================

std::vector<ToolParameter> GrepSearchTool::GetParameters() const {
    return {
        {"pattern", "Regex pattern to search for", ParamType::REGEX_PATTERN, true, {}},
        {"path", "File or directory to search", ParamType::FILE_PATH, true, {}},
        {"recursive", "Search recursively in directories", ParamType::BOOLEAN, false, false},
        {"case_sensitive", "Case sensitive search", ParamType::BOOLEAN, false, true},
        {"max_results", "Maximum number of results", ParamType::INTEGER, false, 100}
    };
}

ToolResult GrepSearchTool::Execute(const std::unordered_map<std::string, std::string>& params) {
    auto start = std::chrono::steady_clock::now();
    
    auto patternIt = params.find("pattern");
    auto pathIt = params.find("path");
    
    if (patternIt == params.end()) {
        return {ToolStatus::VALIDATION_FAILED, "", "Missing required parameter: pattern", 1};
    }
    if (pathIt == params.end()) {
        return {ToolStatus::VALIDATION_FAILED, "", "Missing required parameter: path", 1};
    }
    
    bool recursive = false;
    bool caseSensitive = true;
    int maxResults = 100;
    
    auto recIt = params.find("recursive");
    if (recIt != params.end()) {
        recursive = (recIt->second == "true" || recIt->second == "1");
    }
    
    auto caseIt = params.find("case_sensitive");
    if (caseIt != params.end()) {
        caseSensitive = (caseIt->second == "true" || caseIt->second == "1");
    }
    
    auto maxIt = params.find("max_results");
    if (maxIt != params.end()) {
        maxResults = std::stoi(maxIt->second);
    }
    
    try {
        std::regex::flag_type flags = std::regex::ECMAScript;
        if (!caseSensitive) {
            flags |= std::regex::icase;
        }
        
        std::regex regexPattern(patternIt->second, flags);
        std::stringstream output;
        int matchCount = 0;
        
        std::vector<std::filesystem::path> filesToSearch;
        
        if (std::filesystem::is_regular_file(pathIt->second)) {
            filesToSearch.push_back(pathIt->second);
        } else if (std::filesystem::is_directory(pathIt->second)) {
            if (recursive) {
                for (const auto& entry : std::filesystem::recursive_directory_iterator(pathIt->second)) {
                    if (entry.is_regular_file()) {
                        filesToSearch.push_back(entry.path());
                    }
                }
            } else {
                for (const auto& entry : std::filesystem::directory_iterator(pathIt->second)) {
                    if (entry.is_regular_file()) {
                        filesToSearch.push_back(entry.path());
                    }
                }
            }
        }
        
        for (const auto& filePath : filesToSearch) {
            if (matchCount >= maxResults) break;
            
            std::ifstream file(filePath);
            if (!file.is_open()) continue;
            
            std::string line;
            int lineNum = 0;
            while (std::getline(file, line) && matchCount < maxResults) {
                lineNum++;
                if (std::regex_search(line, regexPattern)) {
                    output << filePath.string() << ":" << lineNum << ":" << line << "\n";
                    matchCount++;
                }
            }
        }
        
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        ToolResult result;
        result.status = ToolStatus::SUCCESS;
        result.output = output.str();
        result.exitCode = 0;
        result.duration = duration;
        result.metadata["match_count"] = std::to_string(matchCount);
        result.metadata["files_searched"] = std::to_string(filesToSearch.size());
        
        return result;
        
    } catch (const std::regex_error& e) {
        return {ToolStatus::VALIDATION_FAILED, "", std::string("Invalid regex pattern: ") + e.what(), 1};
    } catch (const std::exception& e) {
        return {ToolStatus::ERROR, "", std::string("Search failed: ") + e.what(), 1};
    }
}

// ============================================================================
// ReplaceStringTool Implementation
// ============================================================================

std::vector<ToolParameter> ReplaceStringTool::GetParameters() const {
    return {
        {"file_path", "Path to file", ParamType::FILE_PATH, true, {}},
        {"old_string", "String to replace", ParamType::STRING, true, {}},
        {"new_string", "Replacement string", ParamType::STRING, true, {}},
        {"occurrence", "Which occurrence to replace (0=all)", ParamType::INTEGER, false, 0}
    };
}

ToolResult ReplaceStringTool::Execute(const std::unordered_map<std::string, std::string>& params) {
    auto start = std::chrono::steady_clock::now();
    
    auto pathIt = params.find("file_path");
    auto oldIt = params.find("old_string");
    auto newIt = params.find("new_string");
    
    if (pathIt == params.end()) {
        return {ToolStatus::VALIDATION_FAILED, "", "Missing required parameter: file_path", 1};
    }
    if (oldIt == params.end()) {
        return {ToolStatus::VALIDATION_FAILED, "", "Missing required parameter: old_string", 1};
    }
    if (newIt == params.end()) {
        return {ToolStatus::VALIDATION_FAILED, "", "Missing required parameter: new_string", 1};
    }
    
    std::string error;
    if (!ValidatePath(pathIt->second, true, error)) {
        return {ToolStatus::ERROR, "", error, 1};
    }
    
    // Read file
    std::ifstream file(pathIt->second, std::ios::binary);
    if (!file.is_open()) {
        return {ToolStatus::ERROR, "", "Failed to open file: " + pathIt->second, 1};
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    file.close();
    
    int occurrence = 0;
    auto occIt = params.find("occurrence");
    if (occIt != params.end()) {
        occurrence = std::stoi(occIt->second);
    }
    
    // Perform replacement
    std::string newContent;
    int replacements = 0;
    
    if (occurrence == 0) {
        // Replace all
        size_t pos = 0;
        while ((pos = content.find(oldIt->second, pos)) != std::string::npos) {
            newContent += content.substr(0, pos);
            newContent += newIt->second;
            pos += oldIt->second.length();
            content = content.substr(pos);
            pos = 0;
            replacements++;
        }
        newContent += content;
    } else {
        // Replace specific occurrence
        size_t pos = 0;
        int currentOcc = 0;
        while ((pos = content.find(oldIt->second, pos)) != std::string::npos) {
            currentOcc++;
            if (currentOcc == occurrence) {
                newContent = content.substr(0, pos);
                newContent += newIt->second;
                newContent += content.substr(pos + oldIt->second.length());
                replacements = 1;
                break;
            }
            pos += oldIt->second.length();
        }
        if (replacements == 0) {
            return {ToolStatus::ERROR, "", "Occurrence " + std::to_string(occurrence) + " not found", 1};
        }
    }
    
    // Write back
    std::ofstream outFile(pathIt->second, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
        return {ToolStatus::ERROR, "", "Failed to write file: " + pathIt->second, 1};
    }
    
    outFile.write(newContent.data(), newContent.size());
    outFile.close();
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    ToolResult result;
    result.status = ToolStatus::SUCCESS;
    result.output = "Replaced " + std::to_string(replacements) + " occurrence(s)";
    result.exitCode = 0;
    result.duration = duration;
    result.metadata["replacements"] = std::to_string(replacements);
    result.metadata["file_path"] = pathIt->second;
    
    return result;
}

// ============================================================================
// GitStatusTool Implementation
// ============================================================================

std::vector<ToolParameter> GitStatusTool::GetParameters() const {
    return {
        {"repo_path", "Path to git repository", ParamType::DIRECTORY_PATH, false, "."}
    };
}

ToolResult GitStatusTool::Execute(const std::unordered_map<std::string, std::string>& params) {
    auto start = std::chrono::steady_clock::now();
    
    std::string repoPath = ".";
    auto pathIt = params.find("repo_path");
    if (pathIt != params.end()) {
        repoPath = pathIt->second;
    }
    
    std::string error;
    if (!ValidatePath(repoPath, true, error)) {
        return {ToolStatus::ERROR, "", error, 1};
    }
    
    int exitCode;
    std::string output = ExecuteCommand("cd \"" + repoPath + "\" && git status --porcelain", exitCode);
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    ToolResult result;
    result.status = (exitCode == 0) ? ToolStatus::SUCCESS : ToolStatus::ERROR;
    result.output = output;
    result.error = (exitCode != 0) ? "Git command failed" : "";
    result.exitCode = exitCode;
    result.duration = duration;
    
    return result;
}

// ============================================================================
// GitDiffTool Implementation
// ============================================================================

std::vector<ToolParameter> GitDiffTool::GetParameters() const {
    return {
        {"repo_path", "Path to git repository", ParamType::DIRECTORY_PATH, false, "."},
        {"cached", "Show staged changes", ParamType::BOOLEAN, false, false}
    };
}

ToolResult GitDiffTool::Execute(const std::unordered_map<std::string, std::string>& params) {
    auto start = std::chrono::steady_clock::now();
    
    std::string repoPath = ".";
    auto pathIt = params.find("repo_path");
    if (pathIt != params.end()) {
        repoPath = pathIt->second;
    }
    
    bool cached = false;
    auto cachedIt = params.find("cached");
    if (cachedIt != params.end()) {
        cached = (cachedIt->second == "true" || cachedIt->second == "1");
    }
    
    std::string error;
    if (!ValidatePath(repoPath, true, error)) {
        return {ToolStatus::ERROR, "", error, 1};
    }
    
    std::string cmd = "cd \"" + repoPath + "\" && git diff";
    if (cached) {
        cmd += " --cached";
    }
    
    int exitCode;
    std::string output = ExecuteCommand(cmd, exitCode);
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    ToolResult result;
    result.status = (exitCode == 0) ? ToolStatus::SUCCESS : ToolStatus::ERROR;
    result.output = output;
    result.error = (exitCode != 0) ? "Git command failed" : "";
    result.exitCode = exitCode;
    result.duration = duration;
    
    return result;
}

// ============================================================================
// BuildProjectTool Implementation
// ============================================================================

std::vector<ToolParameter> BuildProjectTool::GetParameters() const {
    return {
        {"build_dir", "Build directory", ParamType::DIRECTORY_PATH, false, "build"},
        {"config", "Build configuration", ParamType::STRING, false, "Release"},
        {"target", "Specific target to build", ParamType::STRING, false, ""},
        {"parallel", "Parallel jobs", ParamType::INTEGER, false, 0}
    };
}

ToolResult BuildProjectTool::Execute(const std::unordered_map<std::string, std::string>& params) {
    auto start = std::chrono::steady_clock::now();
    
    std::string buildDir = "build";
    std::string config = "Release";
    std::string target;
    int parallel = 0;
    
    auto buildIt = params.find("build_dir");
    if (buildIt != params.end()) {
        buildDir = buildIt->second;
    }
    
    auto configIt = params.find("config");
    if (configIt != params.end()) {
        config = configIt->second;
    }
    
    auto targetIt = params.find("target");
    if (targetIt != params.end()) {
        target = targetIt->second;
    }
    
    auto parIt = params.find("parallel");
    if (parIt != params.end()) {
        parallel = std::stoi(parIt->second);
    }
    
    // Ensure build directory exists
    std::filesystem::create_directories(buildDir);
    
    // Configure if needed
    if (!std::filesystem::exists(buildDir + "/CMakeCache.txt")) {
        int configExit;
        std::string configOutput = ExecuteCommand(
            "cmake -B \"" + buildDir + "\" -DCMAKE_BUILD_TYPE=" + config, configExit);
        
        if (configExit != 0) {
            return {ToolStatus::ERROR, configOutput, "CMake configuration failed", configExit};
        }
    }
    
    // Build
    std::string buildCmd = "cmake --build \"" + buildDir + "\" --config " + config;
    if (!target.empty()) {
        buildCmd += " --target " + target;
    }
    if (parallel > 0) {
        buildCmd += " --parallel " + std::to_string(parallel);
    }
    
    int exitCode;
    std::string output = ExecuteCommand(buildCmd, exitCode);
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    ToolResult result;
    result.status = (exitCode == 0) ? ToolStatus::SUCCESS : ToolStatus::ERROR;
    result.output = output;
    result.error = (exitCode != 0) ? "Build failed" : "";
    result.exitCode = exitCode;
    result.duration = duration;
    result.metadata["build_dir"] = buildDir;
    result.metadata["config"] = config;
    
    return result;
}

// ============================================================================
// RunTestsTool Implementation
// ============================================================================

std::vector<ToolParameter> RunTestsTool::GetParameters() const {
    return {
        {"build_dir", "Build directory", ParamType::DIRECTORY_PATH, false, "build"},
        {"config", "Build configuration", ParamType::STRING, false, "Release"},
        {"verbose", "Verbose output", ParamType::BOOLEAN, false, false}
    };
}

ToolResult RunTestsTool::Execute(const std::unordered_map<std::string, std::string>& params) {
    auto start = std::chrono::steady_clock::now();
    
    std::string buildDir = "build";
    std::string config = "Release";
    bool verbose = false;
    
    auto buildIt = params.find("build_dir");
    if (buildIt != params.end()) {
        buildDir = buildIt->second;
    }
    
    auto configIt = params.find("config");
    if (configIt != params.end()) {
        config = configIt->second;
    }
    
    auto verbIt = params.find("verbose");
    if (verbIt != params.end()) {
        verbose = (verbIt->second == "true" || verbIt->second == "1");
    }
    
    std::string testCmd = "cd \"" + buildDir + "\" && ctest -C " + config;
    if (verbose) {
        testCmd += " -V";
    }
    testCmd += " --output-on-failure";
    
    int exitCode;
    std::string output = ExecuteCommand(testCmd, exitCode);
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    ToolResult result;
    result.status = (exitCode == 0) ? ToolStatus::SUCCESS : ToolStatus::ERROR;
    result.output = output;
    result.error = (exitCode != 0) ? "Tests failed" : "";
    result.exitCode = exitCode;
    result.duration = duration;
    
    return result;
}

// ============================================================================
// ToolRegistry Implementation
// ============================================================================

ToolRegistry& ToolRegistry::Instance() {
    static ToolRegistry instance;
    return instance;
}

void ToolRegistry::RegisterTool(std::shared_ptr<ITool> tool) {
    if (!tool) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    tools_[tool->GetName()] = tool;
}

void ToolRegistry::UnregisterTool(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    tools_.erase(name);
}

std::shared_ptr<ITool> ToolRegistry::GetTool(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tools_.find(name);
    if (it != tools_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::string> ToolRegistry::GetToolNames() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> names;
    for (const auto& [name, tool] : tools_) {
        names.push_back(name);
    }
    return names;
}

std::vector<std::shared_ptr<ITool>> ToolRegistry::GetAllTools() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<ITool>> result;
    for (const auto& [name, tool] : tools_) {
        result.push_back(tool);
    }
    return result;
}

ToolResult ToolRegistry::Execute(const std::string& toolName, const std::unordered_map<std::string, std::string>& params) {
    auto tool = GetTool(toolName);
    if (!tool) {
        return {ToolStatus::NOT_FOUND, "", "Tool not found: " + toolName, 1};
    }
    
    // Validate parameters
    std::string error;
    if (!ValidateToolCall(toolName, params, error)) {
        return {ToolStatus::VALIDATION_FAILED, "", error, 1};
    }
    
    // Execute
    auto result = tool->Execute(params);
    
    // Update stats
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.totalCalls++;
    stats_.callsByTool[toolName]++;
    if (result.status == ToolStatus::SUCCESS) {
        stats_.successfulCalls++;
    } else {
        stats_.failedCalls++;
    }
    
    return result;
}

bool ToolRegistry::ValidateToolCall(const std::string& toolName, const std::unordered_map<std::string, std::string>& params, std::string& error) const {
    auto tool = GetTool(toolName);
    if (!tool) {
        error = "Tool not found: " + toolName;
        return false;
    }
    
    auto toolParams = tool->GetParameters();
    
    // Check required parameters
    for (const auto& param : toolParams) {
        if (param.required) {
            auto it = params.find(param.name);
            if (it == params.end() || it->second.empty()) {
                error = "Missing required parameter: " + param.name;
                return false;
            }
        }
    }
    
    return true;
}

ToolRegistry::Stats ToolRegistry::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void ToolRegistry::ResetStats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = Stats{};
}

} // namespace Tools
} // namespace RawrXD
