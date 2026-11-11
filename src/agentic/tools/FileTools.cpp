// ============================================================================
// FileTools.cpp - Production File Operations for Agentic System
// ============================================================================
// Implements: read_file, write_file, list_dir, search_code
// Security: Path validation, sandboxing, backup before writes
// ============================================================================

#include "FileTools.h"
#include <windows.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <regex>
#include <algorithm>
#include <ctime>

namespace RawrXD {
namespace Agentic {
namespace Tools {

// Security: Allowed base directories (sandbox)
static std::vector<std::wstring> g_allowedDirs;
static bool g_securityInitialized = false;

void InitializeSecurity(const std::vector<std::string>& allowedDirs) {
    g_allowedDirs.clear();
    for (const auto& dir : allowedDirs) {
        std::wstring wdir(dir.begin(), dir.end());
        // Normalize path
        wchar_t fullPath[MAX_PATH];
        if (GetFullPathNameW(wdir.c_str(), MAX_PATH, fullPath, nullptr)) {
            g_allowedDirs.push_back(fullPath);
        }
    }
    g_securityInitialized = true;
}

bool ValidatePath(const std::string& path, std::string& error) {
    if (!g_securityInitialized) {
        error = "Security not initialized";
        return false;
    }
    
    std::wstring wpath(path.begin(), path.end());
    wchar_t fullPath[MAX_PATH];
    
    if (!GetFullPathNameW(wpath.c_str(), MAX_PATH, fullPath, nullptr)) {
        error = "Invalid path";
        return false;
    }
    
    // Check if path is within allowed directories
    for (const auto& allowed : g_allowedDirs) {
        if (wcsncmp(fullPath, allowed.c_str(), allowed.length()) == 0) {
            return true;
        }
    }
    
    error = "Path outside allowed directories";
    return false;
}

std::string GetBackupPath(const std::string& original) {
    std::time_t now = std::time(nullptr);
    char timestamp[32];
    std::strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", std::localtime(&now));
    return original + ".backup_" + timestamp;
}

// ============================================================================
// Tool: read_file
// ============================================================================
ToolResult ReadFile(const ReadFileParams& params) {
    ToolResult result;
    result.success = false;
    
    // Validate path
    if (!ValidatePath(params.path, result.error)) {
        return result;
    }
    
    // Open file
    std::ifstream file(params.path, std::ios::binary);
    if (!file.is_open()) {
        result.error = "Failed to open file: " + params.path;
        return result;
    }
    
    // Get file size
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // Apply offset
    if (params.offset > 0) {
        if (params.offset >= static_cast<int64_t>(fileSize)) {
            result.error = "Offset beyond file end";
            return result;
        }
        file.seekg(params.offset);
        fileSize -= params.offset;
    }
    
    // Apply limit
    size_t readSize = fileSize;
    if (params.limit > 0 && static_cast<size_t>(params.limit) < readSize) {
        readSize = params.limit;
    }
    
    // Read content
    std::string content(readSize, '\0');
    file.read(&content[0], readSize);
    
    if (!file.good() && !file.eof()) {
        result.error = "Failed to read file content";
        return result;
    }
    
    // Trim to actual bytes read
    content.resize(file.gcount());
    
    result.success = true;
    result.data["content"] = content;
    result.data["size"] = std::to_string(content.size());
    result.data["path"] = params.path;
    
    return result;
}

// ============================================================================
// Tool: write_file
// ============================================================================
ToolResult WriteFile(const WriteFileParams& params) {
    ToolResult result;
    result.success = false;
    
    // Validate path
    if (!ValidatePath(params.path, result.error)) {
        return result;
    }
    
    // Create backup if file exists and backup requested
    if (params.createBackup && FileExists(params.path)) {
        std::string backupPath = GetBackupPath(params.path);
        if (!CopyFileA(params.path.c_str(), backupPath.c_str(), FALSE)) {
            result.error = "Failed to create backup: " + backupPath;
            return result;
        }
        result.data["backup"] = backupPath;
    }
    
    // Create directory if needed
    size_t lastSlash = params.path.find_last_of("/\\");
    if (lastSlash != std::string::npos) {
        std::string dir = params.path.substr(0, lastSlash);
        CreateDirectoryA(dir.c_str(), nullptr);
    }
    
    // Open file
    std::ios::openmode mode = std::ios::binary;
    if (params.append) {
        mode |= std::ios::app;
    } else {
        mode |= std::ios::trunc;
    }
    
    std::ofstream file(params.path, mode);
    if (!file.is_open()) {
        result.error = "Failed to open file for writing: " + params.path;
        return result;
    }
    
    // Write content
    file.write(params.content.data(), params.content.size());
    
    if (!file.good()) {
        result.error = "Failed to write file content";
        return result;
    }
    
    result.success = true;
    result.data["path"] = params.path;
    result.data["bytes_written"] = std::to_string(params.content.size());
    result.data["append"] = params.append ? "true" : "false";
    
    return result;
}

// ============================================================================
// Tool: list_dir
// ============================================================================
ToolResult ListDir(const ListDirParams& params) {
    ToolResult result;
    result.success = false;
    
    // Validate path
    if (!ValidatePath(params.path, result.error)) {
        return result;
    }
    
    std::string searchPath = params.path;
    if (searchPath.back() != '\\' && searchPath.back() != '/') {
        searchPath += "\\";
    }
    searchPath += "*";
    
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        result.error = "Failed to open directory: " + params.path;
        return result;
    }
    
    std::vector<std::string> entries;
    int count = 0;
    
    do {
        std::string name = findData.cFileName;
        
        // Skip . and ..
        if (name == "." || name == "..") continue;
        
        // Apply pattern filter if specified
        if (!params.pattern.empty()) {
            std::regex pattern(params.pattern);
            if (!std::regex_match(name, pattern)) continue;
        }
        
        // Check recursive
        bool isDir = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        
        std::string entry;
        if (isDir) {
            entry = "[DIR] " + name;
        } else {
            // Calculate file size
            LARGE_INTEGER size;
            size.HighPart = findData.nFileSizeHigh;
            size.LowPart = findData.nFileSizeLow;
            entry = "[FILE] " + name + " (" + std::to_string(size.QuadPart) + " bytes)";
        }
        
        entries.push_back(entry);
        count++;
        
        // Apply limit
        if (params.limit > 0 && count >= params.limit) break;
        
    } while (FindNextFileA(hFind, &findData));
    
    FindClose(hFind);
    
    result.success = true;
    result.data["count"] = std::to_string(entries.size());
    result.data["path"] = params.path;
    
    // Build entries list
    std::string entriesStr;
    for (const auto& entry : entries) {
        if (!entriesStr.empty()) entriesStr += "\n";
        entriesStr += entry;
    }
    result.data["entries"] = entriesStr;
    
    return result;
}

// ============================================================================
// Tool: search_code
// ============================================================================
ToolResult SearchCode(const SearchCodeParams& params) {
    ToolResult result;
    result.success = false;
    
    // Validate path
    if (!ValidatePath(params.path, result.error)) {
        return result;
    }
    
    std::vector<SearchMatch> matches;
    int matchCount = 0;
    
    // Compile regex
    std::regex pattern(params.query, 
        params.caseSensitive ? std::regex::normal : std::regex::icase);
    
    // Search files
    SearchDirectory(params.path, pattern, params.filePattern, 
                    matches, matchCount, params.limit);
    
    result.success = true;
    result.data["match_count"] = std::to_string(matchCount);
    result.data["file_count"] = std::to_string(matches.size());
    
    // Build results
    std::string resultsStr;
    for (const auto& match : matches) {
        if (!resultsStr.empty()) resultsStr += "\n\n";
        resultsStr += "File: " + match.file + "\n";
        for (const auto& line : match.lines) {
            resultsStr += "  Line " + std::to_string(line.number) + ": " + line.content + "\n";
        }
    }
    result.data["results"] = resultsStr;
    
    return result;
}

void SearchDirectory(const std::string& path, const std::regex& pattern,
                     const std::string& filePattern,
                     std::vector<SearchMatch>& matches, int& matchCount, int limit) {
    std::string searchPath = path;
    if (searchPath.back() != '\\' && searchPath.back() != '/') {
        searchPath += "\\";
    }
    
    // Search files
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA((searchPath + filePattern).c_str(), &findData);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::string name = findData.cFileName;
            if (name == "." || name == "..") continue;
            
            std::string fullPath = searchPath + name;
            
            // Skip directories
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            
            // Search file
            SearchFile(fullPath, pattern, matches, matchCount, limit);
            
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
    
    // Recurse into subdirectories
    hFind = FindFirstFileA((searchPath + "*").c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::string name = findData.cFileName;
            if (name == "." || name == "..") continue;
            
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                std::string subPath = searchPath + name;
                SearchDirectory(subPath, pattern, filePattern, matches, matchCount, limit);
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
}

void SearchFile(const std::string& path, const std::regex& pattern,
                std::vector<SearchMatch>& matches, int& matchCount, int limit) {
    std::ifstream file(path);
    if (!file.is_open()) return;
    
    SearchMatch match;
    match.file = path;
    
    std::string line;
    int lineNum = 0;
    
    while (std::getline(file, line)) {
        lineNum++;
        
        if (std::regex_search(line, pattern)) {
            MatchLine ml;
            ml.number = lineNum;
            ml.content = line;
            match.lines.push_back(ml);
            matchCount++;
            
            if (limit > 0 && matchCount >= limit) break;
        }
    }
    
    if (!match.lines.empty()) {
        matches.push_back(std::move(match));
    }
}

// ============================================================================
// Tool: run_command
// ============================================================================
ToolResult RunCommand(const RunCommandParams& params) {
    ToolResult result;
    result.success = false;
    
    // Security: Validate command (basic)
    std::string cmdLower = params.command;
    std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::tolower);
    
    // Block dangerous commands
    std::vector<std::string> blocked = {
        "format", "del /", "rd /s", "rmdir /s", "erase", "ren ", "rename "
    };
    
    for (const auto& block : blocked) {
        if (cmdLower.find(block) != std::string::npos) {
            result.error = "Command blocked for security: " + block;
            return result;
        }
    }
    
    // Set up process
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    
    // Create pipes for stdout/stderr
    HANDLE hStdOutRead, hStdOutWrite;
    HANDLE hStdErrRead, hStdErrWrite;
    
    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) {
        result.error = "Failed to create stdout pipe";
        return result;
    }
    
    if (!CreatePipe(&hStdErrRead, &hStdErrWrite, &sa, 0)) {
        CloseHandle(hStdOutRead);
        CloseHandle(hStdOutWrite);
        result.error = "Failed to create stderr pipe";
        return result;
    }
    
    // Set up startup info
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdErrWrite;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    
    // Create process
    std::string cmdLine = "cmd.exe /c " + params.command;
    
    if (!CreateProcessA(NULL, &cmdLine[0], NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, 
                        params.workingDir.empty() ? NULL : params.workingDir.c_str(),
                        &si, &pi)) {
        CloseHandle(hStdOutRead);
        CloseHandle(hStdOutWrite);
        CloseHandle(hStdErrRead);
        CloseHandle(hStdErrWrite);
        result.error = "Failed to create process";
        return result;
    }
    
    // Close write ends
    CloseHandle(hStdOutWrite);
    CloseHandle(hStdErrWrite);
    
    // Read output
    std::string stdoutStr, stderrStr;
    char buffer[4096];
    DWORD bytesRead;
    
    // Read stdout
    while (ReadFile(hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        stdoutStr += buffer;
    }
    
    // Read stderr
    while (ReadFile(hStdErrRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        stderrStr += buffer;
    }
    
    // Wait for process
    DWORD waitResult = WaitForSingleObject(pi.hProcess, params.timeoutMs);
    
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    // Cleanup
    CloseHandle(hStdOutRead);
    CloseHandle(hStdErrRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // Build result
    result.success = (waitResult == WAIT_OBJECT_0 && exitCode == 0);
    result.data["stdout"] = stdoutStr;
    result.data["stderr"] = stderrStr;
    result.data["exit_code"] = std::to_string(exitCode);
    result.data["timed_out"] = (waitResult == WAIT_TIMEOUT) ? "true" : "false";
    
    if (waitResult == WAIT_TIMEOUT) {
        result.error = "Command timed out";
        TerminateProcess(pi.hProcess, 1);
    }
    
    return result;
}

// ============================================================================
// Utility Functions
// ============================================================================
bool FileExists(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
}

bool DirectoryExists(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY));
}

std::string GetFileExtension(const std::string& path) {
    size_t dot = path.find_last_of('.');
    if (dot != std::string::npos) {
        return path.substr(dot + 1);
    }
    return "";
}

std::string GetFileName(const std::string& path) {
    size_t slash = path.find_last_of("/\\");
    if (slash != std::string::npos) {
        return path.substr(slash + 1);
    }
    return path;
}

std::string GetDirectory(const std::string& path) {
    size_t slash = path.find_last_of("/\\");
    if (slash != std::string::npos) {
        return path.substr(0, slash);
    }
    return ".";
}

} // namespace Tools
} // namespace Agentic
} // namespace RawrXD
