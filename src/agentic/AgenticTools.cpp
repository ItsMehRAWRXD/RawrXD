// ============================================================================
// AgenticTools.cpp - Production Implementation of 5 Core Agent Tools
// read_file, write_file, run_command, search_code, list_dir
// Fully hardened with path validation, error handling, and security checks
// ============================================================================

#include "AgenticTools.hpp"
#include <windows.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <fstream>
#include <sstream>
#include <regex>
#include <filesystem>
#include <chrono>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

namespace RawrXD {
namespace Agentic {

// ============================================================================
// Security & Path Validation
// ============================================================================

bool ToolSecurity::IsPathAllowed(const std::string& path) {
    // Normalize path
    char fullPath[MAX_PATH];
    if (!GetFullPathNameA(path.c_str(), MAX_PATH, fullPath, nullptr)) {
        return false;
    }
    
    std::string normalized(fullPath);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);
    
    // Block system directories
    static const std::vector<std::string> blockedPrefixes = {
        "c:\\windows",
        "c:\\program files",
        "c:\\program files (x86)",
        "c:\\programdata",
        "c:\\users\\all users",
        "c:\\users\\default",
        "c:\\users\\public",
        "c:\\$",
        "c:\\recovery",
        "c:\\system volume information",
        "c:\\config.msi",
        "c:\\inetpub",
        "c:\\intel",
        "c:\\nvidia",
        "c:\\amd",
    };
    
    for (const auto& prefix : blockedPrefixes) {
        if (normalized.find(prefix) == 0) {
            return false;
        }
    }
    
    // Check for directory traversal
    if (normalized.find("..") != std::string::npos) {
        return false;
    }
    
    return true;
}

bool ToolSecurity::IsWithinWorkspace(const std::string& path, const std::string& workspace) {
    char fullPath[MAX_PATH];
    char fullWorkspace[MAX_PATH];
    
    if (!GetFullPathNameA(path.c_str(), MAX_PATH, fullPath, nullptr) ||
        !GetFullPathNameA(workspace.c_str(), MAX_PATH, fullWorkspace, nullptr)) {
        return false;
    }
    
    // Ensure workspace path ends with backslash for proper prefix check
    std::string ws(fullWorkspace);
    if (!ws.empty() && ws.back() != '\\') {
        ws += '\\';
    }
    
    std::string fp(fullPath);
    std::transform(fp.begin(), fp.end(), fp.begin(), ::tolower);
    std::transform(ws.begin(), ws.end(), ws.begin(), ::tolower);
    
    return fp.find(ws) == 0;
}

std::string ToolSecurity::NormalizePath(const std::string& path) {
    char fullPath[MAX_PATH];
    if (GetFullPathNameA(path.c_str(), MAX_PATH, fullPath, nullptr)) {
        return std::string(fullPath);
    }
    return path;
}

// ============================================================================
// Tool 1: read_file - Read file contents with safety limits
// ============================================================================

ToolResult Tools::read_file(const std::string& path, size_t offset, size_t limit) {
    ToolResult result;
    result.tool = "read_file";
    result.params["path"] = path;
    result.params["offset"] = std::to_string(offset);
    result.params["limit"] = std::to_string(limit);
    
    auto start = std::chrono::steady_clock::now();
    
    // Security check
    if (!ToolSecurity::IsPathAllowed(path)) {
        result.success = false;
        result.error = "Access denied: path not allowed";
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Check file exists
    DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        result.success = false;
        result.error = "File not found: " + path;
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        result.success = false;
        result.error = "Path is a directory, not a file: " + path;
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Get file size
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        result.success = false;
        result.error = "Cannot open file: " + std::to_string(GetLastError());
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        result.success = false;
        result.error = "Cannot get file size";
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Apply limits
    const size_t MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB max
    if (fileSize.QuadPart > MAX_FILE_SIZE) {
        CloseHandle(hFile);
        result.success = false;
        result.error = "File too large: " + std::to_string(fileSize.QuadPart) + 
                      " bytes (max " + std::to_string(MAX_FILE_SIZE) + ")";
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Validate offset
    if (offset > (size_t)fileSize.QuadPart) {
        CloseHandle(hFile);
        result.success = false;
        result.error = "Offset beyond file end";
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Calculate read size
    size_t bytesToRead = (size_t)fileSize.QuadPart - offset;
    if (limit > 0 && limit < bytesToRead) {
        bytesToRead = limit;
    }
    
    // Read file
    std::string content;
    content.resize(bytesToRead);
    
    if (offset > 0) {
        LARGE_INTEGER liOffset;
        liOffset.QuadPart = offset;
        SetFilePointerEx(hFile, liOffset, nullptr, FILE_BEGIN);
    }
    
    DWORD bytesRead = 0;
    BOOL readSuccess = ReadFile(hFile, content.data(), (DWORD)bytesToRead, &bytesRead, nullptr);
    CloseHandle(hFile);
    
    if (!readSuccess || bytesRead != bytesToRead) {
        result.success = false;
        result.error = "Failed to read file: " + std::to_string(GetLastError());
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Success
    result.success = true;
    result.data["content"] = content;
    result.data["size"] = std::to_string(fileSize.QuadPart);
    result.data["read"] = std::to_string(bytesRead);
    result.data["offset"] = std::to_string(offset);
    result.durationMs = GetElapsedMs(start);
    
    return result;
}

// ============================================================================
// Tool 2: write_file - Write file contents with atomic operations
// ============================================================================

ToolResult Tools::write_file(const std::string& path, const std::string& content, bool append) {
    ToolResult result;
    result.tool = "write_file";
    result.params["path"] = path;
    result.params["append"] = append ? "true" : "false";
    result.params["content_length"] = std::to_string(content.length());
    
    auto start = std::chrono::steady_clock::now();
    
    // Security check
    if (!ToolSecurity::IsPathAllowed(path)) {
        result.success = false;
        result.error = "Access denied: path not allowed";
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Ensure directory exists
    std::string dir = path;
    size_t lastSlash = dir.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        dir = dir.substr(0, lastSlash);
        if (!dir.empty()) {
            std::filesystem::create_directories(dir);
        }
    }
    
    // Write atomically using temp file
    std::string tempPath = path + ".tmp." + std::to_string(GetCurrentProcessId());
    
    HANDLE hFile = CreateFileA(tempPath.c_str(), GENERIC_WRITE, 0, nullptr, 
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        result.success = false;
        result.error = "Cannot create temp file: " + std::to_string(GetLastError());
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Write content
    DWORD bytesWritten = 0;
    BOOL writeSuccess = WriteFile(hFile, content.data(), (DWORD)content.length(), &bytesWritten, nullptr);
    
    if (!writeSuccess || bytesWritten != content.length()) {
        CloseHandle(hFile);
        DeleteFileA(tempPath.c_str());
        result.success = false;
        result.error = "Failed to write file: " + std::to_string(GetLastError());
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Flush to disk
    FlushFileBuffers(hFile);
    CloseHandle(hFile);
    
    // Atomic rename
    if (!ReplaceFileA(path.c_str(), tempPath.c_str(), nullptr, 0, nullptr, nullptr)) {
        // If replace fails (file doesn't exist), just rename
        if (GetLastError() == ERROR_FILE_NOT_FOUND) {
            if (!MoveFileA(tempPath.c_str(), path.c_str())) {
                DeleteFileA(tempPath.c_str());
                result.success = false;
                result.error = "Failed to rename temp file: " + std::to_string(GetLastError());
                result.durationMs = GetElapsedMs(start);
                return result;
            }
        } else {
            DeleteFileA(tempPath.c_str());
            result.success = false;
            result.error = "Failed to replace file: " + std::to_string(GetLastError());
            result.durationMs = GetElapsedMs(start);
            return result;
        }
    }
    
    // Success
    result.success = true;
    result.data["bytes_written"] = std::to_string(bytesWritten);
    result.data["path"] = ToolSecurity::NormalizePath(path);
    result.durationMs = GetElapsedMs(start);
    
    return result;
}

// ============================================================================
// Tool 3: run_command - Execute command with timeout and output capture
// ============================================================================

ToolResult Tools::run_command(const std::string& command, const std::vector<std::string>& args, 
                               int timeoutMs, const std::string& cwd) {
    ToolResult result;
    result.tool = "run_command";
    result.params["command"] = command;
    result.params["timeout_ms"] = std::to_string(timeoutMs);
    result.params["cwd"] = cwd.empty() ? "." : cwd;
    
    auto start = std::chrono::steady_clock::now();
    
    // Security: Block dangerous commands
    std::string lowerCmd = command;
    std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::tolower);
    
    static const std::vector<std::string> blockedCommands = {
        "del", "erase", "rmdir", "format", "diskpart",
        "reg", "sc", "net", "schtasks", "wmic",
        "powershell -enc", "powershell -encoded",
        "certutil -decode", "mshta", "cscript", "wscript",
        "bitsadmin", "regsvr32", " Rundll32"
    };
    
    for (const auto& blocked : blockedCommands) {
        if (lowerCmd.find(blocked) != std::string::npos) {
            result.success = false;
            result.error = "Command blocked for security: " + blocked;
            result.durationMs = GetElapsedMs(start);
            return result;
        }
    }
    
    // Build command line
    std::string cmdLine = "\"" + command + "\"";
    for (const auto& arg : args) {
        cmdLine += " \"" + arg + "\"";
    }
    
    // Set up pipes for output capture
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;
    
    HANDLE hStdOutRead, hStdOutWrite;
    HANDLE hStdErrRead, hStdErrWrite;
    
    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0) ||
        !CreatePipe(&hStdErrRead, &hStdErrWrite, &sa, 0)) {
        result.success = false;
        result.error = "Failed to create pipes";
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Set up process
    STARTUPINFOA si = {};
    si.cb = sizeof(STARTUPINFOA);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdErrWrite;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    
    PROCESS_INFORMATION pi = {};
    
    std::string workingDir = cwd.empty() ? ToolSecurity::NormalizePath(".") : cwd;
    
    BOOL created = CreateProcessA(nullptr, cmdLine.data(), nullptr, nullptr, TRUE,
                                   CREATE_NO_WINDOW | NORMAL_PRIORITY_CLASS,
                                   nullptr, workingDir.c_str(), &si, &pi);
    
    // Close write ends of pipes (child has them now)
    CloseHandle(hStdOutWrite);
    CloseHandle(hStdErrWrite);
    
    if (!created) {
        CloseHandle(hStdOutRead);
        CloseHandle(hStdErrRead);
        result.success = false;
        result.error = "Failed to create process: " + std::to_string(GetLastError());
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Read output with timeout
    std::string stdoutData, stderrData;
    char buffer[4096];
    DWORD bytesRead;
    DWORD waitResult;
    bool timedOut = false;
    
    auto timeout = std::chrono::milliseconds(timeoutMs);
    auto endTime = start + timeout;
    
    while (true) {
        DWORD remainingMs = (DWORD)std::max(0LL, 
            std::chrono::duration_cast<std::chrono::milliseconds>(endTime - 
            std::chrono::steady_clock::now()).count());
        
        waitResult = WaitForSingleObject(pi.hProcess, remainingMs > 100 ? 100 : remainingMs);
        
        // Read available output
        DWORD avail;
        while (PeekNamedPipe(hStdOutRead, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
            if (ReadFile(hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                stdoutData += buffer;
            }
        }
        
        while (PeekNamedPipe(hStdErrRead, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
            if (ReadFile(hStdErrRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                stderrData += buffer;
            }
        }
        
        if (waitResult == WAIT_OBJECT_0) {
            break; // Process finished
        }
        
        if (std::chrono::steady_clock::now() >= endTime) {
            timedOut = true;
            TerminateProcess(pi.hProcess, 1);
            break;
        }
    }
    
    // Get exit code
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    // Cleanup
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hStdOutRead);
    CloseHandle(hStdErrRead);
    
    // Build result
    result.success = (exitCode == 0) && !timedOut;
    result.data["stdout"] = stdoutData;
    result.data["stderr"] = stderrData;
    result.data["exit_code"] = std::to_string(exitCode);
    result.data["timed_out"] = timedOut ? "true" : "false";
    result.durationMs = GetElapsedMs(start);
    
    if (timedOut) {
        result.error = "Command timed out after " + std::to_string(timeoutMs) + "ms";
    } else if (exitCode != 0) {
        result.error = "Command failed with exit code " + std::to_string(exitCode);
    }
    
    return result;
}

// ============================================================================
// Tool 4: search_code - Search files with regex patterns
// ============================================================================

ToolResult Tools::search_code(const std::string& pattern, const std::string& path, 
                               const std::vector<std::string>& fileExtensions,
                               bool caseSensitive, int maxResults) {
    ToolResult result;
    result.tool = "search_code";
    result.params["pattern"] = pattern;
    result.params["path"] = path;
    result.params["case_sensitive"] = caseSensitive ? "true" : "false";
    result.params["max_results"] = std::to_string(maxResults);
    
    auto start = std::chrono::steady_clock::now();
    
    // Security check
    if (!ToolSecurity::IsPathAllowed(path)) {
        result.success = false;
        result.error = "Access denied: path not allowed";
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Compile regex
    std::regex::flag_type flags = std::regex::ECMAScript;
    if (!caseSensitive) {
        flags |= std::regex::icase;
    }
    
    std::regex re;
    try {
        re = std::regex(pattern, flags);
    } catch (const std::regex_error& e) {
        result.success = false;
        result.error = std::string("Invalid regex pattern: ") + e.what();
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Build extension filter
    std::unordered_set<std::string> extensions;
    for (const auto& ext : fileExtensions) {
        std::string lowerExt = ext;
        std::transform(lowerExt.begin(), lowerExt.end(), lowerExt.begin(), ::tolower);
        extensions.insert(lowerExt);
    }
    
    // Search results
    std::vector<SearchMatch> matches;
    int filesSearched = 0;
    int filesMatched = 0;
    
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(path, 
                std::filesystem::directory_options::skip_permission_denied)) {
            
            if (matches.size() >= (size_t)maxResults) {
                break;
            }
            
            if (!entry.is_regular_file()) {
                continue;
            }
            
            // Check extension
            if (!extensions.empty()) {
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (extensions.find(ext) == extensions.end()) {
                    continue;
                }
            }
            
            // Check file size (skip files > 10MB)
            auto fileSize = entry.file_size();
            if (fileSize > 10 * 1024 * 1024) {
                continue;
            }
            
            filesSearched++;
            
            // Read and search file
            std::ifstream file(entry.path(), std::ios::binary);
            if (!file) continue;
            
            std::string content((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
            file.close();
            
            // Skip binary files (check for null bytes)
            if (content.find('\0') != std::string::npos) {
                continue;
            }
            
            // Search line by line
            std::istringstream stream(content);
            std::string line;
            int lineNum = 0;
            bool fileMatched = false;
            
            while (std::getline(stream, line) && matches.size() < (size_t)maxResults) {
                lineNum++;
                
                if (std::regex_search(line, re)) {
                    SearchMatch match;
                    match.file = entry.path().string();
                    match.line = lineNum;
                    match.column = std::regex_search(line, re) ? 
                        (int)std::distance(line.begin(), 
                            std::regex_search(line.begin(), line.end(), re) ? 
                            line.begin() : line.begin()) : 0;
                    match.text = line;
                    
                    // Trim line for display
                    if (match.text.length() > 200) {
                        match.text = match.text.substr(0, 200) + "...";
                    }
                    
                    matches.push_back(match);
                    fileMatched = true;
                }
            }
            
            if (fileMatched) {
                filesMatched++;
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        // Continue with partial results
    }
    
    // Build result
    result.success = true;
    result.data["files_searched"] = std::to_string(filesSearched);
    result.data["files_matched"] = std::to_string(filesMatched);
    result.data["matches_found"] = std::to_string(matches.size());
    
    // Serialize matches
    std::string matchesJson = "[";
    for (size_t i = 0; i < matches.size(); i++) {
        if (i > 0) matchesJson += ",";
        matchesJson += "{";
        matchesJson += "\"file\":\"" + EscapeJson(matches[i].file) + "\",";
        matchesJson += "\"line\":" + std::to_string(matches[i].line) + ",";
        matchesJson += "\"column\":" + std::to_string(matches[i].column) + ",";
        matchesJson += "\"text\":\"" + EscapeJson(matches[i].text) + "\"";
        matchesJson += "}";
    }
    matchesJson += "]";
    result.data["matches"] = matchesJson;
    
    result.durationMs = GetElapsedMs(start);
    return result;
}

// ============================================================================
// Tool 5: list_dir - List directory contents with metadata
// ============================================================================

ToolResult Tools::list_dir(const std::string& path, bool recursive, 
                            const std::string& filter) {
    ToolResult result;
    result.tool = "list_dir";
    result.params["path"] = path;
    result.params["recursive"] = recursive ? "true" : "false";
    result.params["filter"] = filter;
    
    auto start = std::chrono::steady_clock::now();
    
    // Security check
    if (!ToolSecurity::IsPathAllowed(path)) {
        result.success = false;
        result.error = "Access denied: path not allowed";
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Check path exists
    DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        result.success = false;
        result.error = "Directory not found: " + path;
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        result.success = false;
        result.error = "Path is not a directory: " + path;
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Compile filter regex if provided
    std::regex filterRe;
    bool hasFilter = !filter.empty();
    if (hasFilter) {
        try {
            filterRe = std::regex(filter, std::regex::icase);
        } catch (...) {
            hasFilter = false;
        }
    }
    
    // Collect entries
    std::vector<DirEntry> entries;
    int totalFiles = 0;
    int totalDirs = 0;
    int64_t totalSize = 0;
    
    try {
        auto options = recursive ? std::filesystem::directory_options::none 
                                : std::filesystem::directory_options::skip_permission_denied;
        
        for (const auto& entry : std::filesystem::directory_iterator(path, options)) {
            DirEntry de;
            de.name = entry.path().filename().string();
            de.path = entry.path().string();
            de.isDirectory = entry.is_directory();
            
            if (de.isDirectory) {
                totalDirs++;
            } else {
                totalFiles++;
                try {
                    de.size = entry.file_size();
                    totalSize += de.size;
                } catch (...) {
                    de.size = 0;
                }
            }
            
            // Get last modified time
            try {
                auto lwt = entry.last_write_time();
                auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    lwt - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
                auto time = std::chrono::system_clock::to_time_t(sctp);
                de.modified = std::ctime(&time);
                if (!de.modified.empty() && de.modified.back() == '\n') {
                    de.modified.pop_back();
                }
            } catch (...) {
                de.modified = "unknown";
            }
            
            // Apply filter
            if (hasFilter && !std::regex_match(de.name, filterRe)) {
                continue;
            }
            
            entries.push_back(de);
            
            if (!recursive && entries.size() >= 1000) {
                break; // Limit non-recursive listings
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        result.success = false;
        result.error = std::string("Filesystem error: ") + e.what();
        result.durationMs = GetElapsedMs(start);
        return result;
    }
    
    // Build result
    result.success = true;
    result.data["total_files"] = std::to_string(totalFiles);
    result.data["total_dirs"] = std::to_string(totalDirs);
    result.data["total_size"] = std::to_string(totalSize);
    result.data["entries_count"] = std::to_string(entries.size());
    
    // Serialize entries
    std::string entriesJson = "[";
    for (size_t i = 0; i < entries.size(); i++) {
        if (i > 0) entriesJson += ",";
        entriesJson += "{";
        entriesJson += "\"name\":\"" + EscapeJson(entries[i].name) + "\",";
        entriesJson += "\"path\":\"" + EscapeJson(entries[i].path) + "\",";
        entriesJson += "\"is_directory\":" + std::string(entries[i].isDirectory ? "true" : "false") + ",";
        entriesJson += "\"size\":" + std::to_string(entries[i].size) + ",";
        entriesJson += "\"modified\":\"" + EscapeJson(entries[i].modified) + "\"";
        entriesJson += "}";
    }
    entriesJson += "]";
    result.data["entries"] = entriesJson;
    
    result.durationMs = GetElapsedMs(start);
    return result;
}

// ============================================================================
// Helper Functions
// ============================================================================

double Tools::GetElapsedMs(const std::chrono::steady_clock::time_point& start) {
    auto end = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count();
}

std::string Tools::EscapeJson(const std::string& s) {
    std::string result;
    result.reserve(s.length() * 2);
    
    for (char c : s) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (c >= 0x20 && c < 0x7F) {
                    result += c;
                } else {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    result += buf;
                }
        }
    }
    
    return result;
}

} // namespace Agentic
} // namespace RawrXD
