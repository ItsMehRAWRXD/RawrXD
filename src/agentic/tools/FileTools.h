// ============================================================================
// FileTools.h - Production File Operations for Agentic System
// ============================================================================
// Declares: read_file, write_file, list_dir, search_code, run_command
// Security: Path validation, sandboxing, backup before writes
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>

namespace RawrXD {
namespace Agentic {
namespace Tools {

// Tool result structure
struct ToolResult {
    bool success = false;
    std::string error;
    std::unordered_map<std::string, std::string> data;
};

// ============================================================================
// Tool: read_file
// ============================================================================
struct ReadFileParams {
    std::string path;           // File path to read
    int64_t offset = 0;         // Starting offset (0 = beginning)
    int64_t limit = -1;         // Max bytes to read (-1 = all)
};

ToolResult ReadFile(const ReadFileParams& params);

// ============================================================================
// Tool: write_file
// ============================================================================
struct WriteFileParams {
    std::string path;           // File path to write
    std::string content;        // Content to write
    bool append = false;        // Append mode
    bool createBackup = true;   // Create backup before write
};

ToolResult WriteFile(const WriteFileParams& params);

// ============================================================================
// Tool: list_dir
// ============================================================================
struct ListDirParams {
    std::string path;           // Directory path
    std::string pattern;        // File pattern filter (e.g., "*.cpp")
    int limit = 100;            // Max entries to return
    bool recursive = false;     // Recursive listing
};

ToolResult ListDir(const ListDirParams& params);

// ============================================================================
// Tool: search_code
// ============================================================================
struct MatchLine {
    int number;
    std::string content;
};

struct SearchMatch {
    std::string file;
    std::vector<MatchLine> lines;
};

struct SearchCodeParams {
    std::string path;           // Directory to search
    std::string query;          // Search query (regex)
    std::string filePattern;    // File pattern (e.g., "*.cpp")
    bool caseSensitive = false; // Case sensitive search
    int limit = 100;            // Max matches
};

ToolResult SearchCode(const SearchCodeParams& params);

// Internal search helpers
void SearchDirectory(const std::string& path, const std::regex& pattern,
                     const std::string& filePattern,
                     std::vector<SearchMatch>& matches, int& matchCount, int limit);
void SearchFile(const std::string& path, const std::regex& pattern,
                std::vector<SearchMatch>& matches, int& matchCount, int limit);

// ============================================================================
// Tool: run_command
// ============================================================================
struct RunCommandParams {
    std::string command;        // Command to execute
    std::string workingDir;     // Working directory
    uint32_t timeoutMs = 30000; // Timeout in milliseconds
};

ToolResult RunCommand(const RunCommandParams& params);

// ============================================================================
// Security Functions
// ============================================================================
void InitializeSecurity(const std::vector<std::string>& allowedDirs);
bool ValidatePath(const std::string& path, std::string& error);
std::string GetBackupPath(const std::string& original);

// ============================================================================
// Utility Functions
// ============================================================================
bool FileExists(const std::string& path);
bool DirectoryExists(const std::string& path);
std::string GetFileExtension(const std::string& path);
std::string GetFileName(const std::string& path);
std::string GetDirectory(const std::string& path);

} // namespace Tools
} // namespace Agentic
} // namespace RawrXD
