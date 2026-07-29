// ============================================================================
// AgenticTools.hpp - Production-Ready 5 Core Agent Tools
// Fully hardened with path validation, error handling, and security checks
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include <chrono>

namespace RawrXD {
namespace Agentic {

// ============================================================================
// Tool Result Structure
// ============================================================================

struct ToolResult {
    bool success = false;
    std::string tool;
    std::string error;
    std::unordered_map<std::string, std::string> data;
    std::unordered_map<std::string, std::string> params;
    double durationMs = 0.0;
};

// ============================================================================
// Search Match Structure
// ============================================================================

struct SearchMatch {
    std::string file;
    int line = 0;
    int column = 0;
    std::string text;
};

// ============================================================================
// Directory Entry Structure
// ============================================================================

struct DirEntry {
    std::string name;
    std::string path;
    bool isDirectory = false;
    uint64_t size = 0;
    std::string modified;
};

// ============================================================================
// Security & Path Validation
// ============================================================================

class ToolSecurity {
public:
    // Check if path is in allowed location (not system directories)
    static bool IsPathAllowed(const std::string& path);
    
    // Check if path is within workspace
    static bool IsWithinWorkspace(const std::string& path, const std::string& workspace);
    
    // Normalize path to absolute form
    static std::string NormalizePath(const std::string& path);
};

// ============================================================================
// 5 Core Tools Implementation
// ============================================================================

class Tools {
public:
    // Tool 1: read_file - Read file contents with safety limits
    // Parameters:
    //   path: File path to read
    //   offset: Starting offset (default 0)
    //   limit: Max bytes to read (0 = unlimited, max 10MB)
    // Returns:
    //   content: File contents
    //   size: Total file size
    //   read: Bytes actually read
    static ToolResult read_file(const std::string& path, size_t offset = 0, size_t limit = 0);
    
    // Tool 2: write_file - Write file contents with atomic operations
    // Parameters:
    //   path: File path to write
    //   content: Content to write
    //   append: If true, append to existing file (default false)
    // Returns:
    //   bytes_written: Number of bytes written
    //   path: Normalized absolute path
    static ToolResult write_file(const std::string& path, const std::string& content, bool append = false);
    
    // Tool 3: run_command - Execute command with timeout and output capture
    // Parameters:
    //   command: Command to execute
    //   args: Command arguments
    //   timeoutMs: Timeout in milliseconds (default 30000)
    //   cwd: Working directory (default current)
    // Returns:
    //   stdout: Standard output
    //   stderr: Standard error
    //   exit_code: Process exit code
    //   timed_out: Whether command timed out
    static ToolResult run_command(const std::string& command, const std::vector<std::string>& args = {}, 
                                   int timeoutMs = 30000, const std::string& cwd = "");
    
    // Tool 4: search_code - Search files with regex patterns
    // Parameters:
    //   pattern: Regex pattern to search for
    //   path: Directory to search in
    //   fileExtensions: List of file extensions to include (empty = all)
    //   caseSensitive: Case-sensitive search (default false)
    //   maxResults: Maximum results to return (default 100)
    // Returns:
    //   files_searched: Number of files searched
    //   files_matched: Number of files with matches
    //   matches_found: Total matches found
    //   matches: JSON array of matches
    static ToolResult search_code(const std::string& pattern, const std::string& path, 
                                   const std::vector<std::string>& fileExtensions = {},
                                   bool caseSensitive = false, int maxResults = 100);
    
    // Tool 5: list_dir - List directory contents with metadata
    // Parameters:
    //   path: Directory path to list
    //   recursive: List recursively (default false)
    //   filter: Regex filter for names (empty = no filter)
    // Returns:
    //   total_files: Total file count
    //   total_dirs: Total directory count
    //   total_size: Total size in bytes
    //   entries_count: Number of entries returned
    //   entries: JSON array of directory entries
    static ToolResult list_dir(const std::string& path, bool recursive = false, 
                                const std::string& filter = "");

private:
    static double GetElapsedMs(const std::chrono::steady_clock::time_point& start);
    static std::string EscapeJson(const std::string& s);
};

// ============================================================================
// Tool Registration Helper
// ============================================================================

class ToolRegistry {
public:
    // Register all 5 core tools with the agentic supervisor
    static void RegisterCoreTools();
};

} // namespace Agentic
} // namespace RawrXD
