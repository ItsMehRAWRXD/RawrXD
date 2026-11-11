//=============================================================================
// ToolRegistry.hpp - Core Tool Definitions for Agentic Operations
// Provides filesystem, process, and search capabilities to the AI agent
//=============================================================================

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <mutex>
#include <unordered_map>

namespace RawrXD {
namespace Tools {

//=============================================================================
// Result Structures
//=============================================================================

struct FileReadResult {
    bool success = false;
    std::string content;
    std::string error;
    size_t bytesRead = 0;
};

struct FileWriteResult {
    bool success = false;
    size_t bytesWritten = 0;
    std::string error;
};

struct CommandResult {
    int exitCode = -1;
    std::string stdout;
    std::string stderr;
    std::string error;
    std::chrono::milliseconds duration{0};
    bool timedOut = false;
};

struct SearchResult {
    std::string filePath;
    int lineNumber = 0;
    int column = 0;
    std::string lineContent;
    int matchScore = 0;
};

struct DirEntry {
    std::string name;
    bool isDirectory = false;
    bool isFile = false;
    size_t size = 0;
    std::chrono::system_clock::time_point modifiedTime;
};

struct DirectoryListResult {
    bool success = false;
    std::vector<DirEntry> entries;
    std::string error;
};

//=============================================================================
// Tool Registry - Singleton providing tool implementations
//=============================================================================

class ToolRegistry {
public:
    static ToolRegistry& Instance();
    
    // Initialize with workspace root
    void Initialize(const std::string& workspaceRoot);
    
    // File Operations
    FileReadResult ReadFile(const std::string& path, 
                           size_t maxSize = 10 * 1024 * 1024); // 10MB default
    FileWriteResult WriteFile(const std::string& path, 
                              const std::string& content,
                              bool createBackup = true);
    bool FileExists(const std::string& path);
    bool DeleteFile(const std::string& path, std::string& error);
    
    // Process Execution
    CommandResult RunCommand(const std::string& command,
                             const std::vector<std::string>& args = {},
                             const std::string& workingDir = "",
                             std::chrono::milliseconds timeout = std::chrono::milliseconds(30000));
    
    // Code Search
    std::vector<SearchResult> SearchCode(const std::string& pattern,
                                            const std::string& root = "",
                                            bool caseSensitive = false,
                                            int maxResults = 100);
    
    std::vector<SearchResult> SearchCodeRegex(const std::string& regexPattern,
                                                const std::string& root = "",
                                                int maxResults = 100);
    
    // Directory Operations
    DirectoryListResult ListDirectory(const std::string& path);
    bool CreateDirectory(const std::string& path, std::string& error);
    bool DeleteDirectory(const std::string& path, bool recursive, std::string& error);
    
    // Path Utilities
    std::string ResolvePath(const std::string& path);
    std::string GetWorkspaceRoot() const { return workspaceRoot_; }
    bool IsPathWithinWorkspace(const std::string& path);
    
    // Safety
    void SetReadOnlyMode(bool enabled) { readOnlyMode_ = enabled; }
    bool IsReadOnly() const { return readOnlyMode_; }
    
    // Statistics
    struct Stats {
        uint64_t filesRead = 0;
        uint64_t filesWritten = 0;
        uint64_t commandsExecuted = 0;
        uint64_t searchesPerformed = 0;
        uint64_t directoriesListed = 0;
    };
    Stats GetStats() const;
    void ResetStats();

private:
    ToolRegistry() = default;
    ~ToolRegistry() = default;
    ToolRegistry(const ToolRegistry&) = delete;
    ToolRegistry& operator=(const ToolRegistry&) = delete;
    
    std::string workspaceRoot_;
    bool readOnlyMode_ = false;
    mutable std::mutex mutex_;
    Stats stats_;
    
    // Path validation
    bool ValidatePath(const std::string& path, std::string& error);
    std::string NormalizePath(const std::string& path);
};

//=============================================================================
// Convenience Functions (C-style interface for easy binding)
//=============================================================================

// File operations
FileReadResult Tool_ReadFile(const std::string& path);
FileWriteResult Tool_WriteFile(const std::string& path, const std::string& content);
bool Tool_FileExists(const std::string& path);

// Process execution
CommandResult Tool_RunCommand(const std::string& command, 
                            const std::vector<std::string>& args = {});

// Search
std::vector<SearchResult> Tool_SearchCode(const std::string& pattern, 
                                           const std::string& root = "");

// Directory
DirectoryListResult Tool_ListDirectory(const std::string& path);

} // namespace Tools
} // namespace RawrXD
