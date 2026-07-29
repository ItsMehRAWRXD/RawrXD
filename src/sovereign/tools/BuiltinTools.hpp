// ============================================================================
// BuiltinTools.hpp - Remaining Built-in Tools for Sovereign IDE
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

struct ToolDefinition {
    std::string name;
    std::string description;
    std::vector<std::string> parameters;
    std::string returnType;
    bool requiresApproval;
    bool isAsync;
};

class BuiltinTools {
public:
    BuiltinTools();
    ~BuiltinTools();

    void RegisterAll(std::function<void(const ToolDefinition&, std::function<std::string(const std::string&)>)> registerFn);

    // File tools
    std::string SearchFiles(const std::string& args);
    std::string ListDirectory(const std::string& args);
    std::string GrepSearch(const std::string& args);
    std::string SemanticSearch(const std::string& args);
    std::string CreateFile(const std::string& args);
    std::string DeleteFile(const std::string& args);
    std::string RenameFile(const std::string& args);
    std::string CopyFile(const std::string& args);
    std::string MoveFile(const std::string& args);
    std::string DownloadFile(const std::string& args);
    std::string FetchWebpage(const std::string& args);

    // Git tools
    std::string GitStatus(const std::string& args);
    std::string GitDiff(const std::string& args);
    std::string GitCommit(const std::string& args);
    std::string GitBranch(const std::string& args);
    std::string GitCheckout(const std::string& args);
    std::string GitLog(const std::string& args);
    std::string GitPush(const std::string& args);
    std::string GitPull(const std::string& args);

    // Debug tools
    std::string DebugStart(const std::string& args);
    std::string DebugStep(const std::string& args);
    std::string DebugBreakpoint(const std::string& args);
    std::string MemoryRead(const std::string& args);
    std::string MemoryWrite(const std::string& args);
    std::string Disassemble(const std::string& args);
    std::string ProfileFunction(const std::string& args);

    // Build tools
    std::string RunTests(const std::string& args);
    std::string BuildProject(const std::string& args);

    struct ToolStats { uint64_t totalCalls; uint64_t totalTools; };
    ToolStats GetStats() const { return stats_; }

private:
    ToolStats stats_;
    mutable std::mutex mutex_;
    
    std::vector<std::string> SplitArgs(const std::string& args) const;
};

} // namespace Sovereign
