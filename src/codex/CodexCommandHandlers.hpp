// ============================================================================
// RawrXD Codex Command Handlers
// Integrates Codex commands into IDE CommandRouter
// ============================================================================

#pragma once
#include "CodexCLI.hpp"
#include "CodexEventBus.hpp"
#include <string>
#include <functional>
#include <memory>

namespace RawrXD {
namespace Codex {

// Command context for IDE integration
struct CodexCommandContext {
    std::string command;           // e.g., "complete", "stream", "explain"
    std::string args;              // Command arguments
    std::string selectedText;      // Currently selected text in editor
    std::string filePath;          // Current file path
    int lineNumber = 0;            // Current line number
    
    // Output callback for IDE
    std::function<void(const std::string&)> outputFn;
    std::function<void(const std::string&)> errorFn;
};

// Command result
struct CodexCommandResult {
    bool success = false;
    std::string message;
    std::string output;
    
    static CodexCommandResult ok(const std::string& msg = "") {
        return {true, msg, ""};
    }
    static CodexCommandResult error(const std::string& msg) {
        return {false, msg, ""};
    }
};

// Codex command router - integrates with IDE command system
class CodexCommandRouter {
public:
    CodexCommandRouter();
    ~CodexCommandRouter();
    
    // Initialize with CLI backend
    bool Initialize(std::shared_ptr<CodexCLI> cli);
    
    // Register with IDE command system
    void RegisterWithIDE();
    
    // Command handlers
    CodexCommandResult HandleComplete(const CodexCommandContext& ctx);
    CodexCommandResult HandleStream(const CodexCommandContext& ctx);
    CodexCommandResult HandleExplain(const CodexCommandContext& ctx);
    CodexCommandResult HandleRefactor(const CodexCommandContext& ctx);
    CodexCommandResult HandleCompleteLine(const CodexCommandContext& ctx);
    CodexCommandResult HandleCompleteBlock(const CodexCommandContext& ctx);
    CodexCommandResult HandleGenerateTests(const CodexCommandContext& ctx);
    CodexCommandResult HandleGenerateDocs(const CodexCommandContext& ctx);
    CodexCommandResult HandleFixErrors(const CodexCommandContext& ctx);
    CodexCommandResult HandleOptimize(const CodexCommandContext& ctx);
    
    // Generic handler for all /codex commands
    CodexCommandResult HandleCommand(const std::string& subcommand, const CodexCommandContext& ctx);
    
    // Check if initialized
    bool IsInitialized() const { return m_initialized; }
    
    // Get CLI backend
    std::shared_ptr<CodexCLI> GetCLI() const { return m_cli; }

private:
    std::shared_ptr<CodexCLI> m_cli;
    bool m_initialized = false;
    
    // Helper to build prompt from context
    std::string BuildPrompt(const std::string& template_, const CodexCommandContext& ctx);
    
    // Output helpers
    void Output(const CodexCommandContext& ctx, const std::string& text);
    void OutputChunk(const CodexCommandContext& ctx, const std::string& chunk);
    void Error(const CodexCommandContext& ctx, const std::string& text);
};

// FNV-1a hash constants for Codex commands
namespace CodexCommandHashes {
    constexpr uint64_t Complete = 0x8F4A2B1C8D7E6F5AULL;      // "/codex complete"
    constexpr uint64_t Stream = 0x3E7D8A9F2B1C4D6EULL;        // "/codex stream"
    constexpr uint64_t Explain = 0xC5B1E4D2A9F3C7E8ULL;       // "/codex explain"
    constexpr uint64_t Refactor = 0xA9F3C7E87B2D5F1AULL;      // "/codex refactor"
    constexpr uint64_t CompleteLine = 0x7B2D5F1A3E7D8A9FULL;   // "/codex complete-line"
    constexpr uint64_t CompleteBlock = 0x3E7D8A9F7B2D5F1AULL;  // "/codex complete-block"
    constexpr uint64_t GenerateTests = 0x5F1A3E7D8A9F2B1CULL;    // "/codex generate-tests"
    constexpr uint64_t GenerateDocs = 0x8A9F2B1C5F1A3E7DULL;    // "/codex generate-docs"
    constexpr uint64_t FixErrors = 0x2B1C5F1A8A9F3E7DULL;      // "/codex fix-errors"
    constexpr uint64_t Optimize = 0xF3E7D8A9F2B1C5F1ULL;       // "/codex optimize"
}

} // namespace Codex
} // namespace RawrXD
