// ============================================================================
// RawrXD_UnifiedAgent.hpp — ONE COMMAND TO RULE THEM ALL
// ============================================================================
// Unified autonomous agent that integrates ALL RawrXD components:
//   - Model loading & streaming inference
//   - Native toolchain (compile, patch, disasm)
//   - Ghost text inline completions
//   - Tool registry (GitHub, file ops, memory)
//   - Agentic reasoning loops
//
// Usage:
//   rawrxd "compile hello.c and run it"
//   rawrxd "patch app.exe to return 0"
//   rawrxd "disassemble malware.exe"
//   rawrxd "find buffer overflow in this code"
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <future>
#include <nlohmann/json.hpp>

namespace RawrXD::Agentic {

// Forward declarations
class ModelLoader;
class StreamingClient;
class ToolRegistry;
class SlashCommandParser;
class AgenticEngine;
class GhostTextProvider;

// ============================================================================
// Intent Types — What the user wants to do
// ============================================================================
enum class IntentType {
    UNKNOWN,
    COMPILE,        // Compile code to executable
    PATCH,          // Patch binary
    DISASSEMBLE,    // Disassemble binary
    ANALYZE,        // Analyze code/binary
    SEARCH,         // Search GitHub/code
    EDIT,           // Edit files
    AUTONOMOUS,     // Complex multi-step task
    QUERY,          // General question
    GHOST_COMPLETE, // Ghost text completion
    TOOL_CALL       // Direct tool execution
};

// ============================================================================
// Intent — Parsed user request
// ============================================================================
struct Intent {
    IntentType type = IntentType::UNKNOWN;
    std::string description;           // Original request
    std::string target;               // File/target to operate on
    std::string language;             // Detected language
    nlohmann::json parameters;        // Additional parameters
    float confidence = 0.0f;          // AI confidence 0-1
    std::vector<std::string> steps;   // Planned steps for autonomous mode
};

// ============================================================================
// Execution Result
// ============================================================================
struct ExecutionResult {
    bool success = false;
    int exitCode = 0;
    std::string output;
    std::string error;
    std::vector<std::string> filesCreated;
    std::vector<std::string> filesModified;
    nlohmann::json metadata;
};

// ============================================================================
// Ghost Text Request/Response
// ============================================================================
struct GhostTextRequest {
    std::string prefix;
    std::string suffix;
    std::string filePath;
    std::string languageId;
    int cursorLine = 0;
    int cursorColumn = 0;
};

struct GhostTextResponse {
    std::string text;
    float confidence = 0.0f;
    bool isComplete = false;
};

// ============================================================================
// Unified Agent — ONE COMMAND INTERFACE
// ============================================================================
class RawrXDUnifiedAgent {
public:
    RawrXDUnifiedAgent();
    ~RawrXDUnifiedAgent();

    // Initialize all subsystems
    bool Initialize();
    void Shutdown();

    // =========================================================================
    // MAIN ENTRY POINT — One command to do everything
    // =========================================================================
    ExecutionResult Execute(const std::string& naturalLanguageRequest);

    // Specific handlers (called by Execute based on intent)
    ExecutionResult HandleCompile(const Intent& intent);
    ExecutionResult HandlePatch(const Intent& intent);
    ExecutionResult HandleDisassemble(const Intent& intent);
    ExecutionResult HandleAnalyze(const Intent& intent);
    ExecutionResult HandleSearch(const Intent& intent);
    ExecutionResult HandleEdit(const Intent& intent);
    ExecutionResult HandleAutonomous(const Intent& intent);
    ExecutionResult HandleQuery(const Intent& intent);

    // Ghost text inline completion
    GhostTextResponse GetGhostCompletion(const GhostTextRequest& request);
    void StreamGhostCompletion(const GhostTextRequest& request,
                                std::function<void(const std::string&)> onToken);

    // Direct tool execution
    ExecutionResult ExecuteTool(const std::string& toolName,
                                 const nlohmann::json& params);

    // Status & info
    std::string GetStatus() const;
    std::vector<std::string> GetAvailableCapabilities() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// Ghost Text Provider — IDE Integration
// ============================================================================
class GhostTextProvider {
public:
    GhostTextProvider(RawrXDUnifiedAgent* agent);
    ~GhostTextProvider();

    // Called by IDE when user pauses typing
    void RequestCompletion(const GhostTextRequest& request,
                          std::function<void(const GhostTextResponse&)> callback);

    // Cancel pending completion
    void Cancel();

    // Configuration
    void SetEnabled(bool enabled);
    void SetDelayMs(int ms);
    void SetMaxTokens(int tokens);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick compile: source file -> executable
ExecutionResult QuickCompile(const std::string& sourceFile,
                              const std::string& outputName = "");

// Quick patch: binary + patch description -> patched binary
ExecutionResult QuickPatch(const std::string& binaryFile,
                            const std::string& patchDescription);

// Quick disasm: binary -> assembly
ExecutionResult QuickDisasm(const std::string& binaryFile,
                             const std::string& outputFile = "");

// Quick analyze: file -> analysis report
ExecutionResult QuickAnalyze(const std::string& targetFile);

// ============================================================================
// CLI Entry Point
// ============================================================================
int RawrXDMain(int argc, char** argv);

} // namespace RawrXD::Agentic

// ============================================================================
// C API for external integration
// ============================================================================
extern "C" {

// Create/destroy agent instance
void* RawrXD_CreateAgent();
void RawrXD_DestroyAgent(void* agent);

// Execute natural language command
// Returns JSON string (caller must free with RawrXD_FreeString)
char* RawrXD_Execute(void* agent, const char* request);

// Get ghost text completion
char* RawrXD_GetGhostCompletion(void* agent, const char* requestJson);

// Free string returned by other functions
void RawrXD_FreeString(char* str);

// Get last error message
char* RawrXD_GetLastError();

} // extern "C"
