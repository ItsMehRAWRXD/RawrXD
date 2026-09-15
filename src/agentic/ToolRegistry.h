// =============================================================================
// ToolRegistry.h — X-Macro Tool Registry & LLM Schema Generator
// =============================================================================
// Defines the interface between LLM intent and engine execution.
// Adding a tool here automatically updates:
//   1. The JSON schema sent to the LLM (OpenAI function-calling format)
//   2. The dispatch logic in AgentOrchestrator
//   3. The system prompt injected into every conversation
//
// Uses the X-Macro pattern for single-source-of-truth tool definitions.
// =============================================================================
#pragma once

#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace RawrXD {
namespace Agent {

// ---------------------------------------------------------------------------
// X-Macro: AGENT_TOOLS_X(M)
// M(internal_name, description)
//
// Parameter schemas are defined programmatically in InitDescriptors().
// Each tool maps 1:1 to an OpenAI function-calling tool definition.
// ---------------------------------------------------------------------------
#define AGENT_TOOLS_X(M) \
    M(read_file,        "Read the content of a file at a specific path. Returns UTF-8 text.") \
    M(write_file,       "Create a new file or overwrite an existing one with the provided content.") \
    M(replace_in_file,  "Search and replace a block of text within a file. Uses exact string matching.") \
    M(execute_command,  "Run a shell command in the terminal. Returns stdout, stderr, and exit code.") \
    M(search_code,      "Fast regex/literal search across the codebase. Uses AVX-512 SIMD accelerator when available.") \
    M(get_diagnostics,  "Retrieve current compiler/LSP errors and warnings for a specific file or all files.") \
    M(list_directory,   "List files and subdirectories at a given path.") \
    M(get_coverage,     "Retrieve BBCov/DiffCov coverage data for a file or function to verify logic path changes.") \
    M(run_build,        "Trigger a CMake build with specified target and configuration.") \
    M(apply_hotpatch,   "Apply a runtime hotpatch through the unified hotpatch manager (memory, byte-level, or server layer).") \
    M(disk_recovery,    "Control the hardware disk recovery agent for dying WD My Book USB bridges (scan, init, extract key, run, abort, stats).") \
    M(code_edit,        "Edit source code with line-based replacement and automatic backup. Legacy adapter to RawrXD_ToolRegistry.") \
    M(build_project,    "Build the project using the configured build system. Legacy adapter to RawrXD_ToolRegistry.") \
    M(static_analysis,  "Run static analysis (clang-tidy or custom rules) on source files. Legacy adapter to RawrXD_ToolRegistry.") \
    M(git_operation,    "Execute git commands safely with sandboxing. Legacy adapter to RawrXD_ToolRegistry.") \
    M(ssa_lift,         "Lift binary code to Static Single Assignment form for reverse engineering analysis.") \
    M(byte_patch,       "Apply byte-level patches to files or memory regions via the unified hotpatch manager.") \
    M(memory_patch,     "Apply in-memory patches to running processes via the unified hotpatch manager.")

// ---------------------------------------------------------------------------
// Tool ID enum — auto-generated from X-Macro
// ---------------------------------------------------------------------------
enum class ToolId : uint32_t {
    #define ENUM_ENTRY(tool_name_, tool_desc_) tool_name_,
    AGENT_TOOLS_X(ENUM_ENTRY)
    #undef ENUM_ENTRY
    _COUNT
};

// ---------------------------------------------------------------------------
// Tool execution result (no exceptions — follows PatchResult pattern)
// ---------------------------------------------------------------------------
struct ToolExecResult {
    bool success;
    std::string output;
    int exit_code;
    double elapsed_ms;

    static ToolExecResult ok(const std::string& out, double ms = 0.0) {
        return {true, out, 0, ms};
    }
    static ToolExecResult error(const std::string& msg, int code = -1) {
        return {false, msg, code, 0.0};
    }
};

// ---------------------------------------------------------------------------
// Normalized tool contract — single authority for ALL tool dispatch
// ---------------------------------------------------------------------------
enum class AgentToolKind : uint32_t {
    Unknown = 0,
    ReadFile, WriteFile, ListDirectory, SearchText, CodeEdit,
    ApplyPatch, RunProcess, ShellCommand, BuildProject,
    RunTests, StaticAnalysis,
    GitStatus, GitDiff, GitOperation, GitCheckpoint,
    SSALift, BytePatch, MemoryPatch
};

struct AgentToolRequest {
    AgentToolKind kind = AgentToolKind::Unknown;
    std::string tool_name;           // LLM-facing name (from X-Macro)
    json args;                       // Raw JSON args from LLM
    std::string caller_surface;      // "cli", "gui", "headless", "swarm", "agentic_loop"
    std::string session_id;          // For tracing
    uint64_t    sequence_id = 0;     // Monotonic per-session
};

struct AgentToolResult {
    bool success = false;
    std::string output;
    int exit_code = 0;
    double elapsed_ms = 0.0;
    AgentToolKind kind = AgentToolKind::Unknown;
    std::string tool_name;

    static AgentToolResult ok(const std::string& out, double ms = 0.0) {
        return {true, out, 0, ms, AgentToolKind::Unknown, ""};
    }
    static AgentToolResult error(const std::string& msg, int code = -1) {
        return {false, msg, code, 0.0, AgentToolKind::Unknown, ""};
    }
};

enum class AgentToolSurface : uint8_t {
    CLI = 0,
    GUI = 1,
    Headless = 2,
    Swarm = 3,
    AgenticLoop = 4,
    Unknown = 255
};

// ---------------------------------------------------------------------------
// Authority metrics — gate: RAWRXD_AGENT_TOOL_AUTHORITY_001
// ---------------------------------------------------------------------------
struct AgentToolAuthorityMetrics {
    std::atomic<uint64_t> reach_cli{0};
    std::atomic<uint64_t> reach_gui{0};
    std::atomic<uint64_t> reach_headless{0};
    std::atomic<uint64_t> reach_swarm{0};
    std::atomic<uint64_t> reach_agentic_loop{0};

    std::atomic<uint64_t> bypass_cli{0};
    std::atomic<uint64_t> bypass_gui{0};
    std::atomic<uint64_t> bypass_headless{0};
    std::atomic<uint64_t> bypass_swarm{0};
    std::atomic<uint64_t> bypass_agentic_loop{0};

    std::atomic<uint64_t> unknown_tool_dispatches{0};
    std::atomic<uint64_t> validation_failures{0};
    std::atomic<uint64_t> total_dispatches{0};

    bool GatePass() const {
        return bypass_cli.load() == 0 && bypass_gui.load() == 0 &&
               bypass_headless.load() == 0 && bypass_swarm.load() == 0 &&
               bypass_agentic_loop.load() == 0 &&
               reach_cli.load() >= 1 && reach_gui.load() >= 1 &&
               reach_headless.load() >= 1 && reach_swarm.load() >= 1 &&
               reach_agentic_loop.load() >= 1;
    }
};

// ---------------------------------------------------------------------------
// Tool handler function pointer (no std::function in hot path)
// ---------------------------------------------------------------------------
using ToolHandler = ToolExecResult(*)(const json& args);

// ---------------------------------------------------------------------------
// ToolDescriptor — runtime metadata for a single tool
// ---------------------------------------------------------------------------
struct ToolDescriptor {
    const char* name;
    const char* description;
    json params_schema;
    ToolHandler handler;
    uint64_t invocation_count = 0;  // Protected by registry mutex
    uint64_t error_count = 0;       // Protected by registry mutex
};

// ---------------------------------------------------------------------------
// AgentToolRegistry — singleton registry with LLM schema generation
// ---------------------------------------------------------------------------
class AgentToolRegistry {
public:
    static AgentToolRegistry& Instance();

    // Generate OpenAI-compatible tool schemas for the LLM
    json GetToolSchemas() const;

    // Generate the full system prompt with tool documentation
    std::string GetSystemPrompt(const std::string& cwd,
                                const std::vector<std::string>& openFiles) const;

    // Dispatch a tool call by name (legacy entrypoint — wrapped by normalized contract)
    ToolExecResult Dispatch(const std::string& tool_name, const json& args);

    // Normalized dispatch — ALL callers must use this for authority gate tracking
    AgentToolResult Dispatch(const AgentToolRequest& request);

    // Register a handler for a tool (called during init)
    void RegisterHandler(const std::string& tool_name, ToolHandler handler);

    // Legacy adapter wiring — absorbs RawrXD_ToolRegistry capabilities
    void RegisterLegacyAdapter(const std::string& tool_name,
                                std::function<ToolExecResult(const json&)> adapter);

    // Authority metrics
    const AgentToolAuthorityMetrics& GetAuthorityMetrics() const { return m_authorityMetrics; }

    // Get tool names
    std::vector<std::string> ListTools() const;

    // Get stats
    uint64_t GetTotalInvocations() const;
    uint64_t GetTotalErrors() const;

    // Validate args against schema
    bool ValidateArgs(const std::string& tool_name, const json& args,
                      std::string& error) const;

private:
    AgentToolRegistry();
    ~AgentToolRegistry() = default;

    void InitDescriptors();

    mutable std::mutex m_mutex;
    std::vector<ToolDescriptor> m_tools;
    std::unordered_map<std::string, size_t> m_nameIndex;
    std::unordered_map<std::string, std::function<ToolExecResult(const json&)>> m_legacyAdapters;

    AgentToolAuthorityMetrics m_authorityMetrics;

};

} // namespace Agent
} // namespace RawrXD
