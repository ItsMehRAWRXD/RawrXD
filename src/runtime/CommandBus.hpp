//==============================================================================
// CommandBus.hpp / CommandBus.cpp
// Central command dispatcher for rawrxd.exe
// Phase 15B: Service Architecture
//
// All CLI commands route through here. No subsystem owns the process.
// The bus translates user input → service calls → JSON output.
//==============================================================================

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <map>
#include <string_view>

namespace RawrXD::Runtime {

//==============================================================================
// Command Result
//==============================================================================
struct CommandResult {
    int exitCode = 0;
    std::string output;
    std::string error;
    bool jsonOutput = false;
    
    // Performance telemetry
    float executionTimeMs = 0.0f;
    uint64_t memoryUsed = 0;
};

//==============================================================================
// Command Handler Signature
//==============================================================================
using CommandHandler = std::function<CommandResult(const std::vector<std::string>& args)>;

//==============================================================================
// Command Bus
// Singleton dispatcher. Thread-safe. No dependencies on implementation details.
//==============================================================================
class CommandBus {
public:
    static CommandBus& Instance();
    
    // Registration
    void Register(const std::string& name, CommandHandler handler);
    void RegisterAlias(const std::string& alias, const std::string& target);
    
    // Execution
    CommandResult Execute(const std::string& command, 
                          const std::vector<std::string>& args);
    
    // Batch execution (for agentic workflows)
    std::vector<CommandResult> ExecuteBatch(
        const std::vector<std::pair<std::string, std::vector<std::string>>>& commands
    );
    
    // Introspection
    std::vector<std::string> ListCommands() const;
    bool HasCommand(const std::string& name) const;
    std::string GetHelp(const std::string& command) const;
    
    // Lifecycle
    void Initialize();
    void Shutdown();
    bool IsReady() const;

private:
    CommandBus() = default;
    ~CommandBus() = default;
    
    CommandBus(const CommandBus&) = delete;
    CommandBus& operator=(const CommandBus&) = delete;
    
    struct CommandEntry {
        CommandHandler handler;
        std::string help;
        std::string category;  // "inference", "codex", "compiler", "system"
    };
    
    std::map<std::string, CommandEntry> commands_;
    std::map<std::string, std::string> aliases_;
    bool ready_ = false;
};

} // namespace RawrXD::Runtime
