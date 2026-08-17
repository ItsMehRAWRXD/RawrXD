//==============================================================================
// CommandBus.cpp
// Central command dispatcher implementation
// Phase 15B: Service Architecture
//==============================================================================

#include "CommandBus.hpp"
#include "../cli/cli_entrypoints.hpp"

#include <windows.h>
#include <chrono>
#include <sstream>
#include <nlohmann/json.hpp>

namespace RawrXD::Runtime {

//==============================================================================
// Singleton
//==============================================================================
CommandBus& CommandBus::Instance() {
    static CommandBus instance;
    return instance;
}

//==============================================================================
// Lifecycle
//==============================================================================
void CommandBus::Initialize() {
    if (ready_) return;
    
    // Register all commands
    Register("run", [](const std::vector<std::string>& args) {
        CommandResult result;
        auto start = std::chrono::high_resolution_clock::now();
        
        // Convert to argc/argv for legacy compatibility
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>("rawrxd"));
        for (const auto& arg : args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        
        result.exitCode = RawrXD::CLI::RunInferenceCLI(
            static_cast<int>(argv.size()), 
            argv.data()
        );
        
        auto end = std::chrono::high_resolution_clock::now();
        result.executionTimeMs = std::chrono::duration<float, std::milli>(end - start).count();
        result.jsonOutput = true;
        
        return result;
    });
    
    Register("benchmark", [](const std::vector<std::string>& args) {
        CommandResult result;
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>("rawrxd"));
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        
        result.exitCode = RawrXD::CLI::RunBenchmarkCLI(
            static_cast<int>(argv.size()), 
            argv.data()
        );
        result.jsonOutput = true;
        return result;
    });
    
    Register("chat", [](const std::vector<std::string>& args) {
        CommandResult result;
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>("rawrxd"));
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        
        result.exitCode = RawrXD::CLI::RunChatCLI(
            static_cast<int>(argv.size()), 
            argv.data()
        );
        result.jsonOutput = true;
        return result;
    });
    
    Register("serve", [](const std::vector<std::string>& args) {
        CommandResult result;
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>("rawrxd"));
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        
        result.exitCode = RawrXD::CLI::RunServeCLI(
            static_cast<int>(argv.size()), 
            argv.data()
        );
        result.jsonOutput = true;
        return result;
    });
    
    Register("compile", [](const std::vector<std::string>& args) {
        CommandResult result;
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>("rawrxd"));
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        
        result.exitCode = RawrXD::CLI::RunCompilerCLI(
            static_cast<int>(argv.size()), 
            argv.data()
        );
        result.jsonOutput = true;
        return result;
    });
    
    Register("build", [](const std::vector<std::string>& args) {
        CommandResult result;
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>("rawrxd"));
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        
        result.exitCode = RawrXD::CLI::RunBuildCLI(
            static_cast<int>(argv.size()), 
            argv.data()
        );
        result.jsonOutput = true;
        return result;
    });
    
    Register("assemble", [](const std::vector<std::string>& args) {
        CommandResult result;
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>("rawrxd"));
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        
        result.exitCode = RawrXD::CLI::RunAssembleCLI(
            static_cast<int>(argv.size()), 
            argv.data()
        );
        result.jsonOutput = true;
        return result;
    });
    
    Register("codex", [](const std::vector<std::string>& args) {
        CommandResult result;
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>("rawrxd"));
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        
        result.exitCode = RawrXD::CLI::RunCodexCLI(
            static_cast<int>(argv.size()), 
            argv.data()
        );
        result.jsonOutput = true;
        return result;
    });
    
    Register("agent", [](const std::vector<std::string>& args) {
        CommandResult result;
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>("rawrxd"));
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        
        result.exitCode = RawrXD::CLI::RunAgentCLI(
            static_cast<int>(argv.size()), 
            argv.data()
        );
        result.jsonOutput = true;
        return result;
    });
    
    Register("swarm", [](const std::vector<std::string>& args) {
        CommandResult result;
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>("rawrxd"));
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        
        result.exitCode = RawrXD::CLI::RunSwarmCLI(
            static_cast<int>(argv.size()), 
            argv.data()
        );
        result.jsonOutput = true;
        return result;
    });
    
    Register("system", [](const std::vector<std::string>& args) {
        CommandResult result;
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>("rawrxd"));
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        
        result.exitCode = RawrXD::CLI::RunUnifiedCLI(
            static_cast<int>(argv.size()), 
            argv.data()
        );
        result.jsonOutput = true;
        return result;
    });
    
    Register("status", [](const std::vector<std::string>&) {
        CommandResult result;
        result.exitCode = RawrXD::CLI::RunStatusCLI();
        result.jsonOutput = true;
        return result;
    });
    
    Register("diagnostics", [](const std::vector<std::string>&) {
        CommandResult result;
        result.exitCode = RawrXD::CLI::RunDiagnosticsCLI();
        result.jsonOutput = true;
        return result;
    });
    
    // Aliases
    RegisterAlias("r", "run");
    RegisterAlias("b", "benchmark");
    RegisterAlias("c", "compile");
    RegisterAlias("a", "agent");
    RegisterAlias("s", "status");
    RegisterAlias("d", "diagnostics");
    
    ready_ = true;
    
    OutputDebugStringA("[CommandBus] Initialized with ");
    char buf[32];
    sprintf_s(buf, "%zu", commands_.size());
    OutputDebugStringA(buf);
    OutputDebugStringA(" commands\n");
}

void CommandBus::Shutdown() {
    commands_.clear();
    aliases_.clear();
    ready_ = false;
}

bool CommandBus::IsReady() const {
    return ready_;
}

//==============================================================================
// Registration
//==============================================================================
void CommandBus::Register(const std::string& name, CommandHandler handler) {
    CommandEntry entry;
    entry.handler = handler;
    entry.category = "general";
    commands_[name] = entry;
}

void CommandBus::RegisterAlias(const std::string& alias, const std::string& target) {
    aliases_[alias] = target;
}

//==============================================================================
// Execution
//==============================================================================
CommandResult CommandBus::Execute(const std::string& command,
                                   const std::vector<std::string>& args) {
    if (!ready_) {
        CommandResult result;
        result.exitCode = -1;
        result.error = "CommandBus not initialized";
        return result;
    }
    
    // Resolve alias
    std::string resolved = command;
    auto aliasIt = aliases_.find(command);
    if (aliasIt != aliases_.end()) {
        resolved = aliasIt->second;
    }
    
    auto it = commands_.find(resolved);
    if (it == commands_.end()) {
        CommandResult result;
        result.exitCode = -2;
        result.error = "Unknown command: " + command;
        result.error += "\nUse 'rawrxd status' for available commands";
        return result;
    }
    
    return it->second.handler(args);
}

std::vector<CommandResult> CommandBus::ExecuteBatch(
    const std::vector<std::pair<std::string, std::vector<std::string>>>& commands
) {
    std::vector<CommandResult> results;
    results.reserve(commands.size());
    
    for (const auto& [cmd, args] : commands) {
        results.push_back(Execute(cmd, args));
    }
    
    return results;
}

//==============================================================================
// Introspection
//==============================================================================
std::vector<std::string> CommandBus::ListCommands() const {
    std::vector<std::string> result;
    for (const auto& [name, _] : commands_) {
        result.push_back(name);
    }
    return result;
}

bool CommandBus::HasCommand(const std::string& name) const {
    return commands_.find(name) != commands_.end() ||
           aliases_.find(name) != aliases_.end();
}

std::string CommandBus::GetHelp(const std::string& command) const {
    auto it = commands_.find(command);
    if (it != commands_.end()) {
        return it->second.help;
    }
    return "No help available for: " + command;
}

} // namespace RawrXD::Runtime
