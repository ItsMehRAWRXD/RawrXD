// ============================================================================
// CoT Unified Execution Integration
// ============================================================================
// Bridges CoT Multi-Mode Engine with Unified Execution ABI
// ============================================================================

#include "unified_execution_abi.hpp"
#include "../cot/cot_multi_mode_engine.hpp"
#include <sstream>

namespace RawrXD {
namespace CLI {

// ============================================================================
// CoT Command Handlers for Unified ABI
// ============================================================================

class CoTUnifiedCommands {
public:
    static CLIExecutionResult ExecuteCoT(const ExecutionContext& ctx) {
        auto start = std::chrono::steady_clock::now();
        
        // Parse arguments
        std::string query;
        std::vector<CoT::ReasoningMode> modes;
        
        // Check for mode specification
        if (!ctx.args.empty() && ctx.args[0] == "--modes" && ctx.args.size() >= 3) {
            std::string modesStr = ctx.args[1];
            modes = CoT::CoTCLIHelper::ParseModeString(modesStr);
            // Reconstruct query from remaining args
            for (size_t i = 2; i < ctx.args.size(); ++i) {
                if (!query.empty()) query += " ";
                query += ctx.args[i];
            }
        } else if (!ctx.args.empty() && ctx.args[0] == "--single" && ctx.args.size() >= 3) {
            std::string modeStr = ctx.args[1];
            auto parsed = CoT::CoTCLIHelper::ParseModeString(modeStr);
            if (!parsed.empty()) {
                modes.push_back(parsed[0]);
            }
            for (size_t i = 2; i < ctx.args.size(); ++i) {
                if (!query.empty()) query += " ";
                query += ctx.args[i];
            }
        } else if (!ctx.args.empty() && ctx.args[0] == "--chain" && ctx.args.size() >= 3) {
            std::string chainType = ctx.args[1];
            if (chainType == "default" || chainType == "full") {
                modes = CoT::CoTCLIHelper::GetDefaultChain();
            } else if (chainType == "code" || chainType == "review") {
                modes = CoT::CoTCLIHelper::GetCodeReviewChain();
            } else if (chainType == "decision") {
                modes = CoT::CoTCLIHelper::GetDecisionChain();
            } else if (chainType == "creative") {
                modes = CoT::CoTCLIHelper::GetCreativeChain();
            }
            for (size_t i = 2; i < ctx.args.size(); ++i) {
                if (!query.empty()) query += " ";
                query += ctx.args[i];
            }
        } else {
            // Default: treat all args as query with default chain
            for (const auto& arg : ctx.args) {
                if (!query.empty()) query += " ";
                query += arg;
            }
            modes = CoT::CoTCLIHelper::GetDefaultChain();
        }
        
        CLIExecutionResult result;
        result.command = ctx.command;
        result.backendUsed = "ollama";
        
        if (query.empty()) {
            result.success = false;
            result.error = "No query provided. Usage: /cot <query> or /cot --modes <modes> <query>";
            return result;
        }
        
        if (modes.empty()) {
            result.success = false;
            result.error = "No valid modes specified";
            return result;
        }
        
        // Execute CoT chain
        CoT::MultiModeCoTEngine engine;
        engine.SetModelEndpoint("http://localhost:11434");
        engine.SetDefaultModel("llama3.2:3b");
        
        auto cotResult = engine.ExecuteChain(query, modes);
        
        auto end = std::chrono::steady_clock::now();
        result.executionMs = std::chrono::duration<double, std::milli>(end - start).count();
        
        // Convert CoTResult to CLIExecutionResult
        result.success = cotResult.success;
        result.output = engine.FormatResultForCLI(cotResult);
        result.error = cotResult.error;
        
        // Add metadata
        result.metadata["steps"] = cotResult.steps.size();
        result.metadata["overallConfidence"] = cotResult.overallConfidence;
        result.metadata["totalTokens"] = cotResult.totalTokens;
        result.metadata["modes"] = CoT::CoTCLIHelper::ModesToString(modes);
        
        // Add artifact
        result.artifacts.push_back(cotResult.ToJSON().dump());
        
        return result;
    }
    
    // Individual mode handlers
    static CLIExecutionResult ExecuteThinker(const ExecutionContext& ctx) {
        return ExecuteSingleMode(ctx, CoT::ReasoningMode::THINKER, "thinker");
    }
    
    static CLIExecutionResult ExecuteAuditor(const ExecutionContext& ctx) {
        return ExecuteSingleMode(ctx, CoT::ReasoningMode::AUDITOR, "auditor");
    }
    
    static CLIExecutionResult ExecuteReviewer(const ExecutionContext& ctx) {
        return ExecuteSingleMode(ctx, CoT::ReasoningMode::REVIEWER, "reviewer");
    }
    
    static CLIExecutionResult ExecuteResearcher(const ExecutionContext& ctx) {
        return ExecuteSingleMode(ctx, CoT::ReasoningMode::RESEARCHER, "researcher");
    }
    
    static CLIExecutionResult ExecuteArgueFor(const ExecutionContext& ctx) {
        return ExecuteSingleMode(ctx, CoT::ReasoningMode::ARGUE_FOR, "arguefor");
    }
    
    static CLIExecutionResult ExecuteArgueAgainst(const ExecutionContext& ctx) {
        return ExecuteSingleMode(ctx, CoT::ReasoningMode::ARGUE_AGAINST, "argueagainst");
    }
    
    static CLIExecutionResult ExecuteCritic(const ExecutionContext& ctx) {
        return ExecuteSingleMode(ctx, CoT::ReasoningMode::CRITIC, "critic");
    }
    
    static CLIExecutionResult ExecuteSynthesizer(const ExecutionContext& ctx) {
        return ExecuteSingleMode(ctx, CoT::ReasoningMode::SYNTHESIZER, "synthesizer");
    }
    
    static CLIExecutionResult ExecuteBrainstorm(const ExecutionContext& ctx) {
        return ExecuteSingleMode(ctx, CoT::ReasoningMode::BRAINSTORM, "brainstorm");
    }
    
    static CLIExecutionResult ExecuteVerifier(const ExecutionContext& ctx) {
        return ExecuteSingleMode(ctx, CoT::ReasoningMode::VERIFIER, "verifier");
    }
    
    static CLIExecutionResult ExecuteRefiner(const ExecutionContext& ctx) {
        return ExecuteSingleMode(ctx, CoT::ReasoningMode::REFINER, "refiner");
    }
    
    static CLIExecutionResult ExecuteSummarizer(const ExecutionContext& ctx) {
        return ExecuteSingleMode(ctx, CoT::ReasoningMode::SUMMARIZER, "summarizer");
    }
    
    static CLIExecutionResult ExecuteCoTList(const ExecutionContext& ctx) {
        CLIExecutionResult result;
        result.command = "/cot --list";
        result.success = true;
        result.backendUsed = "local";
        
        std::ostringstream oss;
        oss << "\n🧠 Available CoT Modes (12 total)\n";
        oss << std::string(50, '=') << "\n\n";
        
        for (int i = 0; i < 12; ++i) {
            oss << CoT::ModeEmojis[i] << " ";
            oss << std::left << std::setw(15) << CoT::ModeNames[i];
            oss << " - " << CoT::ModeDescriptions[i] << "\n";
        }
        
        oss << "\n";
        result.output = oss.str();
        return result;
    }
    
    static CLIExecutionResult ExecuteCoTStatus(const ExecutionContext& ctx) {
        CLIExecutionResult result;
        result.command = "/cot --status";
        result.success = true;
        result.backendUsed = "local";
        
        CoT::MultiModeCoTEngine engine;
        auto status = engine.GetStatus();
        
        std::ostringstream oss;
        oss << "\n🧠 CoT Engine Status\n";
        oss << std::string(30, '=') << "\n";
        oss << "Initialized: " << (status["initialized"].get<bool>() ? "Yes" : "No") << "\n";
        oss << "Endpoint: " << status["endpoint"].get<std::string>() << "\n";
        oss << "Model: " << status["model"].get<std::string>() << "\n";
        oss << "Modes: " << status["mode_count"].get<int>() << "\n\n";
        
        result.output = oss.str();
        return result;
    }
    
private:
    static CLIExecutionResult ExecuteSingleMode(const ExecutionContext& ctx, 
                                                   CoT::ReasoningMode mode,
                                                   const std::string& modeName) {
        auto start = std::chrono::steady_clock::now();
        
        std::string query;
        for (const auto& arg : ctx.args) {
            if (!query.empty()) query += " ";
            query += arg;
        }
        
        CLIExecutionResult result;
        result.command = "/" + modeName;
        result.backendUsed = "ollama";
        
        if (query.empty()) {
            result.success = false;
            result.error = "Usage: /" + modeName + " <query>";
            return result;
        }
        
        CoT::MultiModeCoTEngine engine;
        engine.SetModelEndpoint("http://localhost:11434");
        engine.SetDefaultModel("llama3.2:3b");
        
        auto cotResult = engine.ExecuteChain(query, {mode});
        
        auto end = std::chrono::steady_clock::now();
        result.executionMs = std::chrono::duration<double, std::milli>(end - start).count();
        
        result.success = cotResult.success;
        result.output = engine.FormatResultForCLI(cotResult);
        result.error = cotResult.error;
        
        result.metadata["mode"] = CoT::ModeNames[static_cast<size_t>(mode)];
        result.metadata["confidence"] = cotResult.overallConfidence;
        
        return result;
    }
};

// ============================================================================
// Registration
// ============================================================================

void RegisterCoTCommandsWithUnifiedABI() {
    auto& registry = CommandRegistry::Instance();
    
    // Main CoT command
    registry.Register({
        "/cot",
        {"cot", "chain-of-thought"},
        "Execute Chain of Thought reasoning",
        "/cot [options] <query>",
        ExecutionContext::Capability::RESEARCH,
        CoTUnifiedCommands::ExecuteCoT,
        true,
        false
    });
    
    // Individual mode commands
    registry.Register({
        "/thinker",
        {"thinker", "think"},
        "Deep analytical thinking",
        "/thinker <query>",
        ExecutionContext::Capability::RESEARCH,
        CoTUnifiedCommands::ExecuteThinker,
        true,
        false
    });
    
    registry.Register({
        "/auditor",
        {"auditor", "audit"},
        "Code/logic audit",
        "/auditor <code>",
        ExecutionContext::Capability::ANALYSIS,
        CoTUnifiedCommands::ExecuteAuditor,
        true,
        false
    });
    
    registry.Register({
        "/reviewer",
        {"reviewer", "review"},
        "Peer review analysis",
        "/reviewer <content>",
        ExecutionContext::Capability::ANALYSIS,
        CoTUnifiedCommands::ExecuteReviewer,
        true,
        false
    });
    
    registry.Register({
        "/researcher",
        {"researcher", "research"},
        "Research and fact-finding",
        "/researcher <topic>",
        ExecutionContext::Capability::RESEARCH,
        CoTUnifiedCommands::ExecuteResearcher,
        true,
        false
    });
    
    registry.Register({
        "/arguefor",
        {"arguefor", "pro"},
        "Argue FOR a position",
        "/arguefor <position>",
        ExecutionContext::Capability::RESEARCH,
        CoTUnifiedCommands::ExecuteArgueFor,
        true,
        false
    });
    
    registry.Register({
        "/argueagainst",
        {"argueagainst", "con"},
        "Argue AGAINST a position",
        "/argueagainst <position>",
        ExecutionContext::Capability::RESEARCH,
        CoTUnifiedCommands::ExecuteArgueAgainst,
        true,
        false
    });
    
    registry.Register({
        "/critic",
        {"critic", "critique"},
        "Critical analysis",
        "/critic <content>",
        ExecutionContext::Capability::ANALYSIS,
        CoTUnifiedCommands::ExecuteCritic,
        true,
        false
    });
    
    registry.Register({
        "/synthesizer",
        {"synthesizer", "synthesize"},
        "Combine perspectives",
        "/synthesizer <perspectives...>",
        ExecutionContext::Capability::SYNTHESIS,
        CoTUnifiedCommands::ExecuteSynthesizer,
        true,
        false
    });
    
    registry.Register({
        "/brainstorm",
        {"brainstorm", "ideas"},
        "Generate creative ideas",
        "/brainstorm <topic>",
        ExecutionContext::Capability::CODE_GENERATION,
        CoTUnifiedCommands::ExecuteBrainstorm,
        true,
        false
    });
    
    registry.Register({
        "/verifier",
        {"verifier", "verify"},
        "Verify correctness",
        "/verifier <claim>",
        ExecutionContext::Capability::ANALYSIS,
        CoTUnifiedCommands::ExecuteVerifier,
        true,
        false
    });
    
    registry.Register({
        "/refiner",
        {"refiner", "refine"},
        "Refine and polish",
        "/refiner <content>",
        ExecutionContext::Capability::CODE_GENERATION,
        CoTUnifiedCommands::ExecuteRefiner,
        true,
        false
    });
    
    registry.Register({
        "/summarizer",
        {"summarizer", "summarize"},
        "Summarize content",
        "/summarizer <content>",
        ExecutionContext::Capability::SYNTHESIS,
        CoTUnifiedCommands::ExecuteSummarizer,
        true,
        false
    });
    
    // Utility commands
    registry.Register({
        "/cot-list",
        {"cot-list"},
        "List CoT modes",
        "/cot-list",
        ExecutionContext::Capability::ANALYSIS,
        CoTUnifiedCommands::ExecuteCoTList,
        false,
        false
    });
    
    registry.Register({
        "/cot-status",
        {"cot-status"},
        "Show CoT status",
        "/cot-status",
        ExecutionContext::Capability::ANALYSIS,
        CoTUnifiedCommands::ExecuteCoTStatus,
        false,
        false
    });
    
    std::cout << "[CoTUnifiedIntegration] Registered " << registry.GetAll().size() << " CoT commands\n";
}

} // namespace CLI
} // namespace RawrXD
