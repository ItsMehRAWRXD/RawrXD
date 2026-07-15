// ============================================================================
// CoT CLI Integration — 12-Mode Chain of Thought Commands
// ============================================================================
// Adds /cot command to CLI with full 12-mode support
// Integrates with existing CLI_SlashRouter and InteractiveShell
// ============================================================================

#include "../cot/cot_multi_mode_engine.hpp"
#include "CLI_SlashRouter.hpp"
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>

namespace RawrXD {
namespace CLI {

// ============================================================================
// CoT CLI Context
// ============================================================================

class CoTCLIContext {
public:
    CoT::MultiModeCoTEngine engine;
    std::string lastQuery;
    CoT::CoTResult lastResult;
    bool hasLastResult;
    
    CoTCLIContext() : hasLastResult(false) {
        // Initialize with default Ollama endpoint
        engine.SetModelEndpoint("http://localhost:11434");
        engine.SetDefaultModel("llama3.2:3b");
    }
    
    void SetModel(const std::string& model) {
        engine.SetDefaultModel(model);
    }
    
    void SetEndpoint(const std::string& endpoint) {
        engine.SetModelEndpoint(endpoint);
    }
};

// Global context (singleton for CLI session)
static CoTCLIContext* g_cotContext = nullptr;

CoTCLIContext* GetCoTContext() {
    if (!g_cotContext) {
        g_cotContext = new CoTCLIContext();
    }
    return g_cotContext;
}

// ============================================================================
// Command Handlers
// ============================================================================

void HandleCoTHelp() {
    std::cout << R"(
🧠 Chain of Thought (CoT) Commands
==================================

USAGE:
  /cot <query>                    Run default 8-step chain
  /cot --modes <modes> <query>   Run with specific modes
  /cot --single <mode> <query>  Run single mode
  /cot --chain <type> <query>    Run predefined chain
  /cot --list                     List all 12 modes
  /cot --status                   Show CoT engine status
  /cot --last                     Show last result
  /cot --export <file>            Export last result to JSON

12 REASONING MODES:
  💭 thinker      - Deep analytical thinking
  🔍 auditor      - Code/logic audit and review
  👁️  reviewer     - Peer review style analysis
  📚 researcher   - Research and fact-finding
  ✅ arguefor     - Argue FOR a position
  ❌ argueagainst - Argue AGAINST a position
  ⚠️  critic       - Critical analysis and flaw detection
  ✨ synthesizer  - Combine multiple perspectives
  💡 brainstorm   - Generate creative ideas
  ✓  verifier     - Verify correctness and validity
  🔧 refiner      - Refine and polish
  📝 summarizer   - Summarize and condense

PREDEFINED CHAINS:
  default    - Full 8-step analysis
  code       - Code review chain
  decision   - Decision making chain
  creative   - Creative brainstorming chain

EXAMPLES:
  /cot "How do I optimize this function?"
  /cot --modes thinker,critic,synthesizer "Is this design good?"
  /cot --single auditor "void main() { ... }"
  /cot --chain code "int factorial(int n) { ... }"
  /cot --list

)";
}

void HandleCoTList() {
    std::cout << "\n🧠 Available CoT Modes (12 total)\n";
    std::cout << std::string(50, '=') << "\n\n";
    
    auto ctx = GetCoTContext();
    auto modes = ctx->engine.GetAllModes();
    
    for (const auto& mode : modes) {
        std::cout << mode["emoji"].get<std::string>() << " ";
        std::cout << std::left << std::setw(15) << mode["name"].get<std::string>();
        std::cout << " - " << mode["description"].get<std::string>() << "\n";
    }
    
    std::cout << "\n";
}

void HandleCoTStatus() {
    auto ctx = GetCoTContext();
    auto status = ctx->engine.GetStatus();
    
    std::cout << "\n🧠 CoT Engine Status\n";
    std::cout << std::string(30, '=') << "\n";
    std::cout << "Initialized: " << (status["initialized"].get<bool>() ? "Yes" : "No") << "\n";
    std::cout << "Endpoint: " << status["endpoint"].get<std::string>() << "\n";
    std::cout << "Model: " << status["model"].get<std::string>() << "\n";
    std::cout << "Modes: " << status["mode_count"].get<int>() << "\n\n";
}

void HandleCoTLast() {
    auto ctx = GetCoTContext();
    
    if (!ctx->hasLastResult) {
        std::cout << "[CoT] No previous result available.\n";
        return;
    }
    
    std::cout << ctx->engine.FormatResultForCLI(ctx->lastResult);
}

void HandleCoTExport(const std::string& filename) {
    auto ctx = GetCoTContext();
    
    if (!ctx->hasLastResult) {
        std::cout << "[CoT] No result to export. Run a CoT chain first.\n";
        return;
    }
    
    auto json = ctx->engine.ExportResult(ctx->lastResult);
    
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cout << "[CoT] Error: Cannot open file for writing: " << filename << "\n";
        return;
    }
    
    file << json.dump(2);
    file.close();
    
    std::cout << "[CoT] Result exported to: " << filename << "\n";
}

void HandleCoTSetModel(const std::string& model) {
    auto ctx = GetCoTContext();
    ctx->SetModel(model);
    std::cout << "[CoT] Model set to: " << model << "\n";
}

void HandleCoTSetEndpoint(const std::string& endpoint) {
    auto ctx = GetCoTContext();
    ctx->SetEndpoint(endpoint);
    std::cout << "[CoT] Endpoint set to: " << endpoint << "\n";
}

// ============================================================================
// Main CoT Execution
// ============================================================================

void ExecuteCoTChain(const std::string& query, 
                     const std::vector<CoT::ReasoningMode>& modes,
                     const std::unordered_map<std::string, std::string>& context = {}) {
    auto ctx = GetCoTContext();
    
    std::cout << "\n🧠 Chain of Thought Starting...\n";
    std::cout << "Query: " << query << "\n";
    std::cout << "Modes: " << CoT::CoTCLIHelper::ModesToString(modes) << "\n";
    std::cout << "Model: " << "llama3.2:3b" << "\n\n";
    
    auto start = std::chrono::steady_clock::now();
    
    CoT::CoTResult result = ctx->engine.ExecuteChain(query, modes, context);
    
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration<double, std::milli>(end - start).count();
    
    ctx->lastResult = result;
    ctx->hasLastResult = true;
    ctx->lastQuery = query;
    
    // Display result
    std::cout << ctx->engine.FormatResultForCLI(result);
    
    std::cout << "\n[CoT] Chain complete in " << std::fixed << std::setprecision(0) << elapsed << "ms\n";
}

void ExecuteCoTSingle(CoT::ReasoningMode mode, const std::string& query) {
    std::vector<CoT::ReasoningMode> modes = {mode};
    ExecuteCoTChain(query, modes);
}

void ExecuteCoTChainByType(const std::string& chainType, const std::string& query) {
    std::vector<CoT::ReasoningMode> modes;
    
    if (chainType == "default" || chainType == "full") {
        modes = CoT::CoTCLIHelper::GetDefaultChain();
    } else if (chainType == "code" || chainType == "review") {
        modes = CoT::CoTCLIHelper::GetCodeReviewChain();
    } else if (chainType == "decision") {
        modes = CoT::CoTCLIHelper::GetDecisionChain();
    } else if (chainType == "creative") {
        modes = CoT::CoTCLIHelper::GetCreativeChain();
    } else {
        std::cout << "[CoT] Unknown chain type: " << chainType << "\n";
        std::cout << "Available: default, code, decision, creative\n";
        return;
    }
    
    ExecuteCoTChain(query, modes);
}

// ============================================================================
// Command Parser
// ============================================================================

void ProcessCoTCommand(const std::string& input) {
    std::istringstream iss(input);
    std::string cmd;
    iss >> cmd; // Skip "/cot"
    
    std::vector<std::string> args;
    std::string arg;
    while (iss >> arg) {
        args.push_back(arg);
    }
    
    if (args.empty()) {
        HandleCoTHelp();
        return;
    }
    
    std::string firstArg = args[0];
    
    // Handle flags
    if (firstArg == "--help" || firstArg == "-h") {
        HandleCoTHelp();
    }
    else if (firstArg == "--list" || firstArg == "-l") {
        HandleCoTList();
    }
    else if (firstArg == "--status" || firstArg == "-s") {
        HandleCoTStatus();
    }
    else if (firstArg == "--last") {
        HandleCoTLast();
    }
    else if (firstArg == "--export" || firstArg == "-e") {
        if (args.size() < 2) {
            std::cout << "[CoT] Usage: /cot --export <filename>\n";
            return;
        }
        HandleCoTExport(args[1]);
    }
    else if (firstArg == "--model" || firstArg == "-m") {
        if (args.size() < 2) {
            std::cout << "[CoT] Usage: /cot --model <model_name>\n";
            return;
        }
        HandleCoTSetModel(args[1]);
    }
    else if (firstArg == "--endpoint") {
        if (args.size() < 2) {
            std::cout << "[CoT] Usage: /cot --endpoint <url>\n";
            return;
        }
        HandleCoTSetEndpoint(args[1]);
    }
    else if (firstArg == "--modes") {
        if (args.size() < 3) {
            std::cout << "[CoT] Usage: /cot --modes <mode1,mode2,...\u003e <query>\n";
            return;
        }
        std::string modesStr = args[1];
        // Reconstruct query from remaining args
        std::string query;
        for (size_t i = 2; i < args.size(); ++i) {
            if (i > 2) query += " ";
            query += args[i];
        }
        
        auto modes = CoT::CoTCLIHelper::ParseModeString(modesStr);
        if (modes.empty()) {
            std::cout << "[CoT] No valid modes specified. Use /cot --list to see available modes.\n";
            return;
        }
        ExecuteCoTChain(query, modes);
    }
    else if (firstArg == "--single") {
        if (args.size() < 3) {
            std::cout << "[CoT] Usage: /cot --single <mode> <query>\n";
            return;
        }
        std::string modeStr = args[1];
        std::string query;
        for (size_t i = 2; i < args.size(); ++i) {
            if (i > 2) query += " ";
            query += args[i];
        }
        
        auto modes = CoT::CoTCLIHelper::ParseModeString(modeStr);
        if (modes.empty()) {
            std::cout << "[CoT] Invalid mode: " << modeStr << "\n";
            return;
        }
        ExecuteCoTSingle(modes[0], query);
    }
    else if (firstArg == "--chain" || firstArg == "-c") {
        if (args.size() < 3) {
            std::cout << "[CoT] Usage: /cot --chain <type> <query>\n";
            std::cout << "Types: default, code, decision, creative\n";
            return;
        }
        std::string chainType = args[1];
        std::string query;
        for (size_t i = 2; i < args.size(); ++i) {
            if (i > 2) query += " ";
            query += args[i];
        }
        ExecuteCoTChainByType(chainType, query);
    }
    else {
        // Default: treat entire input as query with default chain
        std::string query;
        for (const auto& a : args) {
            if (!query.empty()) query += " ";
            query += a;
        }
        auto modes = CoT::CoTCLIHelper::GetDefaultChain();
        ExecuteCoTChain(query, modes);
    }
}

// ============================================================================
// Individual Mode Commands (Shortcuts)
// ============================================================================

void ProcessThinkerCommand(const std::string& query) {
    ExecuteCoTSingle(CoT::ReasoningMode::THINKER, query);
}

void ProcessAuditorCommand(const std::string& query) {
    ExecuteCoTSingle(CoT::ReasoningMode::AUDITOR, query);
}

void ProcessReviewerCommand(const std::string& query) {
    ExecuteCoTSingle(CoT::ReasoningMode::REVIEWER, query);
}

void ProcessResearcherCommand(const std::string& query) {
    ExecuteCoTSingle(CoT::ReasoningMode::RESEARCHER, query);
}

void ProcessArgueForCommand(const std::string& query) {
    ExecuteCoTSingle(CoT::ReasoningMode::ARGUE_FOR, query);
}

void ProcessArgueAgainstCommand(const std::string& query) {
    ExecuteCoTSingle(CoT::ReasoningMode::ARGUE_AGAINST, query);
}

void ProcessCriticCommand(const std::string& query) {
    ExecuteCoTSingle(CoT::ReasoningMode::CRITIC, query);
}

void ProcessSynthesizerCommand(const std::string& query) {
    ExecuteCoTSingle(CoT::ReasoningMode::SYNTHESIZER, query);
}

void ProcessBrainstormCommand(const std::string& query) {
    ExecuteCoTSingle(CoT::ReasoningMode::BRAINSTORM, query);
}

void ProcessVerifierCommand(const std::string& query) {
    ExecuteCoTSingle(CoT::ReasoningMode::VERIFIER, query);
}

void ProcessRefinerCommand(const std::string& query) {
    ExecuteCoTSingle(CoT::ReasoningMode::REFINER, query);
}

void ProcessSummarizerCommand(const std::string& query) {
    ExecuteCoTSingle(CoT::ReasoningMode::SUMMARIZER, query);
}

// ============================================================================
// Integration with CLI_SlashRouter
// ============================================================================

// This function is called from CLI_SlashRouter to handle /cot commands
SlashCommandResult HandleCoT(const std::vector<std::string>& args, void* ctx) {
    if (args.empty()) {
        HandleCoTHelp();
        return {true, "", ""};
    }
    
    // Reconstruct command line
    std::string cmdLine = "/cot";
    for (const auto& arg : args) {
        cmdLine += " " + arg;
    }
    
    ProcessCoTCommand(cmdLine);
    
    return {true, "CoT command executed", ""};
}

// Individual mode handlers for direct CLI shortcuts
SlashCommandResult HandleThinker(const std::vector<std::string>& args, void* ctx) {
    if (args.empty()) {
        return {false, "", "Usage: /thinker <query>"};
    }
    std::string query;
    for (const auto& a : args) {
        if (!query.empty()) query += " ";
        query += a;
    }
    ProcessThinkerCommand(query);
    return {true, "", ""};
}

SlashCommandResult HandleAuditor(const std::vector<std::string>& args, void* ctx) {
    if (args.empty()) {
        return {false, "", "Usage: /auditor <code>"};
    }
    std::string query;
    for (const auto& a : args) {
        if (!query.empty()) query += " ";
        query += a;
    }
    ProcessAuditorCommand(query);
    return {true, "", ""};
}

SlashCommandResult HandleReviewer(const std::vector<std::string>& args, void* ctx) {
    if (args.empty()) {
        return {false, "", "Usage: /reviewer <content>"};
    }
    std::string query;
    for (const auto& a : args) {
        if (!query.empty()) query += " ";
        query += a;
    }
    ProcessReviewerCommand(query);
    return {true, "", ""};
}

SlashCommandResult HandleResearcher(const std::vector<std::string>& args, void* ctx) {
    if (args.empty()) {
        return {false, "", "Usage: /researcher <topic>"};
    }
    std::string query;
    for (const auto& a : args) {
        if (!query.empty()) query += " ";
        query += a;
    }
    ProcessResearcherCommand(query);
    return {true, "", ""};
}

SlashCommandResult HandleArgueFor(const std::vector<std::string>& args, void* ctx) {
    if (args.empty()) {
        return {false, "", "Usage: /arguefor <position>"};
    }
    std::string query;
    for (const auto& a : args) {
        if (!query.empty()) query += " ";
        query += a;
    }
    ProcessArgueForCommand(query);
    return {true, "", ""};
}

SlashCommandResult HandleArgueAgainst(const std::vector<std::string>& args, void* ctx) {
    if (args.empty()) {
        return {false, "", "Usage: /argueagainst <position>"};
    }
    std::string query;
    for (const auto& a : args) {
        if (!query.empty()) query += " ";
        query += a;
    }
    ProcessArgueAgainstCommand(query);
    return {true, "", ""};
}

SlashCommandResult HandleCritic(const std::vector<std::string>& args, void* ctx) {
    if (args.empty()) {
        return {false, "", "Usage: /critic <content>"};
    }
    std::string query;
    for (const auto& a : args) {
        if (!query.empty()) query += " ";
        query += a;
    }
    ProcessCriticCommand(query);
    return {true, "", ""};
}

SlashCommandResult HandleSynthesizer(const std::vector<std::string>& args, void* ctx) {
    if (args.empty()) {
        return {false, "", "Usage: /synthesizer <perspectives...>"};
    }
    std::string query;
    for (const auto& a : args) {
        if (!query.empty()) query += " ";
        query += a;
    }
    ProcessSynthesizerCommand(query);
    return {true, "", ""};
}

SlashCommandResult HandleBrainstorm(const std::vector<std::string>& args, void* ctx) {
    if (args.empty()) {
        return {false, "", "Usage: /brainstorm <topic>"};
    }
    std::string query;
    for (const auto& a : args) {
        if (!query.empty()) query += " ";
        query += a;
    }
    ProcessBrainstormCommand(query);
    return {true, "", ""};
}

SlashCommandResult HandleVerifier(const std::vector<std::string>& args, void* ctx) {
    if (args.empty()) {
        return {false, "", "Usage: /verifier <claim>"};
    }
    std::string query;
    for (const auto& a : args) {
        if (!query.empty()) query += " ";
        query += a;
    }
    ProcessVerifierCommand(query);
    return {true, "", ""};
}

SlashCommandResult HandleRefiner(const std::vector<std::string>& args, void* ctx) {
    if (args.empty()) {
        return {false, "", "Usage: /refiner <content>"};
    }
    std::string query;
    for (const auto& a : args) {
        if (!query.empty()) query += " ";
        query += a;
    }
    ProcessRefinerCommand(query);
    return {true, "", ""};
}

SlashCommandResult HandleSummarizer(const std::vector<std::string>& args, void* ctx) {
    if (args.empty()) {
        return {false, "", "Usage: /summarizer <content>"};
    }
    std::string query;
    for (const auto& a : args) {
        if (!query.empty()) query += " ";
        query += a;
    }
    ProcessSummarizerCommand(query);
    return {true, "", ""};
}

// ============================================================================
// Initialization
// ============================================================================

void InitializeCoTCLI() {
    // Initialize the CoT context
    GetCoTContext();
    std::cout << "[CoT] Chain of Thought system initialized (12 modes)\n";
}

} // namespace CLI
} // namespace RawrXD
