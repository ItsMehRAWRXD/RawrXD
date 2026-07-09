/**
 * @file unified_cli_v3_real.cpp
 * @brief RawrXD Unified CLI v3 - Real Execution Gateway
 *
 * CLI Contract:
 * - Strict argument parsing with deterministic error codes
 * - JSON output mode for machine integration
 * - Proper exit codes: 0=success, 1=user error, 2=validation failure, 3=runtime failure
 * - Command determinism: same input → same output format
 * - No simulation - only real kernel execution
 *
 * @copyright RawrXD 2026
 */

#include "../execution/execution_contracts.h"
#include "../execution/execution_gateway_impl.h"
#include "../kernels/compression_codec.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <thread>
#include <memory>

namespace fs = std::filesystem;
using namespace rawrxd::execution;

// Exit code constants for CLI
namespace ExitCode {
    constexpr int SUCCESS = 0;
    constexpr int USER_ERROR = 1;
    constexpr int VALIDATION_FAILURE = 2;
    constexpr int RUNTIME_FAILURE = 3;
}

// ============================================================================
// Version Information
// ============================================================================
constexpr const char* VERSION = "3.0.0-real";
constexpr const char* BUILD_DATE = __DATE__;
constexpr const char* BUILD_TIME = __TIME__;

// ============================================================================
// Global State
// ============================================================================
struct CLIState {
    bool jsonOutput = false;
    bool verbose = false;
    bool quiet = false;
    std::string requestId;
};

static CLIState g_state;
static std::unique_ptr<ExecutionGateway> g_gateway;

// ============================================================================
// Output Helpers (Respects --json and --quiet)
// ============================================================================
void Print(const std::string& msg) {
    if (!g_state.quiet && !g_state.jsonOutput) {
        std::cout << msg;
    }
}

void PrintLn(const std::string& msg = "") {
    if (!g_state.quiet && !g_state.jsonOutput) {
        std::cout << msg << "\n";
    }
}

void PrintError(const std::string& msg) {
    if (!g_state.quiet) {
        std::cerr << msg << "\n";
    }
}

void PrintVerbose(const std::string& msg) {
    if (g_state.verbose && !g_state.quiet) {
        std::cerr << "[verbose] " << msg << "\n";
    }
}

void OutputResult(const ExecutionResult& result) {
    if (g_state.jsonOutput) {
        std::cout << result.ToJson() << "\n";
    } else if (!g_state.quiet) {
        std::cout << result.ToHumanReadable();
    }
}

// ============================================================================
// Argument Parser (Hardened)
// ============================================================================
class ArgParser {
    std::map<std::string, std::string> flags_;
    std::vector<std::string> positional_;
    std::string error_;
    
public:
    ArgParser(int argc, char* argv[]) {
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            
            if (arg.substr(0, 2) == "--") {
                size_t eq = arg.find('=');
                if (eq != std::string::npos) {
                    flags_[arg.substr(2, eq - 2)] = arg.substr(eq + 1);
                } else if (i + 1 < argc && argv[i + 1][0] != '-') {
                    flags_[arg.substr(2)] = argv[++i];
                } else {
                    flags_[arg.substr(2)] = "true";
                }
            } else if (arg[0] == '-' && arg.length() > 1) {
                flags_[arg.substr(1)] = "true";
            } else {
                positional_.push_back(arg);
            }
        }
    }
    
    bool HasFlag(const std::string& name) const {
        return flags_.find(name) != flags_.end();
    }
    
    std::string GetFlagValue(const std::string& name, const std::string& defaultVal = "") const {
        auto it = flags_.find(name);
        return (it != flags_.end()) ? it->second : defaultVal;
    }
    
    int GetFlagInt(const std::string& name, int defaultVal = 0) const {
        auto it = flags_.find(name);
        if (it == flags_.end()) return defaultVal;
        try {
            return std::stoi(it->second);
        } catch (...) {
            return defaultVal;
        }
    }
    
    float GetFlagFloat(const std::string& name, float defaultVal = 0.0f) const {
        auto it = flags_.find(name);
        if (it == flags_.end()) return defaultVal;
        try {
            return std::stof(it->second);
        } catch (...) {
            return defaultVal;
        }
    }
    
    const std::vector<std::string>& GetPositional() const { return positional_; }
    
    bool RequireFlag(const std::string& name, const std::string& desc) const {
        if (!HasFlag(name)) {
            const_cast<ArgParser*>(this)->error_ = "Missing required flag: --" + name + " (" + desc + ")";
            return false;
        }
        return true;
    }
    
    const std::string& GetError() const { return error_; }
    bool Valid() const { return error_.empty(); }
};

// ============================================================================
// Command Handlers
// ============================================================================

int HandleHelp(const ArgParser& args) {
    PrintLn("RawrXD Unified CLI v" + std::string(VERSION));
    PrintLn("Build: " + std::string(BUILD_DATE) + " " + std::string(BUILD_TIME));
    PrintLn("");
    PrintLn("Usage: rawrxd <command> [options]");
    PrintLn("");
    PrintLn("Commands:");
    PrintLn("  run --model <path> --prompt <text>   Run inference");
    PrintLn("  kernel --list                        List available kernels");
    PrintLn("  kernel --validate --gemm             Validate GEMM kernel");
    PrintLn("  kernel --profile --gemm               Profile GEMM kernel");
    PrintLn("  kernel --policy                       Generate compression policy");
    PrintLn("  benchmark                             Run benchmark suite");
    PrintLn("  inspect <model.gguf>                  Inspect model file");
    PrintLn("  tokenizer --model <path> [--text]    Validate tokenizer (Step C2)");
    PrintLn("  test --all                           Run all tests");
    PrintLn("  config --show                        Show configuration");
    PrintLn("  help                                 Show this help");
    PrintLn("");
    PrintLn("Global Options:");
    PrintLn("  --json     Output in JSON format");
    PrintLn("  --verbose  Enable verbose output");
    PrintLn("  --quiet    Suppress all output");
    PrintLn("");
    PrintLn("Run Options:");
    PrintLn("  --model <path>       Path to GGUF model");
    PrintLn("  --prompt <text>      Input prompt");
    PrintLn("  --max-tokens <n>     Maximum tokens to generate (default: 128)");
    PrintLn("  --temperature <f>    Sampling temperature (default: 0.8)");
    PrintLn("  --seed <n>           Random seed (0 = random)");
    PrintLn("");
    PrintLn("Kernel Options:");
    PrintLn("  --kernel <name>      Kernel name (gemm, rmsnorm, rope, softmax)");
    PrintLn("  --variant <type>     Implementation variant (reference, avx2, avx512)");
    PrintLn("");
    PrintLn("Exit Codes:");
    PrintLn("  0  Success");
    PrintLn("  1  User error (invalid arguments)");
    PrintLn("  2  Validation failure");
    PrintLn("  3  Runtime failure");
    PrintLn("");
    PrintLn("Examples:");
    PrintLn("  rawrxd run --model model.gguf --prompt \"Hello world\"");
    PrintLn("  rawrxd kernel --list --json");
    PrintLn("  rawrxd kernel --validate --kernel gemm --variant avx2");
    PrintLn("  rawrxd benchmark --json");
    return ExitCode::SUCCESS;
}

int HandleRun(const ArgParser& args) {
    if (!args.RequireFlag("model", "path to GGUF model")) {
        return ExitCode::USER_ERROR;
    }
    if (!args.RequireFlag("prompt", "input prompt text")) {
        return ExitCode::USER_ERROR;
    }
    
    ExecutionRequest req;
    req.command = CommandType::RUN_INFERENCE;
    req.command_name = "run";
    req.model_path = args.GetFlagValue("model");
    req.prompt = args.GetFlagValue("prompt");
    req.max_tokens = args.GetFlagInt("max-tokens", 128);
    req.temperature = args.GetFlagFloat("temperature", 0.8f);
    req.seed = args.GetFlagInt("seed", 0);
    req.json_output = g_state.jsonOutput;
    req.verbose = g_state.verbose;
    req.quiet = g_state.quiet;
    req.request_id = g_state.requestId;
    
    PrintVerbose("Loading model: " + req.model_path);
    PrintVerbose("Prompt: " + req.prompt);
    
    ExecutionResult result = g_gateway->Execute(req);
    OutputResult(result);
    
    return result.ExitCode();
}

int HandleKernel(const ArgParser& args) {
    if (args.HasFlag("list")) {
        ExecutionRequest req;
        req.command = CommandType::TEST_SUITE;
        req.command_name = "kernel-list";
        req.json_output = g_state.jsonOutput;
        req.quiet = g_state.quiet;
        req.request_id = g_state.requestId;
        
        // Get available kernels
        auto kernels = g_gateway->GetAvailableKernels();
        
        ExecutionResult result;
        result.status = Status::SUCCESS;
        result.status_message = "Kernel list";
        
        std::ostringstream oss;
        oss << "Registered Kernels (L4.2.2):\n\n";
        oss << "Reference: RMSNorm, RoPE, Softmax, GEMV, BatchedGEMV\n";
        oss << "AVX2: RMSNormAVX2, RoPEAVX2, SoftmaxAVX2, GEMVAVX2, BatchedGEMVAVX2\n";
        oss << "Attention: AttentionReference, AttentionAVX2, DotProductAVX2\n";
        oss << "FFN: FFNReference, FFNAVX2, SiLU, SwiGLU\n";
        result.text_output = oss.str();
        
        // Add kernel list to metadata
        std::string kernel_list;
        for (const auto& k : kernels) {
            if (!kernel_list.empty()) kernel_list += ", ";
            kernel_list += k;
        }
        result.metadata["available_kernels"] = kernel_list;
        result.metadata["count"] = std::to_string(kernels.size());
        
        OutputResult(result);
        return ExitCode::SUCCESS;
    }
    
    if (args.HasFlag("validate")) {
        if (!args.RequireFlag("kernel", "kernel name (gemm, rmsnorm, rope, softmax)")) {
            return ExitCode::USER_ERROR;
        }
        
        ExecutionRequest req;
        req.command = CommandType::KERNEL_VALIDATE;
        req.command_name = "kernel-validate";
        req.kernel_name = args.GetFlagValue("kernel");
        req.kernel_variant = args.GetFlagValue("variant", "auto");
        req.json_output = g_state.jsonOutput;
        req.quiet = g_state.quiet;
        req.request_id = g_state.requestId;
        
        PrintVerbose("Validating kernel: " + req.kernel_name);
        PrintVerbose("Variant: " + req.kernel_variant);
        
        ExecutionResult result = g_gateway->Execute(req);
        OutputResult(result);
        
        return result.ExitCode();
    }
    
    if (args.HasFlag("profile")) {
        if (!args.RequireFlag("kernel", "kernel name")) {
            return ExitCode::USER_ERROR;
        }
        
        ExecutionRequest req;
        req.command = CommandType::KERNEL_PROFILE;
        req.command_name = "kernel-profile";
        req.kernel_name = args.GetFlagValue("kernel");
        req.kernel_variant = args.GetFlagValue("variant", "auto");
        req.json_output = g_state.jsonOutput;
        req.quiet = g_state.quiet;
        req.request_id = g_state.requestId;
        
        PrintVerbose("Profiling kernel: " + req.kernel_name);
        
        ExecutionResult result = g_gateway->Execute(req);
        OutputResult(result);
        
        return result.ExitCode();
    }
    
    if (args.HasFlag("policy")) {
        ExecutionRequest req;
        req.command = CommandType::KERNEL_POLICY;
        req.command_name = "kernel-policy";
        req.json_output = g_state.jsonOutput;
        req.quiet = g_state.quiet;
        req.request_id = g_state.requestId;
        
        ExecutionResult result = g_gateway->Execute(req);
        OutputResult(result);
        
        return result.ExitCode();
    }
    
    PrintError("Error: Unknown kernel subcommand");
    PrintError("Use: --list, --validate, --profile, or --policy");
    return ExitCode::USER_ERROR;
}

int HandleBenchmark(const ArgParser& args) {
    ExecutionRequest req;
    req.command = CommandType::BENCHMARK;
    req.command_name = "benchmark";
    req.json_output = g_state.jsonOutput;
    req.quiet = g_state.quiet;
    req.request_id = g_state.requestId;
    
    PrintVerbose("Running benchmark suite...");
    
    ExecutionResult result = g_gateway->Execute(req);
    OutputResult(result);
    
    return result.ExitCode();
}

int HandleInspect(const ArgParser& args) {
    const auto& positional = args.GetPositional();
    if (positional.size() < 2) {
        PrintError("Error: Model path required");
        PrintError("Usage: rawrxd inspect <model.gguf>");
        return ExitCode::USER_ERROR;
    }
    
    ExecutionRequest req;
    req.command = CommandType::INSPECT_MODEL;
    req.command_name = "inspect";
    req.model_path = positional[1];
    req.json_output = g_state.jsonOutput;
    req.quiet = g_state.quiet;
    req.request_id = g_state.requestId;
    
    PrintVerbose("Inspecting: " + req.model_path);
    
    ExecutionResult result = g_gateway->Execute(req);
    OutputResult(result);
    
    return result.ExitCode();
}

int HandleTest(const ArgParser& args) {
    ExecutionRequest req;
    req.command = CommandType::TEST_SUITE;
    req.command_name = "test";
    req.json_output = g_state.jsonOutput;
    req.quiet = g_state.quiet;
    req.request_id = g_state.requestId;
    
    PrintVerbose("Running test suite...");
    
    ExecutionResult result = g_gateway->Execute(req);
    OutputResult(result);
    
    return result.ExitCode();
}

int HandleTokenizer(const ArgParser& args) {
    if (!args.RequireFlag("model", "path to GGUF model")) {
        return ExitCode::USER_ERROR;
    }
    
    ExecutionRequest req;
    req.command = CommandType::TOKENIZER_VALIDATE;
    req.command_name = "tokenizer";
    req.model_path = args.GetFlagValue("model");
    req.prompt = args.GetFlagValue("text", "hello world");
    req.json_output = g_state.jsonOutput;
    req.quiet = g_state.quiet;
    req.request_id = g_state.requestId;
    
    PrintVerbose("Validating tokenizer for: " + req.model_path);
    PrintVerbose("Test text: " + req.prompt);
    
    ExecutionResult result = g_gateway->Execute(req);
    OutputResult(result);
    
    return result.ExitCode();
}

int HandleConfig(const ArgParser& args) {
    if (args.HasFlag("show")) {
        PrintLn("RawrXD Configuration:");
        PrintLn("  Version: " + std::string(VERSION));
        PrintLn("  Gateway: RealExecutionGateway");
        PrintLn("  Kernel Registry: L4.2.2");
        
        auto kernels = g_gateway->GetAvailableKernels();
        PrintLn("  Available Kernels: " + std::to_string(kernels.size()));
        
        return ExitCode::SUCCESS;
    }
    
    PrintError("Error: Use --show to display configuration");
    return ExitCode::USER_ERROR;
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char* argv[]) {
    // Generate request ID
    auto now = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ).count();
    g_state.requestId = "req_" + std::to_string(ms);
    
    ArgParser args(argc, argv);
    
    // Parse global flags
    g_state.jsonOutput = args.HasFlag("json");
    g_state.verbose = args.HasFlag("verbose");
    g_state.quiet = args.HasFlag("quiet");
    
    // Validate flag combinations
    if (g_state.jsonOutput && g_state.quiet) {
        // JSON + quiet is allowed (JSON output only)
    }
    
    const auto& positional = args.GetPositional();
    if (positional.empty()) {
        PrintError("Error: No command specified");
        PrintError("Use 'rawrxd help' for usage information");
        return ExitCode::USER_ERROR;
    }
    
    std::string command = positional[0];
    
    // Initialize execution gateway
    PrintVerbose("Initializing execution gateway...");
    g_gateway = ExecutionGatewayFactory::CreateRealGateway();
    if (!g_gateway || !g_gateway->IsReady()) {
        PrintError("Error: Failed to initialize execution gateway");
        return ExitCode::RUNTIME_FAILURE;
    }
    PrintVerbose("Gateway ready");
    
    // Dispatch command
    int exitCode = ExitCode::USER_ERROR;
    
    if (command == "help" || command == "--help" || command == "-h") {
        exitCode = HandleHelp(args);
    } else if (command == "run") {
        exitCode = HandleRun(args);
    } else if (command == "kernel") {
        exitCode = HandleKernel(args);
    } else if (command == "benchmark") {
        exitCode = HandleBenchmark(args);
    } else if (command == "inspect") {
        exitCode = HandleInspect(args);
    } else if (command == "test") {
        exitCode = HandleTest(args);
    } else if (command == "tokenizer") {
        exitCode = HandleTokenizer(args);
    } else if (command == "config") {
        exitCode = HandleConfig(args);
    } else {
        PrintError("Error: Unknown command: " + command);
        PrintError("Use 'rawrxd help' for available commands");
        exitCode = ExitCode::USER_ERROR;
    }
    
    // Shutdown gateway
    g_gateway.reset();
    
    return exitCode;
}
