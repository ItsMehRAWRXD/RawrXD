// ============================================================================
// rawrxd.cpp — RawrXD Sovereign Runtime Entry Point
// ============================================================================
// War Room: One binary, one command, one evidence bundle.
//
// Usage:
//   rawrxd.exe --model phi3-mini.gguf --prompt "Hello" --inference
//   rawrxd.exe --model phi3-mini.gguf --prompt "Analyze this" --agentic
//   rawrxd.exe --model phi3-mini.gguf --prompt "Hello" --validate
//
// Output:
//   RawrXD Sovereign Runtime v1.0-ALPHA
//   
//   MODEL
//   PASS GGUF Integrity
//   PASS Tensor Manifest
//   PASS Vocabulary Load
//   
//   EXECUTION
//   PASS Transformer Pipeline
//   PASS Kernel Registry
//   PASS KV Cache
//   
//   AGENT
//   PASS Planning
//   PASS Code Analysis
//   PASS Recovery
//   
//   HARDWARE
//   PASS CPU Backend
//   PASS GPU Backend
//   
//   CERTIFICATE: RXD-SOVEREIGN-001
// ============================================================================

#include "sovereign/ExecutionContract.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#include <filesystem>

using namespace RawrXD::Sovereign;

// ============================================================================
// Command Line Parser
// ============================================================================
struct CommandLineArgs {
    std::string modelPath;
    std::string prompt;
    std::string mode = "inference";  // inference, agentic, validate
    uint32_t maxTokens = 512;
    float temperature = 0.7f;
    std::string backend = "auto";
    std::string evidenceDir = "validation/runs";
    bool verbose = false;
    bool help = false;
};

void printUsage(const char* programName) {
    std::cout << R"(
RawrXD Sovereign Runtime v1.0-ALPHA
Usage: )" << programName << R"( [options]

Required:
  --model PATH          Path to GGUF model file
  --prompt TEXT         Input prompt

Execution Mode:
  --inference           Single generation (default)
  --agentic             Autonomous agent loop
  --validate            Full validation + evidence bundle

Generation Parameters:
  --max-tokens N        Maximum tokens to generate (default: 512)
  --temperature T       Sampling temperature (default: 0.7)
  --top-p P             Nucleus sampling (default: 0.9)
  --top-k K             Top-k sampling (default: 40)

Backend:
  --backend NAME        Backend: auto, cpu_avx2, cpu_avx512, vulkan_amd

Validation:
  --evidence-dir PATH   Evidence output directory (default: validation/runs)

Other:
  --verbose             Detailed output
  --help                Show this help

Examples:
  )" << programName << R"( --model phi3.gguf --prompt "Hello world"
  )" << programName << R"( --model phi3.gguf --prompt "Analyze code" --agentic
  )" << programName << R"( --model phi3.gguf --prompt "Hello" --validate
)" << std::endl;
}

CommandLineArgs parseArgs(int argc, char* argv[]) {
    CommandLineArgs args;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            args.help = true;
        } else if (arg == "--model" && i + 1 < argc) {
            args.modelPath = argv[++i];
        } else if (arg == "--prompt" && i + 1 < argc) {
            args.prompt = argv[++i];
        } else if (arg == "--inference") {
            args.mode = "inference";
        } else if (arg == "--agentic") {
            args.mode = "agentic";
        } else if (arg == "--validate") {
            args.mode = "validate";
        } else if (arg == "--max-tokens" && i + 1 < argc) {
            args.maxTokens = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--temperature" && i + 1 < argc) {
            args.temperature = std::stof(argv[++i]);
        } else if (arg == "--top-p" && i + 1 < argc) {
            // Parse but not stored in simple version
            ++i;
        } else if (arg == "--top-k" && i + 1 < argc) {
            ++i;
        } else if (arg == "--backend" && i + 1 < argc) {
            args.backend = argv[++i];
        } else if (arg == "--evidence-dir" && i + 1 < argc) {
            args.evidenceDir = argv[++i];
        } else if (arg == "--verbose" || arg == "-v") {
            args.verbose = true;
        }
    }
    
    return args;
}

// ============================================================================
// Output Formatting
// ============================================================================
void printBanner() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║              RawrXD Sovereign Runtime v1.0-ALPHA                 ║
║                                                                  ║
║         Validated Autonomous AI Execution Platform               ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
)" << std::endl;
}

void printSection(const std::string& name) {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "  " << name << std::endl;
    std::cout << std::string(60, '=') << std::endl;
}

void printCheck(const std::string& item, bool passed, const std::string& detail = "") {
    const char* status = passed ? "✓ PASS" : "✗ FAIL";
    std::cout << "  " << std::left << std::setw(40) << item << status;
    if (!detail.empty()) {
        std::cout << "  (" << detail << ")";
    }
    std::cout << std::endl;
}

void printResult(const ExecutionResult& result, bool verbose) {
    printSection("EXECUTION RESULT");
    
    std::cout << "  Status: " << result.statusMessage << std::endl;
    
    if (!result.generatedText.empty()) {
        std::cout << "\n  Generated Text:\n";
        std::cout << "  \"" << result.generatedText.substr(0, 200);
        if (result.generatedText.length() > 200) {
            std::cout << "...";
        }
        std::cout << "\"\n";
    }
    
    printSection("TIMING");
    std::cout << "  Total:        " << result.timing.totalMs.count() << " ms\n";
    std::cout << "  Load:         " << result.timing.loadMs.count() << " ms\n";
    std::cout << "  Tokenize:     " << result.timing.tokenizeMs.count() << " ms\n";
    std::cout << "  Inference:    " << result.timing.inferenceMs.count() << " ms\n";
    std::cout << "  Sampling:     " << result.timing.samplingMs.count() << " ms\n";
    if (result.timing.agenticMs.count() > 0) {
        std::cout << "  Agentic:      " << result.timing.agenticMs.count() << " ms\n";
    }
    if (result.timing.recoveryMs.count() > 0) {
        std::cout << "  Recovery:     " << result.timing.recoveryMs.count() << " ms\n";
    }
    std::cout << "  TPS:          " << std::fixed << std::setprecision(2) << result.timing.tokensPerSecond << " tokens/sec\n";
    
    printSection("TELEMETRY");
    std::cout << "  Tokens Generated: " << result.telemetry.tokensGenerated << "\n";
    std::cout << "  Tokens Prompt:    " << result.telemetry.tokensPrompt << "\n";
    std::cout << "  Memory Peak:      " << result.telemetry.memoryPeakBytes / (1024*1024) << " MB\n";
    if (result.telemetry.agentIterations > 0) {
        std::cout << "  Agent Iterations: " << result.telemetry.agentIterations << "\n";
    }
    if (result.telemetry.recoveriesAttempted > 0) {
        std::cout << "  Recoveries:       " << result.telemetry.recoveriesSuccessful << "/" << result.telemetry.recoveriesAttempted << "\n";
    }
    
    if (result.hasEvidence()) {
        printSection("EVIDENCE");
        std::cout << "  Run ID:        " << result.evidence.runId << "\n";
        std::cout << "  Certificate:   " << result.evidence.certificateId << "\n";
        std::cout << "  Model Hash:    " << result.evidence.modelHash.substr(0, 32) << "...\n";
        std::cout << "  Output Hash:   " << result.evidence.outputHash.substr(0, 32) << "...\n";
        
        printCheck("Kernel Validation", result.evidence.kernelValidationPassed);
        printCheck("Numeric Validation", result.evidence.numericValidationPassed);
        printCheck("Recovery Validation", result.evidence.recoveryValidationPassed);
        
        if (!result.artifactPaths.empty()) {
            std::cout << "\n  Artifacts:\n";
            for (const auto& [name, path] : result.artifactPaths) {
                std::cout << "    " << name << ": " << path << "\n";
            }
        }
    }
    
    if (result.error) {
        printSection("ERROR");
        std::cout << "  Category:   " << result.error->category << "\n";
        std::cout << "  Component:  " << result.error->component << "\n";
        std::cout << "  Message:    " << result.error->message << "\n";
    }
    
    if (verbose) {
        printSection("FULL JSON");
        std::cout << result.toJsonString() << std::endl;
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================
int main(int argc, char* argv[]) {
    // Parse command line
    CommandLineArgs args = parseArgs(argc, argv);
    
    if (args.help) {
        printUsage(argv[0]);
        return 0;
    }
    
    // Validate required args
    if (args.modelPath.empty() || args.prompt.empty()) {
        std::cerr << "Error: --model and --prompt are required\n\n";
        printUsage(argv[0]);
        return 1;
    }
    
    // Print banner
    printBanner();
    
    // Build execution request
    ExecutionRequest req;
    req.modelPath = args.modelPath;
    req.prompt = args.prompt;
    req.maxTokens = args.maxTokens;
    req.temperature = args.temperature;
    
    // Set mode
    if (args.mode == "agentic") {
        req.mode = ExecutionRequest::Mode::AGENTIC;
    } else if (args.mode == "validate") {
        req.mode = ExecutionRequest::Mode::VALIDATED;
    } else {
        req.mode = ExecutionRequest::Mode::INFERENCE;
    }
    
    // Set backend
    if (args.backend == "cpu_avx2") {
        req.backend = ExecutionRequest::Backend::CPU_AVX2;
    } else if (args.backend == "cpu_avx512") {
        req.backend = ExecutionRequest::Backend::CPU_AVX512;
    } else if (args.backend == "vulkan_amd") {
        req.backend = ExecutionRequest::Backend::VULKAN_AMD;
    }
    
    // Set evidence directory for validated mode
    if (req.mode == ExecutionRequest::Mode::VALIDATED) {
        req.evidenceDirectory = args.evidenceDir;
    }
    
    // Print configuration
    printSection("CONFIGURATION");
    std::cout << "  Model:    " << req.modelPath << "\n";
    std::cout << "  Prompt:   \"" << req.prompt.substr(0, 50);
    if (req.prompt.length() > 50) std::cout << "...";
    std::cout << "\"\n";
    std::cout << "  Mode:     " << args.mode << "\n";
    std::cout << "  Backend:  " << args.backend << "\n";
    std::cout << "  Max Tok:  " << req.maxTokens << "\n";
    
    // Execute
    printSection("EXECUTING");
    std::cout << "  Initializing Sovereign Runtime...\n";
    
    auto& runtime = SovereignRuntime::instance();
    
    std::cout << "  Running execution pipeline...\n\n";
    
    ExecutionResult result;
    if (req.mode == ExecutionRequest::Mode::VALIDATED) {
        result = RunValidated(req.modelPath, req.prompt, req.evidenceDirectory);
    } else if (req.mode == ExecutionRequest::Mode::AGENTIC) {
        result = RunAgentic(req.modelPath, req.prompt, req.maxAgentIterations);
    } else {
        result = RunInference(req.modelPath, req.prompt, req.maxTokens);
    }
    
    // Print results
    printResult(result, args.verbose);
    
    // Final status
    printSection("FINAL STATUS");
    if (result.success()) {
        std::cout << "  ✓ EXECUTION SUCCESSFUL\n";
        if (result.hasEvidence()) {
            std::cout << "  ✓ CERTIFICATE: " << result.evidence.certificateId << "\n";
        }
        return 0;
    } else {
        std::cout << "  ✗ EXECUTION FAILED\n";
        std::cout << "  " << result.statusMessage << "\n";
        return 1;
    }
}
