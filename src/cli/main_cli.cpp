//==============================================================================
// main_cli.cpp
// SINGLE ENTRY POINT for rawrxd.exe
// Phase 15B: Service Architecture
//
// This is the ONLY main() in the entire RawrXD CLI suite.
// All subsystems route through CommandBus + ModelResolver.
// No standalone executables. No duplicate entry points.
//==============================================================================

#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <string_view>
#include <nlohmann/json.hpp>

#include "runtime/CommandBus.hpp"
#include "runtime/ModelResolver.hpp"
#include "cli/cli_entrypoints.hpp"

using json = nlohmann::json;

//==============================================================================
// Print usage
//==============================================================================
static void PrintUsage(const char* prog) {
    printf("RawrXD CLI v15.0 — Unified Service Runtime\n");
    printf("Usage: %s <command> [args...]\n\n", prog);
    printf("Commands:\n");
    printf("  run <model> <\"prompt\">    Run inference with model\n");
    printf("  benchmark <model>          Benchmark model performance\n");
    printf("  chat <model>              Interactive chat mode\n");
    printf("  serve <model>             Start API server\n");
    printf("  compile <file>            Compile source to binary\n");
    printf("  build <project>           Build project\n");
    printf("  assemble <file.asm>       Assemble MASM64 source\n");
    printf("  codex <subcmd> <file>     CODEX RE analysis\n");
    printf("  agent <task>              Run agentic task\n");
    printf("  swarm <config>            Run swarm orchestration\n");
    printf("  system <cmd>              Unified subsystem dispatch\n");
    printf("  status                   Show runtime status\n");
    printf("  diagnostics              Run system diagnostics\n");
    printf("\nModel Resolution:\n");
    printf("  rawrxd run phi3-mini \"hello\"\n");
    printf("  rawrxd run F:\\OllamaModels\\BigDaddyG.gguf \"audit\"\n");
    printf("  rawrxd run huggingface:TheBloke/Llama-2-7B-GGUF \"test\"\n");
    printf("  rawrxd run ollama:llama3.1 \"hi\"\n");
    printf("\nCODEX Examples:\n");
    printf("  rawrxd codex pe test.exe          PE analysis\n");
    printf("  rawrxd codex disasm test.exe      Disassembly\n");
    printf("  rawrxd codex decompile test.exe   Decompilation\n");
    printf("  rawrxd codex cfg test.exe         Control flow graph\n");
    printf("  rawrxd codex imports test.exe     Import table\n");
    printf("  rawrxd codex exports test.exe     Export table\n");
    printf("  rawrxd codex strings test.exe     String extraction\n");
    printf("  rawrxd codex entropy test.exe     Entropy analysis\n");
    printf("  rawrxd codex pattern test.exe     Pattern matching\n");
    printf("\nCompiler Examples:\n");
    printf("  rawrxd compile hello.eon          Compile Eon source\n");
    printf("  rawrxd assemble kernel.asm        Assemble MASM64\n");
    printf("  rawrxd build project.json         Build from config\n");
    printf("\nOptions:\n");
    printf("  --json                   Output JSON (default)\n");
    printf("  --verbose                Verbose output\n");
    printf("  --gpu                    Force GPU inference\n");
    printf("  --cpu                    Force CPU inference\n");
    printf("  --max-tokens N           Max tokens to generate\n");
    printf("  --temperature T          Sampling temperature\n");
    printf("  --top-p P                Nucleus sampling threshold\n");
    printf("\n");
}

//==============================================================================
// Parse arguments
//==============================================================================
static bool ParseGlobalOptions(int& argc, char** argv, bool& jsonOutput, bool& verbose, bool& useGpu) {
    jsonOutput = true;  // Default
    verbose = false;
    useGpu = true;      // Default
    
    int writeIdx = 1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            jsonOutput = true;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "--gpu") == 0) {
            useGpu = true;
        } else if (strcmp(argv[i], "--cpu") == 0) {
            useGpu = false;
        } else {
            argv[writeIdx++] = argv[i];
        }
    }
    argc = writeIdx;
    return true;
}

//==============================================================================
// MAIN — Single Entry Point
//==============================================================================
int main(int argc, char** argv) {
    // Set console output to UTF-8
    SetConsoleOutputCP(CP_UTF8);
    
    // Parse global options
    bool jsonOutput, verbose, useGpu;
    if (!ParseGlobalOptions(argc, argv, jsonOutput, verbose, useGpu)) {
        return 1;
    }
    
    // No command?
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 0;
    }
    
    const char* command = argv[1];
    
    // Help?
    if (strcmp(command, "help") == 0 || strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        PrintUsage(argv[0]);
        return 0;
    }
    
    // Version?
    if (strcmp(command, "version") == 0 || strcmp(command, "--version") == 0 || strcmp(command, "-v") == 0) {
        printf("RawrXD CLI v15.0.1-GOLD\n");
        printf("Architecture: x64 Native + MASM64\n");
        printf("Runtime: Cyclonic Flow + 256-Byte State\n");
        printf("Engine: Deep2 + Sovereign Kernel\n");
        return 0;
    }
    
    // Initialize runtime
    RawrXD::Runtime::CommandBus& bus = RawrXD::Runtime::CommandBus::Instance();
    bus.Initialize();
    
    RawrXD::Runtime::ModelResolver& resolver = RawrXD::Runtime::ModelResolver::Instance();
    resolver.Initialize();
    
    // Build args vector (skip program name and command)
    std::vector<std::string> args;
    for (int i = 2; i < argc; i++) {
        args.push_back(argv[i]);
    }
    
    // Execute command
    auto result = bus.Execute(command, args);
    
    // Output result
    if (jsonOutput) {
        json output;
        output["exit_code"] = result.exitCode;
        output["command"] = command;
        
        if (!result.output.empty()) {
            output["output"] = result.output;
        }
        
        if (!result.error.empty()) {
            output["error"] = result.error;
        }
        
        output["execution_time_ms"] = result.executionTimeMs;
        output["memory_used"] = result.memoryUsed;
        
        printf("%s\n", output.dump(2).c_str());
    } else {
        if (!result.output.empty()) {
            printf("%s\n", result.output.c_str());
        }
        if (!result.error.empty()) {
            fprintf(stderr, "Error: %s\n", result.error.c_str());
        }
    }
    
    // Shutdown
    bus.Shutdown();
    resolver.Shutdown();
    
    return result.exitCode;
}

// Standalone diagnostic binaries are built from separate .cpp files:
//   src/cli/standalone_infer.cpp  (RAWRXD_STANDALONE_INFER)
//   src/cli/standalone_compiler.cpp (RAWRXD_STANDALONE_COMPILER)
//   src/cli/standalone_codex.cpp  (RAWRXD_STANDALONE_CODEX)
//   src/cli/standalone_unified.cpp (RAWRXD_STANDALONE_UNIFIED)
// See CMakeLists.txt for standalone target definitions.
