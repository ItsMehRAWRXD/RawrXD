//==============================================================================
// main_unified.cpp - RawrXD Unified Entry Point
// Phase 15: Complete System Unification
//
// This is THE single entry point for the entire RawrXD system.
// Replaces: RawrXD.exe, RawrXD-Win32IDE.exe, RawrXD_Autonomous_CLI.exe, etc.
//
// Usage:
//   RawrXD.exe                    - Launch IDE (default)
//   RawrXD.exe --cli              - Interactive CLI mode
//   RawrXD.exe --server           - API server mode
//   RawrXD.exe --compile <file>   - Compile mode
//   RawrXD.exe --agent <task>     - Agent mode
//   RawrXD.exe --chat             - Chat mode
//
// This file unifies all previously separate executables into one coherent
// product with explicit mode selection.
//==============================================================================

#include "RawrXDHost.h"
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace RawrXD::Unified;

//==============================================================================
// Print banner
//==============================================================================
void PrintBanner() {
    std::cout << R"(
    ____  __  ________  ____  ________  ____  __
   / __ \/ / / / __ \/ __ \/_  __/ / / / / / /
  / /_/ / /_/ / / / / /_/ / / / / /_/ / / / / 
 / _, _/ __  / /_/ / _, _/ / / / __  / /_/ /  
/_/ |_/_/ /_/_____/_/ |_| /_/ /_/ /_/\____/   
                                              
  Unified AI-Native Development Environment
  Version 15.0.0 - Phase 15 Complete
  
)";
}

//==============================================================================
// Print help
//==============================================================================
void PrintHelp(const char* programName) {
    std::cout << "Usage: " << programName << " [options]\n\n";
    std::cout << "Modes:\n";
    std::cout << "  (no args)          Launch IDE (default)\n";
    std::cout << "  --cli, -c          Interactive CLI mode\n";
    std::cout << "  --server, -s       API server mode (port 11442)\n";
    std::cout << "  --compile <file>   Compile source file\n";
    std::cout << "  --agent <task>     Execute agent task\n";
    std::cout << "  --chat             Interactive chat mode\n";
    std::cout << "\nOptions:\n";
    std::cout << "  --model <path>     Path to GGUF model\n";
    std::cout << "  --workspace <path> Workspace directory\n";
    std::cout << "  --port <num>       Server port (default: 11442)\n";
    std::cout << "  --no-gpu           Disable GPU acceleration\n";
    std::cout << "  --no-agents        Disable agent system\n";
    std::cout << "  --help, -h         Show this help\n";
    std::cout << "  --version, -v      Show version\n";
}

//==============================================================================
// Parse command line
//==============================================================================
struct CommandLineArgs {
    HostConfig::Mode mode = HostConfig::Mode::IDE;
    std::string modelPath;
    std::string workspacePath;
    std::string compileSource;
    std::string compileOutput;
    std::string agentTask;
    int serverPort = 11442;
    bool enableGPU = true;
    bool enableAgents = true;
    bool showHelp = false;
    bool showVersion = false;
};

CommandLineArgs ParseArgs(int argc, char** argv) {
    CommandLineArgs args;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--cli" || arg == "-c") {
            args.mode = HostConfig::Mode::CLI;
        } else if (arg == "--server" || arg == "-s") {
            args.mode = HostConfig::Mode::Server;
        } else if (arg == "--compile") {
            args.mode = HostConfig::Mode::Compile;
            if (i + 1 < argc) {
                args.compileSource = argv[++i];
            }
        } else if (arg == "--agent") {
            args.mode = HostConfig::Mode::Agent;
            if (i + 1 < argc) {
                args.agentTask = argv[++i];
            }
        } else if (arg == "--chat") {
            args.mode = HostConfig::Mode::CLI;  // Chat is a CLI sub-mode
        } else if (arg == "--model" && i + 1 < argc) {
            args.modelPath = argv[++i];
        } else if (arg == "--workspace" && i + 1 < argc) {
            args.workspacePath = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            args.serverPort = std::stoi(argv[++i]);
        } else if (arg == "--output" && i + 1 < argc) {
            args.compileOutput = argv[++i];
        } else if (arg == "--no-gpu") {
            args.enableGPU = false;
        } else if (arg == "--no-agents") {
            args.enableAgents = false;
        } else if (arg == "--help" || arg == "-h") {
            args.showHelp = true;
        } else if (arg == "--version" || arg == "-v") {
            args.showVersion = true;
        }
    }
    
    return args;
}

//==============================================================================
// Main entry point
//==============================================================================
int main(int argc, char** argv) {
    #ifdef _WIN32
    // Enable ANSI colors on Windows
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
    #endif
    
    // Parse arguments
    CommandLineArgs args = ParseArgs(argc, argv);
    
    // Handle help/version
    if (args.showHelp) {
        PrintBanner();
        PrintHelp(argv[0]);
        return 0;
    }
    
    if (args.showVersion) {
        std::cout << "RawrXD Unified v15.0.0\n";
        std::cout << "Phase 15: Complete System Unification\n";
        return 0;
    }
    
    // Print banner for interactive modes
    if (args.mode == HostConfig::Mode::IDE || 
        args.mode == HostConfig::Mode::CLI) {
        PrintBanner();
    }
    
    // Configure host
    HostConfig config;
    config.mode = args.mode;
    config.modelPath = args.modelPath;
    config.workspacePath = args.workspacePath;
    config.serverPort = args.serverPort;
    config.enableGPU = args.enableGPU;
    config.enableAgents = args.enableAgents;
    config.enableAI = !args.modelPath.empty();
    config.enableCompiler = true;
    
    // Create and initialize host
    RawrXDHost host;
    
    if (!host.Initialize(config)) {
        std::cerr << "Failed to initialize RawrXD Host\n";
        return 1;
    }
    
    // Run in appropriate mode
    int result = 0;
    
    switch (args.mode) {
        case HostConfig::Mode::IDE:
            std::cout << "Starting IDE...\n";
            result = host.RunIDE();
            break;
            
        case HostConfig::Mode::CLI:
            std::cout << "Starting CLI...\n";
            result = host.RunCLI(argc, argv);
            break;
            
        case HostConfig::Mode::Server:
            std::cout << "Starting server on port " << config.serverPort << "...\n";
            result = host.RunServer();
            break;
            
        case HostConfig::Mode::Compile:
            if (args.compileSource.empty()) {
                std::cerr << "Error: No source file specified\n";
                std::cerr << "Use: " << argv[0] << " --compile <source> [--output <binary>]\n";
                return 1;
            }
            if (args.compileOutput.empty()) {
                // Default output name
                args.compileOutput = args.compileSource + ".exe";
            }
            result = host.RunCompile(args.compileSource, args.compileOutput);
            break;
            
        case HostConfig::Mode::Agent:
            if (args.agentTask.empty()) {
                std::cerr << "Error: No task specified\n";
                std::cerr << "Use: " << argv[0] << " --agent \"<task description>\"\n";
                return 1;
            }
            result = host.RunAgent(args.agentTask);
            break;
    }
    
    // Shutdown
    host.Shutdown();
    
    return result;
}

//==============================================================================
// Windows-specific entry point
//==============================================================================
#ifdef _WIN32
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    // Convert WinMain to standard main
    return main(__argc, __argv);
}
#endif
