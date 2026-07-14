// RawrXD Agentic IDE - Main Entry Point
// Production-ready native Win32 IDE with zero dependencies

#include "core/application.h"
#include <windows.h>
#include <shellapi.h>
#include <vector>
#include <string>

// Link required libraries
#pragma comment(lib, "shell32.lib")

// Parse command line arguments
RawrXD::AppConfig ParseCommandLine(int argc, char* argv[]) {
    RawrXD::AppConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--workspace" || arg == "-w") {
            if (i + 1 < argc) {
                config.workspacePath = argv[++i];
            }
        }
        else if (arg == "--extensions" || arg == "-e") {
            if (i + 1 < argc) {
                config.extensionsPath = argv[++i];
            }
        }
        else if (arg == "--settings" || arg == "-s") {
            if (i + 1 < argc) {
                config.settingsPath = argv[++i];
            }
        }
        else if (arg == "--no-lsp") {
            config.enableLSP = false;
        }
        else if (arg == "--no-debugger") {
            config.enableDebugger = false;
        }
        else if (arg == "--no-terminal") {
            config.enableTerminal = false;
        }
        else if (arg == "--no-git") {
            config.enableGit = false;
        }
        else if (arg == "--no-extensions") {
            config.enableExtensions = false;
        }
        else if (arg == "--no-ai") {
            config.enableAI = false;
        }
        else if (arg == "--model" || arg == "-m") {
            if (i + 1 < argc) {
                config.defaultModel = argv[++i];
            }
        }
        else if (arg == "--maximized" || arg == "-max") {
            config.maximized = true;
        }
        else if (arg == "--width") {
            if (i + 1 < argc) {
                config.windowWidth = std::atoi(argv[++i]);
            }
        }
        else if (arg == "--height") {
            if (i + 1 < argc) {
                config.windowHeight = std::atoi(argv[++i]);
            }
        }
        else if (arg == "--help" || arg == "-h" || arg == "/?") {
            // Help will be printed and app will exit
            return config;
        }
        else if (arg[0] != '-' && config.workspacePath.empty()) {
            // Positional argument - treat as workspace path
            config.workspacePath = arg;
        }
    }
    
    return config;
}

void PrintHelp() {
    const char* helpText = R"(
RawrXD Agentic IDE - Native Win32 IDE with AI Integration

Usage: RawrXD-AgenticIDE [options] [workspace_path]

Options:
  -w, --workspace <path>    Open workspace at specified path
  -e, --extensions <path>   Set extensions directory
  -s, --settings <path>    Set settings file path
  -m, --model <name>       Set default AI model
  --no-lsp                 Disable Language Server Protocol
  --no-debugger            Disable debugger integration
  --no-terminal            Disable embedded terminal
  --no-git                 Disable Git integration
  --no-extensions          Disable extension host
  --no-ai                  Disable AI features
  --maximized, -max        Start maximized
  --width <pixels>        Set window width
  --height <pixels>       Set window height
  -h, --help               Show this help message

Examples:
  RawrXD-AgenticIDE
  RawrXD-AgenticIDE C:\MyProject
  RawrXD-AgenticIDE -w C:\MyProject --no-ai
  RawrXD-AgenticIDE --maximized --model codestral-22b

)";
    
    MessageBoxA(nullptr, helpText, "RawrXD Agentic IDE Help", MB_OK | MB_ICONINFORMATION);
}

// Windows entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Convert command line to argc/argv
    int argc = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argc);
    
    std::vector<std::string> args;
    std::vector<char*> argvPtrs;
    
    for (int i = 0; i < argc; ++i) {
        int len = WideCharToMultiByte(CP_UTF8, 0, argvW[i], -1, nullptr, 0, nullptr, nullptr);
        std::string arg(len - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, argvW[i], -1, &arg[0], len, nullptr, nullptr);
        args.push_back(arg);
    }
    
    LocalFree(argvW);
    
    // Create argv array
    for (auto& arg : args) {
        argvPtrs.push_back(const_cast<char*>(arg.c_str()));
    }
    
    // Check for help
    for (int i = 1; i < argc; ++i) {
        std::string arg = argvPtrs[i];
        if (arg == "--help" || arg == "-h" || arg == "/?") {
            PrintHelp();
            return 0;
        }
    }
    
    // Parse configuration
    RawrXD::AppConfig config = ParseCommandLine(argc, argvPtrs.data());
    
    // Initialize application
    RawrXD::Application& app = RawrXD::Application::Instance();
    
    if (!app.Initialize(config)) {
        MessageBoxA(nullptr, 
            "Failed to initialize RawrXD Agentic IDE.\n\n"
            "Please check that all dependencies are installed and try again.",
            "Initialization Error", 
            MB_OK | MB_ICONERROR);
        return 1;
    }
    
    // Open workspace if specified
    if (!config.workspacePath.empty()) {
        if (!app.OpenWorkspace(config.workspacePath)) {
            app.ShowError("Workspace Error", 
                "Failed to open workspace: " + config.workspacePath);
        }
    }
    
    // Run main message loop
    int result = app.Run();
    
    // Shutdown
    app.Shutdown();
    
    return result;
}

// Console entry point (for debugging)
int main(int argc, char* argv[]) {
    return WinMain(GetModuleHandleA(nullptr), nullptr, nullptr, SW_SHOW);
}