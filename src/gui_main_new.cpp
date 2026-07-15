// RawrXD IDE - Full GUI Implementation
// Entry point for the complete IDE with Chat, Editor, and File Browser

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <memory>
#include <string>
#include <iostream>
#include <fstream>

#include "gui/RawrXD_IDEWindow.h"
#include "backend/ollama_client.h"
#include "../logger.h"

// Link required libraries
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

// Global Ollama client
std::shared_ptr<RawrXD::Backend::OllamaClient> g_ollamaClient;

// Function to fetch models from Ollama
std::vector<std::string> FetchOllamaModels(const std::string& baseUrl) {
    std::vector<std::string> models;
    
    // Try to fetch from Ollama API
    RawrXD::Backend::OllamaClient client(baseUrl);
    
    // For now, return default models
    // In production, this would call /api/tags endpoint
    models = {
        "llama3.2:3b",
        "phi3:mini", 
        "codellama:7b",
        "qwen2.5:14b",
        "mistral:7b",
        "gemma:7b"
    };
    
    return models;
}

// Parse command line
struct CommandLineArgs {
    bool consoleMode = false;
    bool showHelp = false;
    std::string model;
    std::string prompt;
    int maxTokens = 32;
    std::string ollamaUrl = "http://localhost:11434";
};

CommandLineArgs ParseCommandLine(int argc, wchar_t* argv[]) {
    CommandLineArgs args;
    
    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        
        if (arg == L"--console" || arg == L"-c") {
            args.consoleMode = true;
        } else if (arg == L"--help" || arg == L"-h") {
            args.showHelp = true;
        } else if ((arg == L"--model" || arg == L"-m") && i + 1 < argc) {
            int len = WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, nullptr, 0, nullptr, nullptr);
            args.model.resize(len);
            WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, &args.model[0], len, nullptr, nullptr);
        } else if ((arg == L"--prompt" || arg == L"-p") && i + 1 < argc) {
            int len = WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, nullptr, 0, nullptr, nullptr);
            args.prompt.resize(len);
            WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, &args.prompt[0], len, nullptr, nullptr);
        } else if ((arg == L"--max-tokens" || arg == L"-t") && i + 1 < argc) {
            args.maxTokens = _wtoi(argv[++i]);
        } else if ((arg == L"--ollama-url" || arg == L"-u") && i + 1 < argc) {
            int len = WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, nullptr, 0, nullptr, nullptr);
            args.ollamaUrl.resize(len);
            WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, &args.ollamaUrl[0], len, nullptr, nullptr);
        }
    }
    
    return args;
}

// Console mode inference
int RunConsoleMode(const CommandLineArgs& args) {
    // Allocate console
    AllocConsole();
    FILE* dummy;
    freopen_s(&dummy, "CONOUT$", "w", stdout);
    freopen_s(&dummy, "CONOUT$", "w", stderr);
    
    std::cout << "RawrXD IDE v1.0 - Console Mode\n";
    std::cout << "==============================\n\n";
    
    if (args.model.empty()) {
        std::cout << "Error: No model specified. Use --model \u003cname\u003e\n";
        return 1;
    }
    
    if (args.prompt.empty()) {
        std::cout << "Error: No prompt specified. Use --prompt \u003ctext\u003e\n";
        return 1;
    }
    
    std::cout << "[inference] Using Ollama backend\n";
    std::cout << "[inference] Model: " << args.model << "\n";
    std::cout << "[inference] Prompt: " << args.prompt << "\n";
    std::cout << "[inference] Connecting to Ollama at " << args.ollamaUrl << "...\n\n";
    
    // Create client and send request
    RawrXD::Backend::OllamaClient client(args.ollamaUrl);
    RawrXD::Backend::OllamaGenerateRequest request;
    request.model = args.model;
    request.prompt = args.prompt;
    request.stream = false;
    request.options["num_predict"] = args.maxTokens;
    
    std::string fullResponse;
    bool success = client.generate(request,
        [&fullResponse](const std::string& chunk) {
            std::cout << chunk;
            fullResponse += chunk;
        },
        [&](bool ok, const std::string& response) {
            if (ok) {
                std::cout << "\n\n[inference] Complete.\n";
            } else {
                std::cerr << "\n\n[inference] Failed: " << response << "\n";
            }
        }
    );
    
    return success ? 0 : 1;
}

// Show help
void ShowHelp() {
    MessageBoxW(nullptr,
        L"RawrXD IDE v1.0 - AI-Powered Development Environment\n\n"
        L"Usage: RawrXD-Win32IDE.exe [options]\n\n"
        L"Options:\n"
        L"  --console, -c          Run in console mode (no GUI)\n"
        L"  --model, -m \u003cname\u003e    Specify model for inference\n"
        L"  --prompt, -p \u003ctext\u003e   Prompt for text generation\n"
        L"  --max-tokens, -t \u003cn\u003e   Max tokens (default: 32)\n"
        L"  --ollama-url, -u \u003curl\u003e Ollama URL (default: http://localhost:11434)\n"
        L"  --help, -h             Show this help\n\n"
        L"GUI Mode (default):\n"
        L"  Launches the full IDE with Chat, Editor, and File Browser\n\n"
        L"Console Mode:\n"
        L"  Use --console for command-line inference\n"
        L"  Example: RawrXD --console --model llama3.2:3b --prompt \"Hello\"",
        L"RawrXD IDE Help",
        MB_OK | MB_ICONINFORMATION);
}

// Main entry point
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    
    // Parse command line
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    
    CommandLineArgs args = ParseCommandLine(argc, argv);
    LocalFree(argv);
    
    // Show help if requested
    if (args.showHelp) {
        ShowHelp();
        return 0;
    }
    
    // Console mode
    if (args.consoleMode) {
        return RunConsoleMode(args);
    }
    
    // GUI Mode - Full IDE
    // Initialize common controls
    INITCOMMONCONTROLSEX iccex = {};
    iccex.dwSize = sizeof(iccex);
    iccex.dwICC = ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&iccex);
    
    // Initialize logger
    RawrXD::Logger::Init();
    LOG_INFO("RawrXD IDE v1.0 starting...");
    
    // Create Ollama client
    g_ollamaClient = std::make_shared<RawrXD::Backend::OllamaClient>(args.ollamaUrl);
    
    // Create and run IDE
    RawrXD::GUI::IDEWindow ide;
    if (!ide.Create(hInstance, nCmdShow)) {
        LOG_ERROR("Failed to create IDE window");
        MessageBoxW(nullptr, L"Failed to create IDE window", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    // Set Ollama client
    ide.SetOllamaClient(g_ollamaClient);
    
    // Fetch and set available models
    auto models = FetchOllamaModels(args.ollamaUrl);
    if (auto* chat = ide.GetChatWindow()) {
        chat->SetAvailableModels(models);
    }
    
    LOG_INFO("IDE initialized, entering message loop");
    
    // Run message loop
    int result = ide.Run();
    
    LOG_INFO("RawrXD IDE shutting down");
    RawrXD::Logger::Shutdown();
    
    return result;
}
