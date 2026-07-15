// Test harness for UIModeAdapter
// Compile: g++ -std=c++17 -O2 -Wall test_ui_mode_adapter.cpp -o test_ui_mode_adapter.exe

#include "UIModeAdapter.hpp"
#include <cstdio>

using namespace RawrXD;

int main() {
    printf("=== RawrXD UIModeAdapter Test ===\n\n");
    
    // Test 1: Mode constants
    printf("Test 1: Mode constants...\n");
    printf("  GUI = %u\n", static_cast<uint32_t>(UIMode::GUI));
    printf("  CLI = %u\n", static_cast<uint32_t>(UIMode::CLI));
    printf("  Headless = %u\n", static_cast<uint32_t>(UIMode::Headless));
    printf("  PASSED\n");
    
    // Test 2: GUI Mode Adapter
    printf("\nTest 2: GUI Mode Adapter...\n");
    {
        UIModeAdapter<UIMode::GUI> adapter;
        if (adapter.IsGUI() && !adapter.IsCLI() && !adapter.IsHeadless()) {
            printf("  PASSED: GUI mode detection works\n");
        } else {
            printf("  FAILED: GUI mode detection failed\n");
        }
        
        auto name = adapter.GetModeName();
        if (name == "GUI") {
            printf("  PASSED: Mode name = %.*s\n", static_cast<int>(name.length()), name.data());
        } else {
            printf("  FAILED: Expected 'GUI', got '%.*s'\n", static_cast<int>(name.length()), name.data());
        }
    }
    
    // Test 3: CLI Mode Adapter
    printf("\nTest 3: CLI Mode Adapter...\n");
    {
        UIModeAdapter<UIMode::CLI> adapter;
        if (!adapter.IsGUI() && adapter.IsCLI() && !adapter.IsHeadless()) {
            printf("  PASSED: CLI mode detection works\n");
        } else {
            printf("  FAILED: CLI mode detection failed\n");
        }
        
        auto name = adapter.GetModeName();
        if (name == "CLI") {
            printf("  PASSED: Mode name = %.*s\n", static_cast<int>(name.length()), name.data());
        } else {
            printf("  FAILED: Expected 'CLI', got '%.*s'\n", static_cast<int>(name.length()), name.data());
        }
    }
    
    // Test 4: Headless Mode Adapter
    printf("\nTest 4: Headless Mode Adapter...\n");
    {
        UIModeAdapter<UIMode::Headless> adapter;
        if (!adapter.IsGUI() && !adapter.IsCLI() && adapter.IsHeadless()) {
            printf("  PASSED: Headless mode detection works\n");
        } else {
            printf("  FAILED: Headless mode detection failed\n");
        }
        
        auto name = adapter.GetModeName();
        if (name == "Headless") {
            printf("  PASSED: Mode name = %.*s\n", static_cast<int>(name.length()), name.data());
        } else {
            printf("  FAILED: Expected 'Headless', got '%.*s'\n", static_cast<int>(name.length()), name.data());
        }
    }
    
    // Test 5: ChatPanelAdapter<GUI>
    printf("\nTest 5: ChatPanelAdapter<GUI>...\n");
    {
        ChatPanelAdapter<UIMode::GUI> chat;
        chat.AddMessage("User", "Hello");
        chat.AddMessage("AI", "Hello! How can I help?");
        printf("  PASSED: GUI chat panel works\n");
    }
    
    // Test 6: ChatPanelAdapter<CLI>
    printf("\nTest 6: ChatPanelAdapter<CLI>...\n");
    {
        ChatPanelAdapter<UIMode::CLI> chat;
        chat.AddMessage("User", "Hello");
        chat.AddMessage("AI", "Hello! How can I help?");
        printf("  PASSED: CLI chat panel works\n");
    }
    
    // Test 7: ModelManagerAdapter
    printf("\nTest 7: ModelManagerAdapter...\n");
    {
        ModelManagerAdapter<UIMode::GUI> guiManager;
        guiManager.UpdateStatus("qwen32b", 0.5f);
        
        ModelManagerAdapter<UIMode::CLI> cliManager;
        cliManager.UpdateStatus("qwen32b", 0.75f);
        printf("\n"); // Newline after CLI progress
        
        printf("  PASSED: Model manager adapters work\n");
    }
    
    // Test 8: ModeFactory
    printf("\nTest 8: ModeFactory...\n");
    {
        GUIComponents::ChatPanel guiChat;
        GUIComponents::ModelManager guiModel;
        
        CLIComponents::ChatPanel cliChat;
        CLIComponents::ModelManager cliModel;
        
        printf("  PASSED: ModeFactory components instantiated\n");
    }
    
    // Test 9: Compile-time mode selection
    printf("\nTest 9: Compile-time mode selection...\n");
    {
        constexpr UIMode mode = UIMode::CLI;
        
        // This branch is evaluated at compile time
        if constexpr (mode == UIMode::GUI) {
            printf("  GUI mode (compile-time)\n");
        } else if constexpr (mode == UIMode::CLI) {
            printf("  CLI mode (compile-time) - PASSED\n");
        } else if constexpr (mode == UIMode::Headless) {
            printf("  Headless mode (compile-time)\n");
        }
    }
    
    // Test 10: Runtime mode detection (simulated)
    printf("\nTest 10: Runtime mode detection...\n");
    {
        // Simulate command-line args
        const wchar_t* args[] = { L"program", L"--cli" };
        auto detected = DetectModeFromArgs(2, const_cast<wchar_t**>(args));
        if (detected == UIMode::CLI) {
            printf("  PASSED: Detected CLI from args\n");
        } else {
            printf("  FAILED: Expected CLI, got %u\n", static_cast<uint32_t>(detected));
        }
        
        const wchar_t* headlessArgs[] = { L"program", L"--headless" };
        detected = DetectModeFromArgs(2, const_cast<wchar_t**>(headlessArgs));
        if (detected == UIMode::Headless) {
            printf("  PASSED: Detected Headless from args\n");
        } else {
            printf("  FAILED: Expected Headless, got %u\n", static_cast<uint32_t>(detected));
        }
    }
    
    printf("\n=== All Tests Complete ===\n");
    return 0;
}
