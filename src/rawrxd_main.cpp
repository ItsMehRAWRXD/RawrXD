// RawrXD Unified Agent CLI
// One command to rule them all - with ghost text and autonomous execution

#include "agentic/ghost_text_engine.hpp"
#include "agentic/autonomous_agent.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <conio.h>

using namespace RawrXD::Agentic;

// Terminal utilities
class Terminal {
public:
    static void ClearLine() {
        std::cout << "\r" << std::string(80, ' ') << "\r" << std::flush;
    }
    
    static void MoveUp(int lines = 1) {
        for (int i = 0; i < lines; i++) {
            std::cout << "\033[A";
        }
    }
    
    static void ClearScreen() {
        std::cout << "\033[2J\033[H";
    }
    
    static void SetColor(int color) {
        std::cout << "\033[" << color << "m";
    }
    
    static void ResetColor() {
        std::cout << "\033[0m";
    }
    
    static void HideCursor() {
        std::cout << "\033[?25l";
    }
    
    static void ShowCursor() {
        std::cout << "\033[?25h";
    }
};

// Interactive mode with ghost text
void InteractiveMode() {
    Terminal::ClearScreen();
    
    std::cout << "╔═══════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  👻 RawrXD Ghost Text Interactive Mode                    ║" << std::endl;
    std::cout << "║                                                               ║" << std::endl;
    std::cout << "║  Type your request and ghost text will suggest completions  ║" << std::endl;
    std::cout << "║  [TAB] Accept  [ESC] Cancel  [↑↓] Navigate suggestions      ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
    
    GhostTextEngine ghost;
    InlineAIAssistant assistant(ghost);
    AutonomousAgent agent;
    
    // Set up execution callback
    assistant.SetExecutionCallback([&](const GhostSuggestion& sugg) -> bool {
        std::cout << std::endl;
        
        // Execute with autonomous agent
        auto result = agent.ExecuteWithGhost(sugg.text, &ghost);
        
        return result.success;
    });
    
    // Set up approval callback for autonomous steps
    agent.SetApprovalCallback([](const AutonomousStep& step) -> bool {
        std::cout << "⏸️  Approve: " << step.description << "? [Y/n] ";
        char response = _getch();
        std::cout << std::endl;
        return (response == 'y' || response == 'Y' || response == '\r');
    });
    
    std::string input;
    bool has_ghost = false;
    
    while (true) {
        std::cout << "\033[1mrawrxd> \033[0m" << std::flush;
        
        input.clear();
        has_ghost = false;
        
        while (true) {
            if (_kbhit()) {
                char ch = _getch();
                
                // Handle special keys
                if (ch == 27) { // ESC
                    if (has_ghost) {
                        assistant.DismissGhost();
                        has_ghost = false;
                    } else {
                        input.clear();
                        std::cout << std::endl;
                    }
                    break;
                }
                
                if (ch == '\r' || ch == '\n') { // Enter
                    std::cout << std::endl;
                    if (!input.empty()) {
                        if (has_ghost) {
                            assistant.AcceptGhost();
                        } else {
                            // Execute directly
                            auto result = agent.ExecuteWithGhost(input, &ghost);
                        }
                    }
                    break;
                }
                
                if (ch == '\t') { // TAB - accept ghost
                    if (has_ghost) {
                        assistant.AcceptGhost();
                        break;
                    }
                    continue;
                }
                
                if (ch == 0 || ch == 224) { // Extended key
                    char ext = _getch();
                    if (ext == 72) { // Up arrow
                        if (has_ghost) {
                            assistant.PreviousSuggestion();
                        }
                        continue;
                    }
                    if (ext == 80) { // Down arrow
                        if (has_ghost) {
                            assistant.NextSuggestion();
                        }
                        continue;
                    }
                    continue;
                }
                
                if (ch == 8) { // Backspace
                    if (!input.empty()) {
                        input.pop_back();
                        std::cout << "\b \b" << std::flush;
                        
                        if (input.empty() && has_ghost) {
                            assistant.DismissGhost();
                            has_ghost = false;
                        }
                    }
                    continue;
                }
                
                // Regular character
                if (ch >= 32 && ch < 127) {
                    input += ch;
                    std::cout << ch << std::flush;
                    
                    // Trigger ghost text
                    if (input.length() >= 3) {
                        assistant.HandleInput(input);
                        has_ghost = true;
                    }
                }
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        if (input == "exit" || input == "quit") {
            std::cout << "\n👋 Goodbye!" << std::endl;
            break;
        }
        
        std::cout << std::endl;
    }
}

// Quick command mode
int QuickMode(int argc, char** argv) {
    // Build the request string
    std::string request;
    for (int i = 1; i < argc; i++) {
        request += argv[i];
        if (i < argc - 1) request += " ";
    }
    
    std::cout << "╔═══════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  🚀 RawrXD Autonomous Agent                                 ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
    std::cout << "📝 Request: " << request << std::endl;
    std::cout << std::endl;
    
    // Create ghost text engine for suggestions
    GhostTextEngine ghost;
    auto suggestions = ghost.GenerateSuggestions(request);
    
    if (!suggestions.empty()) {
        std::cout << "👻 Suggested commands:" << std::endl;
        for (size_t i = 0; i < std::min(suggestions.size(), size_t(3)); i++) {
            const auto& s = suggestions[i];
            std::cout << "  " << (i+1) << ". " << s.display_text;
            if (s.confidence > 0.9f) std::cout << " 🔥";
            std::cout << std::endl;
        }
        std::cout << std::endl;
    }
    
    // Execute with autonomous agent
    AutonomousAgent agent;
    
    agent.SetApprovalCallback([](const AutonomousStep& step) -> bool {
        if (!step.requires_approval) return true;
        
        std::cout << "⏸️  Approve: " << step.description << "? [Y/n] ";
        char response = _getch();
        std::cout << std::endl;
        return (response == 'y' || response == 'Y' || response == '\r');
    });
    
    agent.SetProgressCallback([](const AutonomousStep& step, float progress) {
        int bar_width = 30;
        int pos = static_cast<int>(bar_width * progress);
        
        std::cout << "\r[";
        for (int i = 0; i < bar_width; i++) {
            if (i < pos) std::cout << "█";
            else std::cout << "░";
        }
        std::cout << "] " << std::setw(3) << static_cast<int>(progress * 100) << "%";
        std::cout.flush();
    });
    
    auto result = agent.ExecuteWithGhost(request, &ghost);
    
    std::cout << std::endl << std::endl;
    
    if (result.success) {
        std::cout << "✅ Execution successful!" << std::endl;
        if (!result.output.empty()) {
            std::cout << "📄 Output: " << result.output << std::endl;
        }
    } else {
        std::cout << "❌ Execution failed" << std::endl;
        if (!result.error.empty()) {
            std::cout << "💥 Error: " << result.error << std::endl;
        }
    }
    
    std::cout << "⏱️  Duration: " << result.duration.count() << "ms" << std::endl;
    
    return result.success ? 0 : 1;
}

// Show help
void ShowHelp() {
    std::cout << "RawrXD Unified Agent CLI" << std::endl;
    std::cout << "========================" << std::endl;
    std::cout << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  rawrxd                    - Interactive ghost text mode" << std::endl;
    std::cout << "  rawrxd \"<request>\"       - Execute request autonomously" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  rawrxd \"compile hello.c\"" << std::endl;
    std::cout << "  rawrxd \"patch test.exe to return 0\"" << std::endl;
    std::cout << "  rawrxd \"analyze malware.exe\"" << std::endl;
    std::cout << "  rawrxd \"disassemble app.exe\"" << std::endl;
    std::cout << "  rawrxd \"search for buffer overflow examples\"" << std::endl;
    std::cout << "  rawrxd \"reverse engineer this binary\"" << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  compile    - Compile source to native executable" << std::endl;
    std::cout << "  patch      - Apply binary patches" << std::endl;
    std::cout << "  analyze    - Deep binary analysis" << std::endl;
    std::cout << "  disassemble- Disassemble to JSON" << std::endl;
    std::cout << "  search     - Search GitHub/code" << std::endl;
    std::cout << "  native-*   - Native toolchain commands" << std::endl;
}

int main(int argc, char** argv) {
    // Enable ANSI colors on Windows
    #ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
    #endif
    
    if (argc < 2) {
        // Interactive mode
        InteractiveMode();
        return 0;
    }
    
    // Check for help
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        ShowHelp();
        return 0;
    }
    
    // Quick command mode
    return QuickMode(argc, argv);
}
