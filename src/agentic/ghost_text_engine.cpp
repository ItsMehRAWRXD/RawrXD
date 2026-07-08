#include "ghost_text_engine.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <regex>

namespace RawrXD::Agentic {

// Local model placeholder - would integrate with actual model loader
class GhostTextEngine::LocalModel {
public:
    std::string Infer(const std::string& prompt) {
        // Placeholder - would call actual model inference
        // For now, return empty to use pattern matching
        return "";
    }
};

GhostTextEngine::GhostTextEngine() 
    : model_(std::make_unique<LocalModel>()) {
    worker_thread_ = std::thread(&GhostTextEngine::WorkerThread, this);
}

GhostTextEngine::~GhostTextEngine() {
    should_stop_.store(true);
    queue_cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void GhostTextEngine::StartGhost(const std::string& current_input) {
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        // Clear old inputs
        while (!input_queue_.empty()) {
            input_queue_.pop();
        }
        input_queue_.push(current_input);
        last_input_time_ = std::chrono::steady_clock::now();
    }
    
    is_active_.store(true);
    queue_cv_.notify_one();
}

void GhostTextEngine::StopGhost() {
    is_active_.store(false);
    {
        std::lock_guard<std::mutex> lock(suggestions_mutex_);
        current_suggestions_.clear();
        current_index_ = 0;
    }
}

GhostSuggestion GhostTextEngine::Accept() {
    std::lock_guard<std::mutex> lock(suggestions_mutex_);
    if (current_index_ < current_suggestions_.size()) {
        auto suggestion = current_suggestions_[current_index_];
        if (acceptance_callback_) {
            acceptance_callback_(suggestion);
        }
        return suggestion;
    }
    return GhostSuggestion("", "", 0.0f, "", false);
}

void GhostTextEngine::Dismiss() {
    StopGhost();
}

GhostSuggestion GhostTextEngine::NextSuggestion() {
    std::lock_guard<std::mutex> lock(suggestions_mutex_);
    if (!current_suggestions_.empty()) {
        current_index_ = (current_index_ + 1) % current_suggestions_.size();
        return current_suggestions_[current_index_];
    }
    return GhostSuggestion("", "", 0.0f, "", false);
}

GhostSuggestion GhostTextEngine::PreviousSuggestion() {
    std::lock_guard<std::mutex> lock(suggestions_mutex_);
    if (!current_suggestions_.empty()) {
        current_index_ = (current_index_ + current_suggestions_.size() - 1) 
                          % current_suggestions_.size();
        return current_suggestions_[current_index_];
    }
    return GhostSuggestion("", "", 0.0f, "", false);
}

GhostSuggestion GhostTextEngine::GetCurrentSuggestion() const {
    std::lock_guard<std::mutex> lock(suggestions_mutex_);
    if (current_index_ < current_suggestions_.size()) {
        return current_suggestions_[current_index_];
    }
    return GhostSuggestion("", "", 0.0f, "", false);
}

void GhostTextEngine::SetSuggestionCallback(SuggestionCallback callback) {
    suggestion_callback_ = callback;
}

void GhostTextEngine::SetAcceptanceCallback(AcceptanceCallback callback) {
    acceptance_callback_ = callback;
}

void GhostTextEngine::WorkerThread() {
    while (!should_stop_.load()) {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        queue_cv_.wait(lock, [this] { 
            return !input_queue_.empty() || should_stop_.load(); 
        });
        
        if (should_stop_.load()) break;
        
        if (!input_queue_.empty()) {
            std::string input = input_queue_.front();
            input_queue_.pop();
            lock.unlock();
            
            // Debounce
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_input_time_);
            
            if (elapsed < debounce_delay_) {
                std::this_thread::sleep_for(debounce_delay_ - elapsed);
            }
            
            // Generate suggestions
            auto suggestions = GenerateSuggestions(input);
            
            {
                std::lock_guard<std::mutex> sugg_lock(suggestions_mutex_);
                current_suggestions_ = suggestions;
                current_index_ = 0;
            }
            
            // Notify callback
            if (suggestion_callback_ && !suggestions.empty()) {
                suggestion_callback_(suggestions[0]);
            }
        }
    }
}

std::vector<GhostSuggestion> GhostTextEngine::GenerateSuggestions(
    const std::string& input) {
    
    auto suggestions = GeneratePatternSuggestions(input);
    
    // If no pattern matches, try AI
    if (suggestions.empty()) {
        suggestions = GenerateAISuggestions(input);
    }
    
    // Sort by confidence
    std::sort(suggestions.begin(), suggestions.end(),
              [](const GhostSuggestion& a, const GhostSuggestion& b) {
                  return a.confidence > b.confidence;
              });
    
    return suggestions;
}

std::vector<GhostSuggestion> GhostTextEngine::GeneratePatternSuggestions(
    const std::string& input) {
    
    std::vector<GhostSuggestion> suggestions;
    std::string lower_input = input;
    std::transform(lower_input.begin(), lower_input.end(), 
                   lower_input.begin(), ::tolower);
    
    // Compile patterns
    if (lower_input.find("compile") != std::string::npos ||
        lower_input.find("build") != std::string::npos) {
        suggestions.emplace_back(
            "compile test.c -o test.exe",
            "test.c → test.exe",
            0.95f,
            "compile",
            false
        );
        suggestions.back().description = "Compile C code to native executable";
        suggestions.back().tags = {"C", "compiler", "native", "self-hosting"};
        
        suggestions.emplace_back(
            "compile --language cpp main.cpp",
            "main.cpp → main.exe",
            0.88f,
            "compile",
            false
        );
        suggestions.back().description = "Compile C++ code";
        suggestions.back().tags = {"C++", "compiler", "native"};
    }
    
    // Patch patterns
    if (lower_input.find("patch") != std::string::npos ||
        lower_input.find("modify") != std::string::npos ||
        lower_input.find("fix") != std::string::npos) {
        suggestions.emplace_back(
            "patch test.exe --nop 0x1000 --length 5",
            "test.exe [nop] 0x1000",
            0.92f,
            "patch",
            false
        );
        suggestions.back().description = "Patch binary with NOP sled";
        suggestions.back().tags = {"binary", "runtime", "modification", "NOP"};
        
        suggestions.emplace_back(
            "patch test.exe --replace 0x2000 \"48 31 C0\"",
            "test.exe [replace] 0x2000",
            0.85f,
            "patch",
            false
        );
        suggestions.back().description = "Replace bytes at offset";
        suggestions.back().tags = {"binary", "patch", "hex"};
    }
    
    // Analyze patterns
    if (lower_input.find("analyze") != std::string::npos ||
        lower_input.find("scan") != std::string::npos ||
        lower_input.find("check") != std::string::npos) {
        suggestions.emplace_back(
            "analyze test.exe --deep --report",
            "🔍 deep analysis with report",
            0.98f,
            "analyze",
            true  // Can auto-execute
        );
        suggestions.back().description = "Deep binary analysis with full report";
        suggestions.back().tags = {"PE", "reverse", "security", "report"};
        
        suggestions.emplace_back(
            "analyze test.exe --imports --exports",
            "📊 imports/exports only",
            0.90f,
            "analyze",
            true
        );
        suggestions.back().description = "Quick PE header analysis";
        suggestions.back().tags = {"PE", "imports", "exports"};
    }
    
    // Disassemble patterns
    if (lower_input.find("disassemble") != std::string::npos ||
        lower_input.find("disasm") != std::string::npos ||
        lower_input.find("asm") != std::string::npos) {
        suggestions.emplace_back(
            "disassemble test.exe --output disasm.json",
            "📄 disassembly to JSON",
            0.94f,
            "disassemble",
            false
        );
        suggestions.back().description = "Disassemble binary to JSON format";
        suggestions.back().tags = {"x64", "instructions", "analysis", "JSON"};
        
        suggestions.emplace_back(
            "disassemble test.exe --function main",
            "🔍 disassemble main()",
            0.87f,
            "disassemble",
            false
        );
        suggestions.back().description = "Disassemble specific function";
        suggestions.back().tags = {"function", "symbol", "disasm"};
    }
    
    // Search patterns
    if (lower_input.find("search") != std::string::npos ||
        lower_input.find("find") != std::string::npos ||
        lower_input.find("look") != std::string::npos) {
        suggestions.emplace_back(
            "search github --query \"RSA encryption\" --lang C",
            "🔍 GitHub code search",
            0.91f,
            "search",
            false
        );
        suggestions.back().description = "Search GitHub for code examples";
        suggestions.back().tags = {"github", "search", "code"};
    }
    
    // Native toolchain patterns
    if (lower_input.find("native") != std::string::npos ||
        lower_input.find("toolchain") != std::string::npos) {
        suggestions.emplace_back(
            "native-compile bridge.json output.asm",
            "JSON → Native ASM",
            0.93f,
            "native-compile",
            false
        );
        suggestions.back().description = "Compile JSON to native assembly";
        suggestions.back().tags = {"native", "toolchain", "JSON", "ASM"};
    }
    
    // Autonomous patterns
    if (lower_input.find("reverse engineer") != std::string::npos ||
        lower_input.find("audit") != std::string::npos ||
        lower_input.find("investigate") != std::string::npos) {
        suggestions.emplace_back(
            "autonomous --goal \"reverse engineer test.exe and find vulnerabilities\"",
            "🤖 autonomous reverse engineering",
            0.96f,
            "autonomous",
            false
        );
        suggestions.back().description = "Autonomous multi-step analysis";
        suggestions.back().tags = {"autonomous", "AI", "reverse", "security"};
    }
    
    return suggestions;
}

std::vector<GhostSuggestion> GhostTextEngine::GenerateAISuggestions(
    const std::string& input) {
    
    std::vector<GhostSuggestion> suggestions;
    
    // Use local model for intelligent suggestions
    std::string prompt = R"({
        "context": "RawrXD reverse engineering tool",
        "input": ")" + input + R"(",
        "task": "Suggest completions",
        "format": "JSON array with text, display, confidence"
    })";
    
    // This would call the actual model
    // auto response = model_->Infer(prompt);
    // For now, return empty to rely on patterns
    
    return suggestions;
}

// InlineAIAssistant implementation
InlineAIAssistant::InlineAIAssistant(GhostTextEngine& ghost) 
    : ghost_(ghost) {
    
    ghost_.SetSuggestionCallback([this](const GhostSuggestion& sugg) {
        DisplayGhost(sugg);
    });
}

void InlineAIAssistant::HandleInput(const std::string& input) {
    ghost_.StartGhost(input);
}

void InlineAIAssistant::AcceptGhost() {
    auto suggestion = ghost_.Accept();
    if (!suggestion.text.empty()) {
        HideGhost();
        ExecuteWithFeedback(suggestion);
    }
}

void InlineAIAssistant::DismissGhost() {
    ghost_.Dismiss();
    HideGhost();
}

void InlineAIAssistant::NextSuggestion() {
    auto suggestion = ghost_.NextSuggestion();
    DisplayGhost(suggestion);
}

void InlineAIAssistant::PreviousSuggestion() {
    auto suggestion = ghost_.PreviousSuggestion();
    DisplayGhost(suggestion);
}

void InlineAIAssistant::ExecuteWithFeedback(const GhostSuggestion& suggestion) {
    if (execution_callback_) {
        ProgressAnimator::Show("Executing", [&]() {
            execution_callback_(suggestion);
        });
    }
}

void InlineAIAssistant::SetExecutionCallback(ExecutionCallback callback) {
    execution_callback_ = callback;
}

void InlineAIAssistant::DisplayGhost(const GhostSuggestion& suggestion) {
    current_suggestion_ = suggestion;
    has_active_suggestion_.store(true);
    GhostRenderer::RenderConsole(suggestion, GhostAnimationState::FADE_IN);
}

void InlineAIAssistant::HideGhost() {
    has_active_suggestion_.store(false);
    // Clear ghost text from display
    std::cout << "\r" << std::string(80, ' ') << "\r" << std::flush;
}

// ProgressAnimator implementation
void ProgressAnimator::Show(const std::string& label, WorkFunction work) {
    std::atomic<bool> done{false};
    int frame = 0;
    
    std::thread anim([&]() {
        while (!done.load()) {
            std::cout << "\r" << GetSpinnerFrame(frame++) << " " << label << "...";
            std::cout.flush();
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
        }
    });
    
    work();
    done.store(true);
    anim.join();
    
    std::cout << "\r✅ " << label << " complete!" << std::endl;
}

void ProgressAnimator::ShowSteps(const std::vector<std::string>& steps, 
                                  WorkFunction work) {
    // Show step headers
    for (size_t i = 0; i < steps.size(); i++) {
        std::cout << "  " << (i + 1) << ". " << steps[i] << std::endl;
    }
    std::cout << std::endl;
    
    work();
}

void ProgressAnimator::Typewriter(const std::string& text, int delay_ms) {
    for (char c : text) {
        std::cout << c << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
}

const char* ProgressAnimator::GetSpinnerFrame(int frame) {
    static const char* frames[] = {
        "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
    };
    return frames[frame % 10];
}

const char* ProgressAnimator::GetProgressBar(float progress) {
    static char bar[32];
    int filled = static_cast<int>(progress * 20);
    filled = std::min(filled, 20);
    
    bar[0] = '[';
    for (int i = 0; i < 20; i++) {
        bar[i + 1] = (i < filled) ? '█' : '░';
    }
    bar[21] = ']';
    bar[22] = '\0';
    
    return bar;
}

// GhostRenderer implementation
void GhostRenderer::RenderConsole(const GhostSuggestion& suggestion, 
                                   GhostAnimationState state) {
    if (state == GhostAnimationState::FADE_IN || 
        state == GhostAnimationState::VISIBLE) {
        
        std::cout << "\033[2m";  // Dim text
        std::cout << "┌─────────────────────────────────────────────────────────────┐" << std::endl;
        std::cout << "│ 👻 " << suggestion.display_text;
        
        if (suggestion.confidence > 0.9f) {
            std::cout << " 🔥";
        } else if (suggestion.confidence > 0.7f) {
            std::cout << " ✓";
        }
        std::cout << std::endl;
        
        std::cout << "│   " << suggestion.text << std::endl;
        
        if (!suggestion.description.empty()) {
            std::cout << "│   " << suggestion.description << std::endl;
        }
        
        std::cout << "│   " << FormatConfidence(suggestion.confidence) 
                  << " " << FormatTags(suggestion.tags) << std::endl;
        
        std::cout << "│   [TAB] accept  [ESC] cancel  [↑↓] navigate" << std::endl;
        std::cout << "└─────────────────────────────────────────────────────────────┘" << std::endl;
        std::cout << "\033[0m";  // Reset
    }
}

void GhostRenderer::RenderWin32(HWND hwnd, const GhostSuggestion& suggestion,
                                  POINT cursor_pos) {
    // Win32-specific rendering would go here
    // This would draw ghost text near the cursor in the IDE
}

std::string GhostRenderer::RenderRichText(const GhostSuggestion& suggestion) {
    std::ostringstream oss;
    oss << "<ghost>" << suggestion.display_text << "</ghost>";
    return oss.str();
}

std::string GhostRenderer::FormatConfidence(float confidence) {
    std::ostringstream oss;
    oss << "confidence:" << static_cast<int>(confidence * 100) << "%";
    return oss.str();
}

std::string GhostRenderer::FormatTags(const std::vector<std::string>& tags) {
    std::ostringstream oss;
    oss << "#";
    for (size_t i = 0; i < tags.size(); i++) {
        if (i > 0) oss << " #";
        oss << tags[i];
    }
    return oss.str();
}

} // namespace RawrXD::Agentic
