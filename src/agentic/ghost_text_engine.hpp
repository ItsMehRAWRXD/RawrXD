#pragma once

#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <chrono>
#include <memory>
#include <atomic>
#include <queue>
#include <mutex>

namespace RawrXD::Agentic {

// Ghost text suggestion with confidence and metadata
struct GhostSuggestion {
    std::string text;                    // Full command text
    std::string display_text;            // What to show inline
    std::string description;             // Human-readable description
    float confidence;                    // 0.0 - 1.0
    std::string command;                 // Associated command type
    std::vector<std::string> tags;       // Context tags
    bool is_autonomous;                  // Can auto-execute
    std::chrono::milliseconds delay;     // Animation delay
    
    // Constructor for convenience
    GhostSuggestion(const std::string& t, const std::string& d, float c, 
                    const std::string& cmd, bool auto_exec = false)
        : text(t), display_text(d), confidence(c), command(cmd), 
          is_autonomous(auto_exec), delay(std::chrono::milliseconds(100)) {}
};

// Animation state for ghost text
enum class GhostAnimationState {
    IDLE,
    TYPING,
    FADE_IN,
    VISIBLE,
    FADE_OUT,
    ACCEPTED,
    DISMISSED
};

// Real-time ghost text engine with AI-powered suggestions
class GhostTextEngine {
public:
    GhostTextEngine();
    ~GhostTextEngine();
    
    // Start ghost text generation on user input
    void StartGhost(const std::string& current_input);
    
    // Stop current ghost text
    void StopGhost();
    
    // Accept current suggestion
    GhostSuggestion Accept();
    
    // Dismiss current suggestion
    void Dismiss();
    
    // Get next/previous suggestion
    GhostSuggestion NextSuggestion();
    GhostSuggestion PreviousSuggestion();
    
    // Check if ghost text is active
    bool IsActive() const { return is_active_.load(); }
    
    // Get current suggestion
    GhostSuggestion GetCurrentSuggestion() const;
    
    // Set suggestion callback
    using SuggestionCallback = std::function<void(const GhostSuggestion&)>;
    void SetSuggestionCallback(SuggestionCallback callback);
    
    // Set acceptance callback
    using AcceptanceCallback = std::function<void(const GhostSuggestion&)>;
    void SetAcceptanceCallback(AcceptanceCallback callback);

private:
    // Generate suggestions based on input
    std::vector<GhostSuggestion> GenerateSuggestions(const std::string& input);
    
    // Pattern-based suggestions (fast path)
    std::vector<GhostSuggestion> GeneratePatternSuggestions(const std::string& input);
    
    // AI-powered suggestions using local model
    std::vector<GhostSuggestion> GenerateAISuggestions(const std::string& input);
    
    // Background worker thread
    void WorkerThread();
    
    // Debounce timer
    void ResetDebounce();
    
private:
    std::atomic<bool> is_active_{false};
    std::atomic<bool> should_stop_{false};
    std::thread worker_thread_;
    
    std::queue<std::string> input_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    
    std::vector<GhostSuggestion> current_suggestions_;
    size_t current_index_ = 0;
    std::mutex suggestions_mutex_;
    
    std::chrono::milliseconds debounce_delay_{150};
    std::chrono::steady_clock::time_point last_input_time_;
    
    SuggestionCallback suggestion_callback_;
    AcceptanceCallback acceptance_callback_;
    
    // Model interface (placeholder for actual model)
    class LocalModel;
    std::unique_ptr<LocalModel> model_;
};

// Inline AI assistant that coordinates ghost text with execution
class InlineAIAssistant {
public:
    explicit InlineAIAssistant(GhostTextEngine& ghost);
    
    // Handle user input with ghost text
    void HandleInput(const std::string& input);
    
    // Accept current ghost suggestion
    void AcceptGhost();
    
    // Dismiss ghost text
    void DismissGhost();
    
    // Navigate suggestions
    void NextSuggestion();
    void PreviousSuggestion();
    
    // Execute with visual feedback
    void ExecuteWithFeedback(const GhostSuggestion& suggestion);
    
    // Set execution callback
    using ExecutionCallback = std::function<bool(const GhostSuggestion&)>;
    void SetExecutionCallback(ExecutionCallback callback);

private:
    // Show ghost text to user
    void DisplayGhost(const GhostSuggestion& suggestion);
    
    // Hide ghost text
    void HideGhost();
    
    // Animation helpers
    void FadeIn(const GhostSuggestion& suggestion);
    void FadeOut();
    void TypewriterEffect(const std::string& text);
    
private:
    GhostTextEngine& ghost_;
    ExecutionCallback execution_callback_;
    
    GhostSuggestion current_suggestion_;
    std::atomic<bool> has_active_suggestion_{false};
};

// Progress animation for long-running tasks
class ProgressAnimator {
public:
    using WorkFunction = std::function<void()>;
    
    // Show animated progress while work executes
    static void Show(const std::string& label, WorkFunction work);
    
    // Show step-by-step progress
    static void ShowSteps(const std::vector<std::string>& steps, 
                          WorkFunction work);
    
    // Typewriter output
    static void Typewriter(const std::string& text, int delay_ms = 20);

private:
    static const char* GetSpinnerFrame(int frame);
    static const char* GetProgressBar(float progress);
};

// Ghost text renderer for different output modes
class GhostRenderer {
public:
    // Console rendering with ANSI colors
    static void RenderConsole(const GhostSuggestion& suggestion, 
                               GhostAnimationState state);
    
    // Win32 rendering for IDE integration
    static void RenderWin32(HWND hwnd, const GhostSuggestion& suggestion,
                           POINT cursor_pos);
    
    // Rich text rendering with formatting
    static std::string RenderRichText(const GhostSuggestion& suggestion);

private:
    static std::string FormatConfidence(float confidence);
    static std::string FormatTags(const std::vector<std::string>& tags);
};

} // namespace RawrXD::Agentic
