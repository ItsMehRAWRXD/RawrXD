// ============================================================================
// AIInferenceBridge.hpp - Live Data Path: GGUF Runtime -> Ghost Text
// ============================================================================
// Bridges Deep2Engine streaming inference to IDE ghost text display
// ============================================================================

#pragma once

#include <Windows.h>
#include <functional>
#include <string>
#include <atomic>
#include <mutex>
#include <chrono>

// Forward declarations
namespace Deep2 {
    class Deep2Engine;
}

namespace RawrXD {
namespace IDE {

// ============================================================================
// Generation State
// ============================================================================
enum class GenerationState {
    Idle,           // No generation in progress
    Starting,       // Generation requested, waiting for first token
    Streaming,      // Actively receiving tokens
    Finalizing,     // Stream complete, finalizing display
    Cancelled,      // Generation was cancelled
    Error           // Generation failed
};

// ============================================================================
// Telemetry Data
// ============================================================================
struct CompletionTelemetry {
    uint64_t requestId = 0;
    std::chrono::steady_clock::time_point requestTime;
    std::chrono::steady_clock::time_point firstTokenTime;
    std::chrono::steady_clock::time_point completionTime;
    
    size_t tokensGenerated = 0;
    size_t tokensAccepted = 0;
    size_t tokensDismissed = 0;
    
    double firstTokenLatencyMs = 0.0;      // Time to first token
    double totalGenerationTimeMs = 0.0;  // Total generation time
    double tokensPerSecond = 0.0;
    
    bool wasAccepted = false;
    bool wasCancelled = false;
};

// ============================================================================
// Streaming Callback Interface
// ============================================================================
using TokenCallback = std::function<void(const char* token, size_t len, bool isFirst)>;
using CompletionCallback = std::function<void(const std::string& fullCompletion, bool wasCancelled)>;
using ErrorCallback = std::function<void(const char* errorMsg)>;

// ============================================================================
// AI Inference Bridge
// ============================================================================
// Thread-safe bridge between Deep2Engine and IDE ghost text
// ============================================================================
class AIInferenceBridge {
public:
    AIInferenceBridge();
    ~AIInferenceBridge();
    
    // Initialize with Deep2Engine instance
    bool Initialize(Deep2::Deep2Engine* engine);
    void Shutdown();
    
    // ------------------------------------------------------------------------
    // Generation Control
    // ------------------------------------------------------------------------
    
    // Start a new completion generation
    // context: Code context (lines before cursor)
    // cursorLine: Current line number (0-based)
    // cursorCol: Current column position
    // maxTokens: Maximum tokens to generate
    // Returns: Generation request ID (0 on failure)
    uint64_t StartGeneration(const std::string& context, 
                           int cursorLine, 
                           int cursorCol,
                           size_t maxTokens = 256);
    
    // Cancel current generation
    void CancelGeneration();
    
    // Check if generation is active
    bool IsGenerating() const;
    
    // Get current generation state
    GenerationState GetState() const;
    
    // Get current generation ID
    uint64_t GetCurrentGenerationId() const;
    
    // ------------------------------------------------------------------------
    // Callback Registration
    // ------------------------------------------------------------------------
    
    // Called for each token as it arrives (for ghost text streaming)
    void SetTokenCallback(TokenCallback callback);
    
    // Called when generation completes (for final acceptance)
    void SetCompletionCallback(CompletionCallback callback);
    
    // Called on generation error
    void SetErrorCallback(ErrorCallback callback);
    
    // ------------------------------------------------------------------------
    // Telemetry
    // ------------------------------------------------------------------------
    
    // Get telemetry for last completion
    const CompletionTelemetry& GetLastTelemetry() const;
    
    // Reset telemetry
    void ResetTelemetry();
    
    // Export telemetry to JSON string
    std::string ExportTelemetryJson() const;
    
private:
    // Internal generation worker
    void GenerationWorker(uint64_t generationId,
                          std::string context,
                          int cursorLine,
                          int cursorCol,
                          size_t maxTokens);
    
    // Detokenize and notify
    void ProcessToken(int tokenId, bool isFirst);
    
    // State
    Deep2::Deep2Engine* engine_ = nullptr;
    std::atomic<GenerationState> state_{GenerationState::Idle};
    std::atomic<uint64_t> currentGenerationId_{0};
    std::atomic<uint64_t> nextGenerationId_{1};
    std::atomic<bool> cancelRequested_{false};
    
    // Threading
    HANDLE generationThread_ = nullptr;
    std::mutex callbackMutex_;
    
    // Callbacks
    TokenCallback tokenCallback_;
    CompletionCallback completionCallback_;
    ErrorCallback errorCallback_;
    
    // Accumulated completion
    std::mutex completionMutex_;
    std::string currentCompletion_;
    std::vector<int> generatedTokens_;
    
    // Telemetry
    CompletionTelemetry telemetry_;
    std::mutex telemetryMutex_;
};

// ============================================================================
// Global Bridge Access
// ============================================================================
// Singleton-like access for IDE integration
// ============================================================================

// Initialize the global bridge
bool AIInferenceBridge_Initialize(Deep2::Deep2Engine* engine);

// Shutdown the global bridge
void AIInferenceBridge_Shutdown();

// Get the global bridge instance (nullptr if not initialized)
AIInferenceBridge* AIInferenceBridge_Get();

// Convenience: Start generation via global bridge
uint64_t AIInferenceBridge_Start(const std::string& context, 
                                int cursorLine, 
                                int cursorCol,
                                size_t maxTokens = 256);

// Convenience: Cancel via global bridge
void AIInferenceBridge_Cancel();

// Convenience: Check if generating via global bridge
bool AIInferenceBridge_IsGenerating();

} // namespace IDE
} // namespace RawrXD
