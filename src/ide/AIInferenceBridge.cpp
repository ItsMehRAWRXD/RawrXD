// ============================================================================
// AIInferenceBridge.cpp - Live Data Path Implementation
// ============================================================================
// Bridges Deep2Engine streaming inference to IDE ghost text display
// ============================================================================

#include "AIInferenceBridge.hpp"
#include "../deep2/Deep2Engine.h"
#include "GhostTextWndProc.hpp"
#include <thread>
#include <sstream>

namespace RawrXD {
namespace IDE {

// ============================================================================
// Global Instance
// ============================================================================
static AIInferenceBridge* g_pGlobalBridge = nullptr;

// ============================================================================
// Construction / Destruction
// ============================================================================
AIInferenceBridge::AIInferenceBridge() = default;

AIInferenceBridge::~AIInferenceBridge() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================
bool AIInferenceBridge::Initialize(Deep2::Deep2Engine* engine) {
    if (!engine) return false;
    if (engine_) return true; // Already initialized
    
    engine_ = engine;
    state_ = GenerationState::Idle;
    currentGenerationId_ = 0;
    nextGenerationId_ = 1;
    cancelRequested_ = false;
    
    return true;
}

void AIInferenceBridge::Shutdown() {
    CancelGeneration();
    
    // Wait for thread to complete
    if (generationThread_) {
        WaitForSingleObject(generationThread_, 5000); // 5 second timeout
        CloseHandle(generationThread_);
        generationThread_ = nullptr;
    }
    
    engine_ = nullptr;
    state_ = GenerationState::Idle;
}

// ============================================================================
// Generation Control
// ============================================================================
uint64_t AIInferenceBridge::StartGeneration(const std::string& context, 
                                           int cursorLine, 
                                           int cursorCol,
                                           size_t maxTokens) {
    if (!engine_ || !engine_->isModelLoaded()) {
        if (errorCallback_) {
            errorCallback_("Engine not initialized or model not loaded");
        }
        return 0;
    }
    
    // Cancel any existing generation
    CancelGeneration();
    
    // Wait for previous thread to complete
    if (generationThread_) {
        WaitForSingleObject(generationThread_, 1000);
        CloseHandle(generationThread_);
        generationThread_ = nullptr;
    }
    
    // Generate new ID
    uint64_t genId = nextGenerationId_.fetch_add(1);
    currentGenerationId_ = genId;
    cancelRequested_ = false;
    
    // Clear previous completion
    {
        std::lock_guard<std::mutex> lock(completionMutex_);
        currentCompletion_.clear();
        generatedTokens_.clear();
    }
    
    // Initialize telemetry
    {
        std::lock_guard<std::mutex> lock(telemetryMutex_);
        telemetry_ = CompletionTelemetry{};
        telemetry_.requestId = genId;
        telemetry_.requestTime = std::chrono::steady_clock::now();
    }
    
    // Start generation thread
    state_ = GenerationState::Starting;
    
    // Create thread parameters
    struct ThreadParams {
        AIInferenceBridge* bridge;
        uint64_t genId;
        std::string context;
        int cursorLine;
        int cursorCol;
        size_t maxTokens;
    };
    
    auto params = new ThreadParams{this, genId, context, cursorLine, cursorCol, maxTokens};
    
    generationThread_ = CreateThread(nullptr, 0,
        [](LPVOID lpParam) -> DWORD {
            auto* p = static_cast<ThreadParams*>(lpParam);
            p->bridge->GenerationWorker(p->genId, p->context, p->cursorLine, 
                                      p->cursorCol, p->maxTokens);
            delete p;
            return 0;
        }, params, 0, nullptr);
    
    if (!generationThread_) {
        state_ = GenerationState::Error;
        currentGenerationId_ = 0;
        delete params;
        return 0;
    }
    
    return genId;
}

void AIInferenceBridge::CancelGeneration() {
    if (state_ == GenerationState::Idle) return;
    
    cancelRequested_ = true;
    
    // Update telemetry
    {
        std::lock_guard<std::mutex> lock(telemetryMutex_);
        telemetry_.wasCancelled = true;
    }
    
    // Wait briefly for graceful cancellation
    if (generationThread_) {
        WaitForSingleObject(generationThread_, 100);
    }
}

bool AIInferenceBridge::IsGenerating() const {
    return state_ != GenerationState::Idle;
}

GenerationState AIInferenceBridge::GetState() const {
    return state_.load();
}

uint64_t AIInferenceBridge::GetCurrentGenerationId() const {
    return currentGenerationId_.load();
}

// ============================================================================
// Callback Registration
// ============================================================================
void AIInferenceBridge::SetTokenCallback(TokenCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    tokenCallback_ = callback;
}

void AIInferenceBridge::SetCompletionCallback(CompletionCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    completionCallback_ = callback;
}

void AIInferenceBridge::SetErrorCallback(ErrorCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    errorCallback_ = callback;
}

// ============================================================================
// Telemetry
// ============================================================================
const CompletionTelemetry& AIInferenceBridge::GetLastTelemetry() const {
    return telemetry_;
}

void AIInferenceBridge::ResetTelemetry() {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    telemetry_ = CompletionTelemetry{};
}

std::string AIInferenceBridge::ExportTelemetryJson() const {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    
    std::ostringstream json;
    json << "{\n";
    json << "  \"requestId\": " << telemetry_.requestId << ",\n";
    json << "  \"tokensGenerated\": " << telemetry_.tokensGenerated << ",\n";
    json << "  \"tokensAccepted\": " << telemetry_.tokensAccepted << ",\n";
    json << "  \"tokensDismissed\": " << telemetry_.tokensDismissed << ",\n";
    json << "  \"firstTokenLatencyMs\": " << telemetry_.firstTokenLatencyMs << ",\n";
    json << "  \"totalGenerationTimeMs\": " << telemetry_.totalGenerationTimeMs << ",\n";
    json << "  \"tokensPerSecond\": " << telemetry_.tokensPerSecond << ",\n";
    json << "  \"wasAccepted\": " << (telemetry_.wasAccepted ? "true" : "false") << ",\n";
    json << "  \"wasCancelled\": " << (telemetry_.wasCancelled ? "true" : "false") << "\n";
    json << "}";
    
    return json.str();
}

// ============================================================================
// Internal Worker
// ============================================================================
void AIInferenceBridge::GenerationWorker(uint64_t generationId,
                                        std::string context,
                                        int cursorLine,
                                        int cursorCol,
                                        size_t maxTokens) {
    if (!engine_) {
        state_ = GenerationState::Error;
        return;
    }
    
    // Build prompt for code completion
    // Format: <context> with cursor position marked
    std::string prompt = context;
    
    // Tokenize prompt
    std::vector<int> promptTokens = engine_->tokenize(prompt);
    if (promptTokens.empty()) {
        state_ = GenerationState::Error;
        if (errorCallback_) {
            errorCallback_("Failed to tokenize prompt");
        }
        return;
    }
    
    // Prepare output buffer
    std::vector<int> outputTokens;
    outputTokens.reserve(maxTokens);
    
    // Generation loop
    state_ = GenerationState::Streaming;
    bool isFirstToken = true;
    
    for (size_t i = 0; i < maxTokens && !cancelRequested_; ++i) {
        // Check if generation ID changed (stale generation protection)
        if (currentGenerationId_ != generationId) {
            break;
        }
        
        // Generate next token
        // Note: Deep2Engine::generate generates full sequence
        // For streaming, we need to call token-by-token
        // This is a simplified version - real implementation would use
        // a streaming-capable generate method
        
        int nextToken = 0;
        
        // Build full token sequence for this step
        std::vector<int> fullSequence = promptTokens;
        fullSequence.insert(fullSequence.end(), outputTokens.begin(), outputTokens.end());
        
        // Generate single token
        // TODO: Add streaming generate method to Deep2Engine
        // For now, use the batch generate and extract last token
        std::vector<int> stepOutput(1);
        Deep2::InferenceStats stats;
        
        size_t generated = engine_->generate(
            fullSequence.data(), fullSequence.size(),
            stepOutput.data(), 1,
            &stats
        );
        
        if (generated == 0) {
            break; // End of generation
        }
        
        nextToken = stepOutput[0];
        outputTokens.push_back(nextToken);
        
        // Process token
        ProcessToken(nextToken, isFirstToken);
        isFirstToken = false;
        
        // Update telemetry
        {
            std::lock_guard<std::mutex> lock(telemetryMutex_);
            telemetry_.tokensGenerated = outputTokens.size();
            if (telemetry_.tokensGenerated == 1) {
                telemetry_.firstTokenTime = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                    telemetry_.firstTokenTime - telemetry_.requestTime);
                telemetry_.firstTokenLatencyMs = elapsed.count() / 1000.0;
            }
        }
        
        // Check for stop tokens
        // TODO: Add proper stop token detection
        if (nextToken == 2 || nextToken == 0) { // Common EOS tokens
            break;
        }
    }
    
    // Finalize
    state_ = GenerationState::Finalizing;
    
    // Update final telemetry
    {
        std::lock_guard<std::mutex> lock(telemetryMutex_);
        telemetry_.completionTime = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            telemetry_.completionTime - telemetry_.requestTime);
        telemetry_.totalGenerationTimeMs = elapsed.count() / 1000.0;
        if (telemetry_.totalGenerationTimeMs > 0) {
            telemetry_.tokensPerSecond = 
                (telemetry_.tokensGenerated * 1000.0) / telemetry_.totalGenerationTimeMs;
        }
    }
    
    // Build final completion string
    std::string fullCompletion;
    {
        std::lock_guard<std::mutex> lock(completionMutex_);
        fullCompletion = currentCompletion_;
    }
    
    // Notify completion
    if (completionCallback_) {
        completionCallback_(fullCompletion, cancelRequested_.load());
    }
    
    // Final state
    if (cancelRequested_) {
        state_ = GenerationState::Cancelled;
    } else {
        state_ = GenerationState::Idle;
    }
    
    currentGenerationId_ = 0;
}

void AIInferenceBridge::ProcessToken(int tokenId, bool isFirst) {
    // Detokenize single token
    std::vector<int> singleToken = {tokenId};
    std::string tokenStr = engine_->detokenize(singleToken);
    
    // Accumulate
    {
        std::lock_guard<std::mutex> lock(completionMutex_);
        currentCompletion_ += tokenStr;
        generatedTokens_.push_back(tokenId);
    }
    
    // Notify via callback
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        if (tokenCallback_) {
            tokenCallback_(tokenStr.c_str(), tokenStr.length(), isFirst);
        }
    }
}

// ============================================================================
// Global Bridge Implementation
// ============================================================================
bool AIInferenceBridge_Initialize(Deep2::Deep2Engine* engine) {
    if (g_pGlobalBridge) return true;
    
    g_pGlobalBridge = new AIInferenceBridge();
    if (!g_pGlobalBridge->Initialize(engine)) {
        delete g_pGlobalBridge;
        g_pGlobalBridge = nullptr;
        return false;
    }
    
    // Set up default callbacks that wire to ghost text
    g_pGlobalBridge->SetTokenCallback(
        [](const char* token, size_t len, bool isFirst) {
            // Accumulate tokens and update ghost text
            static std::string accumulated;
            if (isFirst) {
                accumulated.clear();
            }
            accumulated.append(token, len);
            
            // Update ghost text with accumulated completion
            // TODO: Get actual cursor position from IDE
            GhostText_OnAICompletion(accumulated.c_str(), -1);
        }
    );
    
    g_pGlobalBridge->SetCompletionCallback(
        [](const std::string& completion, bool wasCancelled) {
            if (wasCancelled) {
                GhostText_OnAIStreamEnd();
            }
            // Completion is now in ghost text, waiting for user action
        }
    );
    
    g_pGlobalBridge->SetErrorCallback(
        [](const char* errorMsg) {
            // Log error and dismiss ghost text
            OutputDebugStringA("AI Inference Error: ");
            OutputDebugStringA(errorMsg);
            OutputDebugStringA("\n");
            GhostText_Dismiss();
        }
    );
    
    return true;
}

void AIInferenceBridge_Shutdown() {
    if (g_pGlobalBridge) {
        delete g_pGlobalBridge;
        g_pGlobalBridge = nullptr;
    }
}

AIInferenceBridge* AIInferenceBridge_Get() {
    return g_pGlobalBridge;
}

uint64_t AIInferenceBridge_Start(const std::string& context, 
                                int cursorLine, 
                                int cursorCol,
                                size_t maxTokens) {
    if (!g_pGlobalBridge) return 0;
    return g_pGlobalBridge->StartGeneration(context, cursorLine, cursorCol, maxTokens);
}

void AIInferenceBridge_Cancel() {
    if (g_pGlobalBridge) {
        g_pGlobalBridge->CancelGeneration();
    }
}

bool AIInferenceBridge_IsGenerating() {
    return g_pGlobalBridge && g_pGlobalBridge->IsGenerating();
}

} // namespace IDE
} // namespace RawrXD
