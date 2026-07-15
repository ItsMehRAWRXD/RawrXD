// ============================================================================
// RawrXD Codex Event Bus Integration
// Bridges Codex streaming to UnifiedSessionState MPMC ring buffer
// Zero-copy, lock-free event dispatch for IDE-wide Codex integration
// ============================================================================

#pragma once
#include "../core/UnifiedSessionState.hpp"
#include <string_view>
#include <cstring>

namespace RawrXD {
namespace Codex {

// Codex event payload structures (fit within 256-byte SharedEventFrame)
// All payloads are POD types for safe shared memory transfer

// Stream started event - announces a new streaming session
struct CodexStreamStartedPayload {
    uint64_t sessionId;           // Unique session identifier
    uint32_t modelNameLength;     // Length of model name
    uint32_t promptLength;        // Length of prompt preview
    char modelName[128];          // Model name (e.g., "gemma3:27b-it-qat")
    char promptPreview[112];      // First 111 chars of prompt + null
    
    static constexpr EventType EVENT_TYPE = EventType::CodexStreamStarted;
};
static_assert(sizeof(CodexStreamStartedPayload) <= 256, "Payload exceeds 256 bytes");

// Stream chunk event - carries token data
struct CodexStreamChunkPayload {
    uint64_t sessionId;           // Session identifier (matches started event)
    uint32_t chunkIndex;          // Sequential chunk index
    uint32_t chunkLength;         // Length of text chunk
    uint32_t isFinal;             // 1 if this is the final chunk
    char text[236];               // UTF-8 text chunk (235 chars + null)
    
    static constexpr EventType EVENT_TYPE = EventType::CodexStreamChunk;
};
static_assert(sizeof(CodexStreamChunkPayload) <= 256, "Payload exceeds 256 bytes");

// Stream completed event - signals successful completion
struct CodexStreamCompletedPayload {
    uint64_t sessionId;           // Session identifier
    uint32_t totalChunks;         // Total chunks delivered
    uint32_t totalTokens;         // Approximate token count
    uint64_t durationMs;          // Total duration in milliseconds
    
    static constexpr EventType EVENT_TYPE = EventType::CodexStreamCompleted;
};
static_assert(sizeof(CodexStreamCompletedPayload) <= 256, "Payload exceeds 256 bytes");

// Stream error event - carries error information
struct CodexStreamErrorPayload {
    uint64_t sessionId;           // Session identifier
    uint32_t errorCode;           // Error code enum
    uint32_t messageLength;       // Length of error message
    char message[240];            // Error message text
    
    static constexpr EventType EVENT_TYPE = EventType::CodexStreamError;
};
static_assert(sizeof(CodexStreamErrorPayload) <= 256, "Payload exceeds 256 bytes");

// Request submitted event - signals a new request was queued
struct CodexRequestSubmittedPayload {
    uint64_t sessionId;           // Session identifier
    uint32_t providerType;        // 0=OpenAI, 1=Ollama
    uint32_t isStreaming;         // 1 if streaming mode
    char modelName[120];          // Target model
    char promptPreview[120];      // Prompt preview
    
    static constexpr EventType EVENT_TYPE = EventType::CodexRequestSubmitted;
};
static_assert(sizeof(CodexRequestSubmittedPayload) <= 256, "Payload exceeds 256 bytes");

// Codex Event Bus - thin wrapper around UnifiedSessionState
class CodexEventBus {
public:
    CodexEventBus() = default;
    ~CodexEventBus() = default;

    // Initialize connection to shared session state
    bool Initialize();
    
    // Check if connected
    bool IsConnected() const { return m_sessionState.IsInitialized(); }
    
    // --- Event Publishers (called from CodexCLI/CodexGUI) ---
    
    // Publish stream started event
    bool PublishStreamStarted(uint64_t sessionId, 
                               std::string_view modelName,
                               std::string_view prompt);
    
    // Publish stream chunk event
    bool PublishStreamChunk(uint64_t sessionId,
                             uint32_t chunkIndex,
                             std::string_view text,
                             bool isFinal);
    
    // Publish stream completed event
    bool PublishStreamCompleted(uint64_t sessionId,
                                 uint32_t totalChunks,
                                 uint32_t totalTokens,
                                 uint64_t durationMs);
    
    // Publish stream error event
    bool PublishStreamError(uint64_t sessionId,
                             uint32_t errorCode,
                             std::string_view message);
    
    // Publish request submitted event
    bool PublishRequestSubmitted(uint64_t sessionId,
                                    uint32_t providerType,
                                    bool isStreaming,
                                    std::string_view modelName,
                                    std::string_view prompt);
    
    // --- Event Consumers (called from IDE subsystems) ---
    
    // Read next Codex event (returns false if no new events)
    bool ReadNextEvent(SharedEventFrame& outFrame, uint64_t& lastSequence);
    
    // Filter and dispatch events by type
    template<typename Handler>
    void Subscribe(EventType type, Handler&& handler);

private:
    UnifiedSessionState m_sessionState;
    
    // Helper to safely copy string to payload buffer
    static void SafeCopy(char* dest, size_t destSize, std::string_view src);
};

// Inline implementation
inline void CodexEventBus::SafeCopy(char* dest, size_t destSize, std::string_view src) {
    size_t copyLen = (src.length() < destSize - 1) ? src.length() : destSize - 1;
    std::memcpy(dest, src.data(), copyLen);
    dest[copyLen] = '\0';
}

} // namespace Codex
} // namespace RawrXD
