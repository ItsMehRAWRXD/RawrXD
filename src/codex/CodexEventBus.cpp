// ============================================================================
// RawrXD Codex Event Bus Implementation
// Lock-free MPMC event dispatch for IDE-wide Codex integration
// ============================================================================

#include "CodexEventBus.hpp"
#include <chrono>

namespace RawrXD {
namespace Codex {

bool CodexEventBus::Initialize() {
    // Open existing shared memory (don't create - IDE should already have it)
    return m_sessionState.Initialize(false);
}

bool CodexEventBus::PublishStreamStarted(uint64_t sessionId,
                                          std::string_view modelName,
                                          std::string_view prompt) {
    if (!IsConnected()) return false;
    
    CodexStreamStartedPayload payload{};
    payload.sessionId = sessionId;
    payload.modelNameLength = static_cast<uint32_t>(modelName.length());
    payload.promptLength = static_cast<uint32_t>(prompt.length());
    
    SafeCopy(payload.modelName, sizeof(payload.modelName), modelName);
    SafeCopy(payload.promptPreview, sizeof(payload.promptPreview), prompt);
    
    // Serialize payload to string_view for WriteEvent
    std::string_view data(reinterpret_cast<const char*>(&payload), sizeof(payload));
    auto result = m_sessionState.WriteEvent(EventType::CodexStreamStarted, data);
    
    return result.success;
}

bool CodexEventBus::PublishStreamChunk(uint64_t sessionId,
                                        uint32_t chunkIndex,
                                        std::string_view text,
                                        bool isFinal) {
    if (!IsConnected()) return false;
    
    CodexStreamChunkPayload payload{};
    payload.sessionId = sessionId;
    payload.chunkIndex = chunkIndex;
    payload.chunkLength = static_cast<uint32_t>(text.length());
    payload.isFinal = isFinal ? 1u : 0u;
    
    SafeCopy(payload.text, sizeof(payload.text), text);
    
    std::string_view data(reinterpret_cast<const char*>(&payload), sizeof(payload));
    auto result = m_sessionState.WriteEvent(EventType::CodexStreamChunk, data);
    
    return result.success;
}

bool CodexEventBus::PublishStreamCompleted(uint64_t sessionId,
                                            uint32_t totalChunks,
                                            uint32_t totalTokens,
                                            uint64_t durationMs) {
    if (!IsConnected()) return false;
    
    CodexStreamCompletedPayload payload{};
    payload.sessionId = sessionId;
    payload.totalChunks = totalChunks;
    payload.totalTokens = totalTokens;
    payload.durationMs = durationMs;
    
    std::string_view data(reinterpret_cast<const char*>(&payload), sizeof(payload));
    auto result = m_sessionState.WriteEvent(EventType::CodexStreamCompleted, data);
    
    return result.success;
}

bool CodexEventBus::PublishStreamError(uint64_t sessionId,
                                        uint32_t errorCode,
                                        std::string_view message) {
    if (!IsConnected()) return false;
    
    CodexStreamErrorPayload payload{};
    payload.sessionId = sessionId;
    payload.errorCode = errorCode;
    payload.messageLength = static_cast<uint32_t>(message.length());
    
    SafeCopy(payload.message, sizeof(payload.message), message);
    
    std::string_view data(reinterpret_cast<const char*>(&payload), sizeof(payload));
    auto result = m_sessionState.WriteEvent(EventType::CodexStreamError, data);
    
    return result.success;
}

bool CodexEventBus::PublishRequestSubmitted(uint64_t sessionId,
                                               uint32_t providerType,
                                               bool isStreaming,
                                               std::string_view modelName,
                                               std::string_view prompt) {
    if (!IsConnected()) return false;
    
    CodexRequestSubmittedPayload payload{};
    payload.sessionId = sessionId;
    payload.providerType = providerType;
    payload.isStreaming = isStreaming ? 1u : 0u;
    
    SafeCopy(payload.modelName, sizeof(payload.modelName), modelName);
    SafeCopy(payload.promptPreview, sizeof(payload.promptPreview), prompt);
    
    std::string_view data(reinterpret_cast<const char*>(&payload), sizeof(payload));
    auto result = m_sessionState.WriteEvent(EventType::CodexRequestSubmitted, data);
    
    return result.success;
}

bool CodexEventBus::ReadNextEvent(SharedEventFrame& outFrame, uint64_t& lastSequence) {
    if (!IsConnected()) return false;
    return m_sessionState.ReadNextEvent(outFrame, lastSequence);
}

} // namespace Codex
} // namespace RawrXD
