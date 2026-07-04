// ============================================================================
// RawrXD Codex Chat Bridge
// Integrates Codex streaming responses with IDE Chat Panel
// ============================================================================

#pragma once
#include "CodexCLI.hpp"
#include "CodexEventBus.hpp"
#include <functional>
#include <memory>
#include <atomic>
#include <string>

namespace RawrXD {
namespace Codex {

// Chat message types
enum class ChatMessageType {
    User,       // User message
    Assistant,  // AI assistant response
    System,     // System message
    Tool        // Tool result
};

// Chat message structure
struct ChatMessage {
    ChatMessageType type;
    std::string content;
    std::string model;      // Source model (for assistant messages)
    uint64_t timestamp;
    bool isStreaming = false;
    bool isComplete = false;
};

// Callback types for chat integration
using ChatMessageCallback = std::function<void(const ChatMessage& msg)>;
using ChatStreamCallback = std::function<void(const std::string& chunk, bool isFinal)>;
using ChatErrorCallback = std::function<void(const std::string& error)>;

// Codex Chat Bridge - connects Codex to IDE Chat Panel
class CodexChatBridge {
public:
    CodexChatBridge();
    ~CodexChatBridge();

    // Initialize with CLI backend
    bool Initialize(std::shared_ptr<CodexCLI> cli);
    
    // Shutdown
    void Shutdown();
    
    // Check if initialized
    bool IsInitialized() const { return m_initialized.load(); }
    
    // Check if streaming is active
    bool IsStreaming() const { return m_isStreaming.load(); }
    
    // --- Chat Operations ---
    
    // Send a message and get streaming response
    // This is the primary method for chat panel integration
    bool SendMessage(const std::string& message, 
                     ChatStreamCallback onChunk,
                     ChatErrorCallback onError = nullptr);
    
    // Send with full message callback (non-streaming)
    bool SendMessageComplete(const std::string& message,
                            ChatMessageCallback onComplete,
                            ChatErrorCallback onError = nullptr);
    
    // Cancel ongoing streaming
    void CancelStreaming();
    
    // Clear conversation history
    void ClearHistory();
    
    // Get conversation history for context
    const std::vector<ChatMessage>& GetHistory() const { return m_history; }
    
    // Set system prompt
    void SetSystemPrompt(const std::string& prompt) { m_systemPrompt = prompt; }
    const std::string& GetSystemPrompt() const { return m_systemPrompt; }
    
    // Configure context window
    void SetMaxContextMessages(size_t max) { m_maxContextMessages = max; }
    size_t GetMaxContextMessages() const { return m_maxContextMessages; }
    
    // --- Event Bus Integration ---
    
    // Enable/disable event bus publishing
    void SetEventBusEnabled(bool enabled) { m_eventBusEnabled = enabled; }
    bool IsEventBusEnabled() const { return m_eventBusEnabled; }

private:
    std::shared_ptr<CodexCLI> m_cli;
    std::shared_ptr<CodexEventBus> m_eventBus;
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_isStreaming{false};
    std::atomic<bool> m_cancelled{false};
    std::atomic<bool> m_eventBusEnabled{true};
    
    // Conversation state
    std::vector<ChatMessage> m_history;
    std::string m_systemPrompt;
    size_t m_maxContextMessages = 10;
    
    // Build prompt with context
    std::string BuildContextualPrompt(const std::string& userMessage);
    
    // Add message to history
    void AddToHistory(const ChatMessage& msg);
    
    // Trim history to max size
    void TrimHistory();
    
    // Publish events
    void PublishChatStarted(const std::string& message);
    void PublishChatChunk(const std::string& chunk);
    void PublishChatComplete();
    void PublishChatError(const std::string& error);
};

} // namespace Codex
} // namespace RawrXD
