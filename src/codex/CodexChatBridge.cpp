// ============================================================================
// RawrXD Codex Chat Bridge Implementation
// ============================================================================

#include "CodexChatBridge.hpp"
#include <chrono>
#include <sstream>

namespace RawrXD {
namespace Codex {

CodexChatBridge::CodexChatBridge() = default;
CodexChatBridge::~CodexChatBridge() {
    Shutdown();
}

bool CodexChatBridge::Initialize(std::shared_ptr<CodexCLI> cli) {
    m_cli = cli;
    if (!m_cli || !m_cli->IsInitialized()) {
        return false;
    }
    
    // Initialize event bus
    m_eventBus = std::make_shared<CodexEventBus>();
    if (!m_eventBus->Initialize()) {
        // Event bus is optional - continue without it
        m_eventBus.reset();
    }
    
    m_initialized = true;
    return true;
}

void CodexChatBridge::Shutdown() {
    CancelStreaming();
    m_initialized = false;
    m_eventBus.reset();
    m_cli.reset();
}

bool CodexChatBridge::SendMessage(const std::string& message, 
                                   ChatStreamCallback onChunk,
                                   ChatErrorCallback onError) {
    if (!m_initialized || !m_cli) {
        if (onError) {
            onError("Chat bridge not initialized");
        }
        return false;
    }
    
    // Cancel any existing streaming
    CancelStreaming();
    
    // Add user message to history
    ChatMessage userMsg;
    userMsg.type = ChatMessageType::User;
    userMsg.content = message;
    userMsg.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    AddToHistory(userMsg);
    
    // Build contextual prompt
    std::string prompt = BuildContextualPrompt(message);
    
    // Prepare assistant message (heap allocated for lambda capture)
    auto assistantMsg = std::make_shared<ChatMessage>();
    assistantMsg->type = ChatMessageType::Assistant;
    assistantMsg->model = m_cli->GetConfig().model;
    assistantMsg->timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    assistantMsg->isStreaming = true;
    assistantMsg->isComplete = false;
    
    // Publish start event
    PublishChatStarted(message);
    
    // Start streaming
    m_isStreaming = true;
    m_cancelled = false;
    
    std::string accumulated;
    bool success = m_cli->CompleteStreaming(prompt, 
        [&accumulated, assistantMsg, onChunk, this](const std::string& chunk, bool isFinal) {
            if (m_cancelled) return;
            
            accumulated += chunk;
            
            // Update assistant message
            assistantMsg->content = accumulated;
            
            // Call user callback
            if (onChunk) {
                onChunk(chunk, isFinal);
            }
            
            // Publish chunk event
            PublishChatChunk(chunk);
            
            // Handle completion
            if (isFinal) {
                assistantMsg->isStreaming = false;
                assistantMsg->isComplete = true;
                AddToHistory(*assistantMsg);
                PublishChatComplete();
                m_isStreaming = false;
            }
        });
    
    if (!success) {
        m_isStreaming = false;
        std::string error = m_cli->GetLastError();
        if (onError) {
            onError(error);
        }
        PublishChatError(error);
        return false;
    }
    
    return true;
}

bool CodexChatBridge::SendMessageComplete(const std::string& message,
                                           ChatMessageCallback onComplete,
                                           ChatErrorCallback onError) {
    if (!m_initialized || !m_cli) {
        if (onError) {
            onError("Chat bridge not initialized");
        }
        return false;
    }
    
    // Add user message to history
    ChatMessage userMsg;
    userMsg.type = ChatMessageType::User;
    userMsg.content = message;
    userMsg.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    AddToHistory(userMsg);
    
    // Build contextual prompt
    std::string prompt = BuildContextualPrompt(message);
    
    // Get complete response
    std::string response = m_cli->Complete(prompt);
    
    if (response.empty()) {
        std::string error = m_cli->GetLastError();
        if (onError) {
            onError(error);
        }
        PublishChatError(error);
        return false;
    }
    
    // Create assistant message
    ChatMessage assistantMsg;
    assistantMsg.type = ChatMessageType::Assistant;
    assistantMsg.content = response;
    assistantMsg.model = m_cli->GetConfig().model;
    assistantMsg.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    assistantMsg.isStreaming = false;
    assistantMsg.isComplete = true;
    
    AddToHistory(assistantMsg);
    
    if (onComplete) {
        onComplete(assistantMsg);
    }
    
    PublishChatComplete();
    
    return true;
}

void CodexChatBridge::CancelStreaming() {
    m_cancelled = true;
    m_isStreaming = false;
}

void CodexChatBridge::ClearHistory() {
    m_history.clear();
}

std::string CodexChatBridge::BuildContextualPrompt(const std::string& userMessage) {
    std::ostringstream prompt;
    
    // Add system prompt if set
    if (!m_systemPrompt.empty()) {
        prompt << "System: " << m_systemPrompt << "\n\n";
    }
    
    // Add conversation history
    for (const auto& msg : m_history) {
        switch (msg.type) {
            case ChatMessageType::User:
                prompt << "User: " << msg.content << "\n";
                break;
            case ChatMessageType::Assistant:
                prompt << "Assistant: " << msg.content << "\n";
                break;
            case ChatMessageType::System:
                prompt << "System: " << msg.content << "\n";
                break;
            case ChatMessageType::Tool:
                prompt << "Tool: " << msg.content << "\n";
                break;
        }
    }
    
    // Add current user message
    prompt << "User: " << userMessage << "\n";
    prompt << "Assistant: ";
    
    return prompt.str();
}

void CodexChatBridge::AddToHistory(const ChatMessage& msg) {
    m_history.push_back(msg);
    TrimHistory();
}

void CodexChatBridge::TrimHistory() {
    // Keep only recent messages to stay within context window
    // Reserve 2 slots for system prompt and current message
    size_t maxHistory = m_maxContextMessages;
    if (maxHistory < 2) maxHistory = 2;
    
    while (m_history.size() > maxHistory) {
        // Remove oldest non-system message
        bool removed = false;
        for (auto it = m_history.begin(); it != m_history.end(); ++it) {
            if (it->type != ChatMessageType::System) {
                m_history.erase(it);
                removed = true;
                break;
            }
        }
        if (!removed) {
            // Only system messages left, remove oldest
            m_history.erase(m_history.begin());
        }
    }
}

void CodexChatBridge::PublishChatStarted(const std::string& message) {
    if (!m_eventBusEnabled || !m_eventBus) return;
    
    // Generate session ID from timestamp
    uint64_t sessionId = std::chrono::steady_clock::now().time_since_epoch().count();
    
    m_eventBus->PublishRequestSubmitted(
        sessionId,
        1,  // Provider type: Ollama
        true,  // Streaming
        m_cli->GetConfig().model,
        message
    );
}

void CodexChatBridge::PublishChatChunk(const std::string& chunk) {
    if (!m_eventBusEnabled || !m_eventBus) return;
    
    uint64_t sessionId = std::chrono::steady_clock::now().time_since_epoch().count();
    static uint32_t chunkIndex = 0;
    
    m_eventBus->PublishStreamChunk(
        sessionId,
        chunkIndex++,
        chunk,
        false  // Not final
    );
}

void CodexChatBridge::PublishChatComplete() {
    if (!m_eventBusEnabled || !m_eventBus) return;
    
    uint64_t sessionId = std::chrono::steady_clock::now().time_since_epoch().count();
    
    m_eventBus->PublishStreamCompleted(
        sessionId,
        0,  // Total chunks unknown
        0,  // Total tokens unknown
        0   // Duration unknown
    );
}

void CodexChatBridge::PublishChatError(const std::string& error) {
    if (!m_eventBusEnabled || !m_eventBus) return;
    
    uint64_t sessionId = std::chrono::steady_clock::now().time_since_epoch().count();
    
    m_eventBus->PublishStreamError(
        sessionId,
        1,  // Generic error code
        error
    );
}

} // namespace Codex
} // namespace RawrXD
