#pragma once
// ============================================================================
// chat_session.h — Multi-turn conversation with KV cache persistence
// ============================================================================
//
// Wraps AutonomousInferenceEngine to provide:
//   - Persistent KV cache across turns (no re-processing history)
//   - Context window management (trim oldest tokens when full)
//   - Streaming output per turn
//   - Conversation history tracking
//
// Usage:
//   ChatSession session(engine, max_context=4096);
//   session.addUserMessage("Hello");
//   session.generate([](const std::string& tok) { printf("%s", tok.c_str()); });
//   session.addUserMessage("What about X?");
//   session.generate(callback);  // KV cache warm — instant resume
// ============================================================================

#include <vector>
#include <string>
#include <cstdint>
#include <functional>
#include <memory>

namespace rawrxd {
namespace inference {

class AutonomousInferenceEngine;

class ChatSession {
public:
    explicit ChatSession(AutonomousInferenceEngine& engine, size_t max_context = 4096);

    // Add a user message (text). Tokenized and appended to context.
    void addUserMessage(const std::string& text);

    // Add an assistant message (already generated tokens). Appends to context.
    void addAssistantTokens(const std::vector<int32_t>& tokens);

    // Generate a response to the current context.
    // Calls token_callback for each token as it's generated.
    // Returns number of tokens generated.
    size_t generate(std::function<void(const std::string&)> token_callback,
                    size_t max_tokens = 256);

    // Clear conversation history and KV cache.
    void reset();

    // Current context length in tokens.
    size_t contextLength() const;

    // Max context window size.
    size_t maxContext() const { return max_context_; }

    // Conversation history (for display / logging).
    const std::vector<std::string>& history() const { return history_; }

private:
    AutonomousInferenceEngine& engine_;
    size_t max_context_;

    // Full token context (user + assistant tokens interleaved)
    std::vector<int32_t> context_tokens_;

    // Human-readable history
    std::vector<std::string> history_;

    // Trim oldest tokens to fit within max_context_
    void trimContext();
};

} // namespace inference
} // namespace rawrxd
