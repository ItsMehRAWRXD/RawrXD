// ============================================================================
// chat_session.cpp — Multi-turn conversation with KV cache persistence
// ============================================================================

#include "chat_session.h"
#include "ultra_fast_inference.h"

#include <sstream>

namespace rawrxd {
namespace inference {

ChatSession::ChatSession(AutonomousInferenceEngine& engine, size_t max_context)
    : engine_(engine), max_context_(max_context)
{
    context_tokens_.reserve(max_context);
}

void ChatSession::addUserMessage(const std::string& text) {
    // Store raw text — tokenization happens inside inferText()
    history_.push_back("User: " + text);
    // For now, we still need token IDs for context tracking
    // TODO: migrate to full text-based context once inferText() returns token IDs
    std::istringstream iss(text);
    std::string word;
    while (iss >> word) {
        uint32_t h = 0;
        for (char c : word) h = h * 31 + static_cast<uint32_t>(c);
        context_tokens_.push_back(static_cast<int32_t>(h % 32000));
    }
    trimContext();
}

void ChatSession::addAssistantTokens(const std::vector<int32_t>& tokens) {
    context_tokens_.insert(context_tokens_.end(), tokens.begin(), tokens.end());
    trimContext();
}

size_t ChatSession::generate(std::function<void(const std::string&)> token_callback,
                             size_t max_tokens) {
    if (history_.empty()) {
        return 0;
    }

    std::string transcript;
    for (const std::string& entry : history_) {
        transcript.append(entry);
        transcript.push_back('\n');
    }
    transcript.append("Assistant:");

    std::string response;
    size_t generated = 0;
    engine_.inferText(transcript, [&](const std::string& token) {
        response.append(token);
        ++generated;
        if (token_callback) token_callback(token);
    }, max_tokens);

    history_.push_back("Assistant: " + response);

    for (unsigned char c : response) {
        context_tokens_.push_back(static_cast<int32_t>(c));
    }
    trimContext();

    return generated;
}

void ChatSession::reset() {
    context_tokens_.clear();
    history_.clear();
    engine_.resetConversationState();
}

size_t ChatSession::contextLength() const {
    return context_tokens_.size();
}

void ChatSession::trimContext() {
    if (context_tokens_.size() <= max_context_) {
        return;
    }
    // Trim from the front (oldest tokens) — preserve recent conversation
    size_t excess = context_tokens_.size() - max_context_;
    context_tokens_.erase(context_tokens_.begin(),
                          context_tokens_.begin() + static_cast<std::ptrdiff_t>(excess));
}

} // namespace inference
} // namespace rawrxd
