// ============================================================================
// AgentStateManager.cpp — RAWRXD_AGENTIC_STATE_MANAGER_001
// ============================================================================
#include "agentic/AgentStateManager.h"

#include <algorithm>
#include <sstream>

namespace rawrxd {
namespace agentic {

std::uint32_t EstimateTokens(const std::string& text) {
    if (text.empty()) return 0;
    // 4 characters per token, rounded up, with a 1-token floor for non-empty
    // text. This is an estimator, not a tokenizer, and is named as such.
    return static_cast<std::uint32_t>((text.size() + 3) / 4);
}

const char* AgentStateManager::RoleName(MessageRole role) {
    switch (role) {
        case MessageRole::System:    return "system";
        case MessageRole::User:      return "user";
        case MessageRole::Assistant: return "assistant";
        case MessageRole::Tool:     return "tool";
    }
    return "user";
}

void AgentStateManager::Reset(const std::string& systemPrompt) {
    std::lock_guard<std::mutex> lk(mtx_);
    history_.clear();
    metrics_.clear();
    currentTurn_ = 0;
    fatalError_ = false;
    lastError_.clear();
    lastDropped_ = 0;
    lastContextChars_ = 0;
    history_.push_back(
        {MessageRole::System, systemPrompt, "", std::chrono::system_clock::now()});
}

void AgentStateManager::PushUser(const std::string& content) {
    std::lock_guard<std::mutex> lk(mtx_);
    history_.push_back(
        {MessageRole::User, content, "", std::chrono::system_clock::now()});
}

void AgentStateManager::PushAssistant(const std::string& content) {
    std::lock_guard<std::mutex> lk(mtx_);
    history_.push_back(
        {MessageRole::Assistant, content, "", std::chrono::system_clock::now()});
    ++currentTurn_;
}

void AgentStateManager::PushToolResult(const std::string& toolName, const std::string& result) {
    std::lock_guard<std::mutex> lk(mtx_);
    std::string content = "[tool:" + toolName + "]\n";
    content += result;
    history_.push_back(
        {MessageRole::Tool, content, toolName, std::chrono::system_clock::now()});
}

std::string AgentStateManager::BuildContextWindow() const {
    std::lock_guard<std::mutex> lk(mtx_);

    // Render every message first, then choose which to keep. Working on
    // rendered entries is what makes "drop the oldest middle" possible.
    struct Entry {
        std::string rendered;
        MessageRole role;
        bool pinned = false;  // system and the newest user message
    };
    std::vector<Entry> entries;
    entries.reserve(history_.size());
    for (std::size_t i = 0; i < history_.size(); ++i) {
        Entry e;
        e.role = history_[i].role;
        e.rendered = std::string("<|") + RoleName(history_[i].role) + "|>\n" +
                     history_[i].content + "\n";
        e.pinned = (history_[i].role == MessageRole::System) ||
                   (history_[i].role == MessageRole::User && i + 1 == history_.size());
        entries.push_back(std::move(e));
    }

    auto totalOf = [&entries](const std::vector<bool>& keep) {
        std::size_t total = 0;
        for (std::size_t i = 0; i < entries.size(); ++i) {
            if (keep[i]) total += entries[i].rendered.size();
        }
        return total;
    };

    std::vector<bool> keep(entries.size(), true);
    std::size_t total = totalOf(keep);
    std::uint32_t dropped = 0;

    if (total > contextCharBudget_) {
        // Drop the oldest non-pinned message, then the next oldest, until the
        // budget is met or nothing droppable remains.
        for (std::size_t i = 0; i < entries.size() && total > contextCharBudget_; ++i) {
            if (entries[i].pinned) continue;
            total -= entries[i].rendered.size();
            keep[i] = false;
            ++dropped;
        }
    }

    std::string out;
    out.reserve(total + 32);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        if (keep[i]) out += entries[i].rendered;
    }
    if (dropped > 0) {
        out += "<|system|>\n[earlier turns omitted: " + std::to_string(dropped) +
               " message(s) removed to fit the context budget]\n";
    }
    out += "<|assistant|>\n";

    lastDropped_ = dropped;
    lastContextChars_ = out.size();
    return out;
}

std::uint32_t AgentStateManager::LastDroppedMessageCount() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return lastDropped_;
}

std::size_t AgentStateManager::LastContextChars() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return lastContextChars_;
}

std::vector<Message> AgentStateManager::History() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return history_;
}

void AgentStateManager::RecordMetrics(const TurnMetrics& metrics) {
    std::lock_guard<std::mutex> lk(mtx_);
    metrics_.push_back(metrics);
}

std::vector<TurnMetrics> AgentStateManager::GetMetrics() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return metrics_;
}

std::uint32_t AgentStateManager::CurrentTurn() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return currentTurn_;
}

bool AgentStateManager::ShouldContinue() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return !fatalError_ && currentTurn_ < maxTurns_;
}

void AgentStateManager::SetFatalError(const std::string& error) {
    std::lock_guard<std::mutex> lk(mtx_);
    fatalError_ = true;
    lastError_ = error;
}

std::string AgentStateManager::LastError() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return lastError_;
}

bool AgentStateManager::HasFatalError() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return fatalError_;
}

std::size_t AgentStateManager::MessageCount() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return history_.size();
}

} // namespace agentic
} // namespace rawrxd
