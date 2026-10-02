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
        bool pinned = false;  // system, the newest user, the newest observation
    };
    std::vector<Entry> entries;
    entries.reserve(history_.size());

    // The newest message of each pinned kind. Found first, because "the last
    // message" is not the same thing: after a tool turn the last message is the
    // observation and the user's actual question is no longer last, which is how
    // a question used to become the first droppable message.
    std::size_t lastUser = history_.size();
    std::size_t lastTool = history_.size();
    for (std::size_t i = 0; i < history_.size(); ++i) {
        if (history_[i].role == MessageRole::User) lastUser = i;
        if (history_[i].role == MessageRole::Tool) lastTool = i;
    }

    for (std::size_t i = 0; i < history_.size(); ++i) {
        Entry e;
        e.role = history_[i].role;
        e.rendered = std::string("<|") + RoleName(history_[i].role) + "|>\n" +
                     history_[i].content + "\n";
        e.pinned = (history_[i].role == MessageRole::System) || i == lastUser || i == lastTool;
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

    // Pinned content alone can still exceed the budget, and the only way to fit
    // it is to cut it. Cutting the observation is wrong (the model would resume
    // without the answer); cutting the system prompt is also wrong. So the
    // newest observation is cut instead, from the END, with the number of lost
    // characters stated, and the loss is counted so a caller can report it.
    std::uint32_t truncatedChars = 0;
    if (total > contextCharBudget_ && lastTool < entries.size() && keep[lastTool]) {
        Entry& obs = entries[lastTool];
        // Leave room for the marker itself, and never cut below the header that
        // names the tool and its status.
        const std::size_t markerReserve = 96;
        const std::string header = obs.rendered.substr(0, obs.rendered.find('\n') + 1);
        if (obs.rendered.size() > header.size() + markerReserve) {
            const std::size_t keepChars = contextCharBudget_ > markerReserve + header.size()
                                              ? contextCharBudget_ - markerReserve - header.size()
                                              : 0;
            const std::size_t cut = obs.rendered.size() - header.size() - keepChars;
            obs.rendered = header + obs.rendered.substr(header.size(), keepChars) +
                           "\n[observation truncated: " + std::to_string(cut) +
                           " character(s) removed to fit the context budget]\n";
            truncatedChars = static_cast<std::uint32_t>(cut);
            total = totalOf(keep);
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
    lastTruncatedChars_ = truncatedChars;
    lastContextChars_ = out.size();
    return out;
}

std::uint32_t AgentStateManager::LastDroppedMessageCount() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return lastDropped_;
}

std::uint32_t AgentStateManager::LastTruncatedCharCount() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return lastTruncatedChars_;
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
