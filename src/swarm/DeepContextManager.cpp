#include "DeepContextManager.hpp"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <math>

namespace rawrxd {
namespace swarm {

DeepContextManager::DeepContextManager() = default;
DeepContextManager::~DeepContextManager() = default;

void DeepContextManager::addTokens(const std::vector<Token>& tokens, const std::string& category) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ContextSegment segment;
    segment.tokens = tokens;
    segment.category = category;
    segment.timestamp = std::chrono::steady_clock::now();
    
    for (auto& token : segment.tokens) {
        token.timestamp = segment.timestamp;
        token.importance = calculateTokenImportance(token);
    }
    
    segments_.push_back(segment);
    
    for (const auto& token : tokens) {
        categoryIndex_[category].push_back(token);
    }
    
    stats_.totalTokens += tokens.size();
    maintainTokenLimit();
    updateStats();
}

void DeepContextManager::addText(const std::string& text, const std::string& category) {
    // Simple tokenization - in production would use proper tokenizer
    std::vector<Token> tokens;
    std::istringstream iss(text);
    std::string word;
    uint32_t tokenId = 0;
    
    while (iss >> word) {
        Token token;
        token.id = tokenId++;
        token.text = word;
        // Initialize embedding (would be actual embeddings in production)
        std::fill(std::begin(token.embedding), std::end(token.embedding), 0.0f);
        tokens.push_back(token);
    }
    
    addTokens(tokens, category);
}

void DeepContextManager::addSystemPrompt(const std::string& prompt) {
    addText(prompt, "system");
}

void DeepContextManager::addUserMessage(const std::string& message) {
    addText(message, "user");
}

void DeepContextManager::addAssistantResponse(const std::string& response) {
    addText(response, "assistant");
}

void DeepContextManager::addToolResult(const std::string& toolName, const std::string& result) {
    std::string formatted = "[Tool: " + toolName + "]\n" + result;
    addText(formatted, "tool");
}

std::vector<Token> DeepContextManager::getContextForInference(size_t maxTokens) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Token> context;
    size_t remaining = maxTokens;
    
    // Always include system prompt first
    auto it = categoryIndex_.find("system");
    if (it != categoryIndex_.end()) {
        size_t toTake = std::min(remaining, it->second.size());
        context.insert(context.end(), it->second.begin(), it->second.begin() + toTake);
        remaining -= toTake;
    }
    
    // Then add most recent segments
    for (auto it = segments_.rbegin(); it != segments_.rend() && remaining > 0; ++it) {
        if (it->category == "system") continue;
        
        size_t toTake = std::min(remaining, it->tokens.size());
        context.insert(context.end(), it->tokens.begin(), it->tokens.begin() + toTake);
        remaining -= toTake;
    }
    
    // Apply selective attention
    applySelectiveAttention(context);
    
    return context;
}

std::vector<Token> DeepContextManager::getRelevantContext(const std::string& query, size_t maxTokens) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Simple relevance scoring based on keyword matching
    // In production would use embedding similarity
    std::vector<std::pair<float, Token>> scoredTokens;
    
    for (const auto& segment : segments_) {
        for (const auto& token : segment.tokens) {
            float score = 0.0f;
            if (query.find(token.text) != std::string::npos) {
                score += 1.0f;
            }
            score += token.importance;
            scoredTokens.push_back({score, token});
        }
    }
    
    // Sort by relevance
    std::sort(scoredTokens.begin(), scoredTokens.end(), 
        [](const auto& a, const auto& b) { return a.first > b.first; });
    
    std::vector<Token> result;
    size_t count = std::min(maxTokens, scoredTokens.size());
    for (size_t i = 0; i < count; ++i) {
        result.push_back(scoredTokens[i].second);
    }
    
    return result;
}

std::string DeepContextManager::getContextAsText(size_t maxTokens) {
    auto tokens = getContextForInference(maxTokens);
    std::string result;
    for (const auto& token : tokens) {
        if (!result.empty()) result += " ";
        result += token.text;
    }
    return result;
}

void DeepContextManager::setFocusTokens(const std::vector<std::string>& keywords) {
    std::lock_guard<std::mutex> lock(mutex_);
    focusKeywords_ = keywords;
}

void DeepContextManager::boostTokenImportance(const std::vector<uint32_t>& tokenIds, float boost) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (uint32_t id : tokenIds) {
        importanceBoosts_[id] = boost;
    }
}

void DeepContextManager::applySelectiveAttention(std::vector<Token>& tokens) {
    for (auto& token : tokens) {
        // Boost importance for focus keywords
        for (const auto& keyword : focusKeywords_) {
            if (token.text.find(keyword) != std::string::npos) {
                token.importance *= 2.0f;
            }
        }
        
        // Apply manual boosts
        auto it = importanceBoosts_.find(token.id);
        if (it != importanceBoosts_.end()) {
            token.importance *= it->second;
        }
    }
}

void DeepContextManager::compressOldSegments() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    
    for (auto& segment : segments_) {
        if (segment.compressed) continue;
        
        auto age = std::chrono::duration_cast<std::chrono::minutes>(
            now - segment.timestamp).count();
        
        // Compress segments older than 10 minutes
        if (age > 10 && segment.tokens.size() > 100) {
            segment.summary = summarizeSegment(segment);
            segment.compressed = true;
            segment.tokens.clear();
            stats_.compressedTokens += segment.tokens.size();
        }
    }
}

std::string DeepContextManager::summarizeSegment(const ContextSegment& segment) {
    // Simple summarization - in production would use actual LLM
    std::stringstream summary;
    summary << "[" << segment.category << "] ";
    
    if (segment.tokens.size() > 10) {
        summary << segment.tokens[0].text;
        for (size_t i = 1; i < std::min(size_t(5), segment.tokens.size()); ++i) {
            summary << " " << segment.tokens[i].text;
        }
        summary << " ... ";
        for (size_t i = segment.tokens.size() - 3; i < segment.tokens.size(); ++i) {
            summary << " " << segment.tokens[i].text;
        }
    } else {
        for (const auto& token : segment.tokens) {
            summary << token.text << " ";
        }
    }
    
    return summary.str();
}

void DeepContextManager::mergeCompressedSegments() {
    // Merge adjacent compressed segments of same category
    std::vector<ContextSegment> merged;
    
    for (auto& segment : segments_) {
        if (!merged.empty() && merged.back().compressed && segment.compressed &&
            merged.back().category == segment.category) {
            merged.back().summary += " | " + segment.summary;
        } else {
            merged.push_back(segment);
        }
    }
    
    segments_ = std::move(merged);
}

void DeepContextManager::maintainTokenLimit() {
    while (stats_.totalTokens > MAX_CONTEXT_TOKENS && !segments_.empty()) {
        // Remove oldest non-system segment
        auto oldest = segments_.begin();
        for (auto it = segments_.begin(); it != segments_.end(); ++it) {
            if (it->category != "system" && 
                (oldest->category == "system" || it->timestamp < oldest->timestamp)) {
                oldest = it;
            }
        }
        
        if (oldest->category == "system") break; // Don't remove system
        
        stats_.totalTokens -= oldest->tokens.size();
        segments_.erase(oldest);
    }
}

void DeepContextManager::updateStats() {
    stats_.activeTokens = stats_.totalTokens - stats_.compressedTokens;
    if (stats_.totalTokens > 0) {
        stats_.avgCompressionRatio = static_cast<float>(stats_.compressedTokens) / stats_.totalTokens;
    }
}

ContextStats DeepContextManager::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

size_t DeepContextManager::getTokenCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_.totalTokens;
}

size_t DeepContextManager::getAvailableSpace() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return MAX_CONTEXT_TOKENS - stats_.totalTokens;
}

float DeepContextManager::getUtilization() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<float>(stats_.totalTokens) / MAX_CONTEXT_TOKENS;
}

float DeepContextManager::calculateTokenImportance(const Token& token) {
    // Base importance
    float importance = 1.0f;
    
    // Punctuation and special tokens have lower importance
    if (token.text.length() <= 2) {
        importance *= 0.5f;
    }
    
    // Capitalized words might be proper nouns
    if (!token.text.empty() && std::isupper(token.text[0])) {
        importance *= 1.2f;
    }
    
    return importance;
}

void DeepContextManager::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    segments_.clear();
    categoryIndex_.clear();
    compressedMemories_.clear();
    stats_ = ContextStats{};
}

void DeepContextManager::clearCategory(const std::string& category) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    segments_.erase(
        std::remove_if(segments_.begin(), segments_.end(),
            [&category](const ContextSegment& s) { return s.category == category; }),
        segments_.end()
    );
    
    categoryIndex_.erase(category);
    updateStats();
}

void DeepContextManager::startNewTurn() {
    std::lock_guard<std::mutex> lock(mutex_);
    currentTurn_++;
}

void DeepContextManager::endTurn() {
    // Mark current segments as belonging to completed turn
}

size_t DeepContextManager::getTurnCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return currentTurn_;
}

void DeepContextManager::registerToolContext(const std::string& toolName, const std::string& contextSchema) {
    std::lock_guard<std::mutex> lock(mutex_);
    toolContexts_[toolName] = contextSchema;
}

void DeepContextManager::injectToolContext(const std::string& toolName) {
    auto it = toolContexts_.find(toolName);
    if (it != toolContexts_.end()) {
        addText(it->second, "tool");
    }
}

} // namespace swarm
} // namespace rawrxd
