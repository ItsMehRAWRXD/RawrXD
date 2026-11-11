// ============================================================================
// CompletionEngine.cpp — Real-time ghost text implementation
// Phase 15 — Product Layer
// ============================================================================

#include "CompletionEngine.h"
#include "../core/AIProvider.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace RawrXD {

// ============================================================================
// CompletionEngine Implementation
// ============================================================================
class CompletionEngine::Impl {
public:
    AIProvider* provider = nullptr;
    std::atomic<bool> initialized{false};
    std::atomic<bool> requestInFlight{false};
    std::atomic<bool> shouldCancel{false};
    
    // Statistics
    std::atomic<uint64_t> requestsTotal{0};
    std::atomic<uint64_t> requestsCancelled{0};
    std::atomic<uint64_t> requestsSucceeded{0};
    std::atomic<double> totalLatencyMs{0.0};
    
    // Config
    uint32_t debounceMs = 50;
    uint32_t maxTokens = 64;
    float temperature = 0.2f;
    
    bool Initialize(AIProvider* p) {
        if (!p || !p->IsReady()) {
            return false;
        }
        provider = p;
        initialized = true;
        return true;
    }
    
    CompletionResult DoCompletion(const EditorContext& ctx) {
        CompletionResult result;
        
        auto t0 = std::chrono::high_resolution_clock::now();
        
        // Build FIM prompt
        std::string prompt = FIMContextBuilder::BuildFIMPrompt(ctx);
        
        // Create AI request
        AIRequest req;
        req.type = AIRequestType::Completion;
        req.prompt = prompt;
        req.maxTokens = maxTokens;
        req.temperature = temperature;
        req.stream = false;
        
        // Execute
        auto aiResp = provider->Execute(req);
        
        auto t1 = std::chrono::high_resolution_clock::now();
        double latencyMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
        
        if (!aiResp.success) {
            result.error = aiResp.error;
            return result;
        }
        
        // Parse completion
        CompletionSuggestion suggestion;
        suggestion.text = aiResp.text;
        suggestion.displayText = TruncateDisplay(aiResp.text, 50);
        suggestion.confidence = 0.9f; // Could be derived from logits
        suggestion.tokens = aiResp.tokensGenerated;
        suggestion.latencyMs = latencyMs;
        suggestion.isFullLine = (aiResp.text.find('\n') != std::string::npos);
        
        result.suggestions.push_back(suggestion);
        result.success = true;
        result.totalLatencyMs = latencyMs;
        
        // Update stats
        requestsTotal++;
        requestsSucceeded++;
        totalLatencyMs += latencyMs;
        
        return result;
    }
    
    void DoCompletionStream(const EditorContext& ctx, CompletionStreamCallback callback) {
        std::string prompt = FIMContextBuilder::BuildFIMPrompt(ctx);
        
        AIRequest req;
        req.type = AIRequestType::Completion;
        req.prompt = prompt;
        req.maxTokens = maxTokens;
        req.temperature = temperature;
        req.stream = true;
        
        provider->ExecuteStream(req, [&](const std::string& token, bool done) {
            if (shouldCancel.load()) {
                return; // Early exit on cancel
            }
            callback(token, done);
        });
    }
    
    std::string TruncateDisplay(const std::string& text, size_t maxLen) {
        if (text.length() <= maxLen) return text;
        return text.substr(0, maxLen) + "...";
    }
};

// ============================================================================
// CompletionEngine Public API
// ============================================================================
CompletionEngine::CompletionEngine() : pImpl(std::make_unique<Impl>()) {}
CompletionEngine::~CompletionEngine() = default;

bool CompletionEngine::Initialize(AIProvider* provider) {
    return pImpl->Initialize(provider);
}

void CompletionEngine::RequestCompletion(
    const EditorContext& ctx,
    std::function<void(const CompletionResult&)> callback,
    CancellationToken* cancelToken
) {
    if (!pImpl->initialized) {
        CompletionResult r;
        r.error = "CompletionEngine not initialized";
        callback(r);
        return;
    }
    
    // Debounce: if a request is already in flight, cancel it
    if (pImpl->requestInFlight.exchange(true)) {
        pImpl->shouldCancel = true;
        // Small wait for cancellation
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        pImpl->shouldCancel = false;
    }
    
    // Apply debounce delay
    if (pImpl->debounceMs > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(pImpl->debounceMs));
    }
    
    // Check if cancelled during debounce
    if (cancelToken && cancelToken->IsCancelled()) {
        pImpl->requestsCancelled++;
        pImpl->requestInFlight = false;
        CompletionResult r;
        r.error = "Cancelled during debounce";
        callback(r);
        return;
    }
    
    // Launch async
    std::thread([this, ctx, callback, cancelToken]() {
        // Check cancellation before starting
        if (cancelToken && cancelToken->IsCancelled()) {
            pImpl->requestsCancelled++;
            pImpl->requestInFlight = false;
            CompletionResult r;
            r.error = "Cancelled";
            callback(r);
            return;
        }
        
        auto result = pImpl->DoCompletion(ctx);
        
        if (cancelToken && cancelToken->IsCancelled()) {
            pImpl->requestsCancelled++;
            result.success = false;
            result.error = "Cancelled";
        }
        
        pImpl->requestInFlight = false;
        callback(result);
    }).detach();
}

void CompletionEngine::CancelCurrentRequest() {
    pImpl->shouldCancel = true;
}

bool CompletionEngine::IsReady() const {
    return pImpl->initialized.load();
}

std::string CompletionEngine::GetStatus() const {
    if (!pImpl->initialized) {
        return "CompletionEngine: NOT READY";
    }
    std::stringstream ss;
    ss << "CompletionEngine: READY | "
       << "Requests: " << pImpl->requestsTotal.load()
       << " | Avg Latency: " 
       << (pImpl->requestsSucceeded > 0 ? pImpl->totalLatencyMs / pImpl->requestsSucceeded : 0)
       << " ms";
    return ss.str();
}

CompletionEngine::Stats CompletionEngine::GetStats() const {
    Stats s;
    s.requestsTotal = pImpl->requestsTotal.load();
    s.requestsCancelled = pImpl->requestsCancelled.load();
    s.requestsSucceeded = pImpl->requestsSucceeded.load();
    s.avgLatencyMs = (s.requestsSucceeded > 0) ? pImpl->totalLatencyMs / s.requestsSucceeded : 0;
    return s;
}

// ============================================================================
// FIMContextBuilder Implementation
// ============================================================================
std::string FIMContextBuilder::BuildFIMPrompt(const EditorContext& ctx) {
    // Standard FIM format used by CodeLlama, DeepSeek-Coder, etc.
    // <PRE> prefix <SUF> suffix <MID>
    
    std::string prefix = ctx.prefix;
    std::string suffix = ctx.suffix;
    
    // Truncate to fit context window
    TruncateToContextWindow(prefix, suffix, 4096, 256);
    
    std::stringstream prompt;
    prompt << "<PRE>" << prefix << "<SUF>" << suffix << "<MID>";
    
    return prompt.str();
}

std::string FIMContextBuilder::BuildChatPrompt(const EditorContext& ctx) {
    // For models without native FIM support
    std::stringstream prompt;
    prompt << "Complete the following " << ctx.language << " code:\n\n";
    prompt << "```" << ctx.language << "\n";
    prompt << ctx.prefix;
    prompt << "[COMPLETE HERE]";
    prompt << ctx.suffix;
    prompt << "\n```\n\n";
    prompt << "Completion:";
    
    return prompt.str();
}

std::string FIMContextBuilder::ExtractRelevantContext(const EditorContext& ctx) {
    // Extract imports, class scope, etc.
    // This is a simplified version — real implementation would parse AST
    return ctx.imports;
}

void FIMContextBuilder::TruncateToContextWindow(
    std::string& prefix,
    std::string& suffix,
    size_t maxTokens,
    size_t reserveForCompletion
) {
    // Rough approximation: 1 token ≈ 4 characters
    size_t maxChars = (maxTokens - reserveForCompletion) * 4;
    
    size_t totalLen = prefix.length() + suffix.length();
    if (totalLen <= maxChars) return;
    
    // Prioritize prefix (more context before cursor)
    if (prefix.length() > maxChars * 0.75) {
        prefix = prefix.substr(prefix.length() - (maxChars * 0.75));
    }
    
    if (suffix.length() > maxChars * 0.25) {
        suffix = suffix.substr(0, maxChars * 0.25);
    }
}

// ============================================================================
// PrefixSuffixExtractor Implementation
// ============================================================================
EditorContext PrefixSuffixExtractor::ExtractFromDocument(
    const std::string& fullText,
    uint32_t cursorPos,
    const std::string& filePath,
    const std::string& language
) {
    EditorContext ctx;
    ctx.filePath = filePath;
    ctx.language = language.empty() ? DetectLanguage(filePath) : language;
    
    if (cursorPos > fullText.length()) {
        cursorPos = fullText.length();
    }
    
    ctx.prefix = fullText.substr(0, cursorPos);
    ctx.suffix = fullText.substr(cursorPos);
    
    // Calculate line/column
    ctx.lineNumber = 1;
    ctx.columnNumber = 1;
    for (size_t i = 0; i < cursorPos && i < fullText.length(); ++i) {
        if (fullText[i] == '\n') {
            ctx.lineNumber++;
            ctx.columnNumber = 1;
        } else {
            ctx.columnNumber++;
        }
    }
    
    return ctx;
}

EditorContext PrefixSuffixExtractor::ExtractFromLines(
    const std::vector<std::string>& lines,
    uint32_t cursorLine,
    uint32_t cursorCol,
    const std::string& filePath,
    const std::string& language
) {
    EditorContext ctx;
    ctx.filePath = filePath;
    ctx.language = language;
    ctx.lineNumber = cursorLine;
    ctx.columnNumber = cursorCol;
    
    // Build prefix from lines before and current line
    std::stringstream prefix;
    for (uint32_t i = 0; i < cursorLine && i < lines.size(); ++i) {
        prefix << lines[i] << "\n";
    }
    if (cursorLine < lines.size()) {
        prefix << lines[cursorLine].substr(0, cursorCol);
    }
    ctx.prefix = prefix.str();
    
    // Build suffix from current line and lines after
    std::stringstream suffix;
    if (cursorLine < lines.size()) {
        suffix << lines[cursorLine].substr(cursorCol) << "\n";
    }
    for (uint32_t i = cursorLine + 1; i < lines.size(); ++i) {
        suffix << lines[i] << "\n";
    }
    ctx.suffix = suffix.str();
    
    return ctx;
}

std::string PrefixSuffixExtractor::GetCurrentScope(
    const std::vector<std::string>& lines,
    uint32_t cursorLine
) {
    // Simple scope detection — look for class/function definitions
    std::string scope;
    for (int i = static_cast<int>(cursorLine); i >= 0; --i) {
        const std::string& line = lines[i];
        if (line.find("class ") != std::string::npos ||
            line.find("struct ") != std::string::npos ||
            line.find("void ") != std::string::npos ||
            line.find("int ") != std::string::npos ||
            line.find("bool ") != std::string::npos) {
            scope = line;
            break;
        }
    }
    return scope;
}

std::string PrefixSuffixExtractor::DetectLanguage(const std::string& filePath) {
    size_t dot = filePath.rfind('.');
    if (dot == std::string::npos) return "text";
    
    std::string ext = filePath.substr(dot + 1);
    if (ext == "cpp" || ext == "cxx" || ext == "cc" || ext == "h" || ext == "hpp") return "cpp";
    if (ext == "c") return "c";
    if (ext == "py") return "python";
    if (ext == "js") return "javascript";
    if (ext == "ts") return "typescript";
    if (ext == "rs") return "rust";
    if (ext == "go") return "go";
    if (ext == "java") return "java";
    if (ext == "cs") return "csharp";
    if (ext == "asm") return "asm";
    return "text";
}

// ============================================================================
// CompletionRanker Implementation
// ============================================================================
std::vector<CompletionRanker::ScoredSuggestion> CompletionRanker::Rank(
    const std::vector<std::string>& rawCompletions,
    const EditorContext& ctx
) {
    std::vector<ScoredSuggestion> scored;
    
    for (const auto& text : rawCompletions) {
        CompletionSuggestion suggestion;
        suggestion.text = text;
        suggestion.displayText = text.substr(0, 50);
        
        ScoredSuggestion ss;
        ss.suggestion = suggestion;
        ss.score = Score(suggestion, ctx);
        scored.push_back(ss);
    }
    
    // Sort by score descending
    std::sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
        return a.score > b.score;
    });
    
    return scored;
}

float CompletionRanker::Score(const CompletionSuggestion& item, const EditorContext& ctx) {
    float score = item.confidence;
    
    // Prefer longer completions (more value)
    score += std::min(item.text.length() / 100.0f, 0.2f);
    
    // Prefer completions that match indentation
    std::string indent = GetIndentation(ctx.prefix);
    if (!indent.empty() && item.text.find(indent) == 0) {
        score += 0.1f;
    }
    
    // Prefer syntactically complete suggestions
    int openParens = std::count(item.text.begin(), item.text.end(), '(');
    int closeParens = std::count(item.text.begin(), item.text.end(), ')');
    if (openParens == closeParens) {
        score += 0.05f;
    }
    
    return score;
}

std::vector<CompletionSuggestion> CompletionRanker::FilterByConfidence(
    const std::vector<ScoredSuggestion>& scored,
    float threshold
) {
    std::vector<CompletionSuggestion> filtered;
    for (const auto& ss : scored) {
        if (ss.score >= threshold) {
            filtered.push_back(ss.suggestion);
        }
    }
    return filtered;
}

std::vector<CompletionSuggestion> CompletionRanker::Deduplicate(
    const std::vector<CompletionSuggestion>& suggestions
) {
    std::vector<CompletionSuggestion> unique;
    std::unordered_set<std::string> seen;
    
    for (const auto& s : suggestions) {
        // Normalize for dedup
        std::string key = s.text;
        // Remove trailing whitespace
        while (!key.empty() && isspace(key.back())) key.pop_back();
        
        if (seen.find(key) == seen.end()) {
            seen.insert(key);
            unique.push_back(s);
        }
    }
    
    return unique;
}

// ============================================================================
// CompletionCache Implementation
// ============================================================================
CompletionCache::CompletionCache(size_t maxEntries) : maxEntries_(maxEntries) {}

bool CompletionCache::Get(const CacheKey& key, CompletionResult& out) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = entries_.find(key);
    if (it == entries_.end()) {
        return false;
    }
    
    // Check TTL
    auto age = std::chrono::steady_clock::now() - it->second.timestamp;
    if (age > std::chrono::minutes(5)) {
        entries_.erase(it);
        return false;
    }
    
    out = it->second.result;
    it->second.hitCount++;
    return true;
}

void CompletionCache::Put(const CacheKey& key, const CompletionResult& result) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Evict if at capacity
    if (entries_.size() >= maxEntries_) {
        // Simple eviction: remove oldest
        auto oldest = entries_.begin();
        for (auto it = entries_.begin(); it != entries_.end(); ++it) {
            if (it->second.timestamp < oldest->second.timestamp) {
                oldest = it;
            }
        }
        entries_.erase(oldest);
    }
    
    CacheEntry entry;
    entry.result = result;
    entry.timestamp = std::chrono::steady_clock::now();
    entries_[key] = entry;
}

void CompletionCache::InvalidateFile(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Remove entries matching file
    for (auto it = entries_.begin(); it != entries_.end();) {
        // Would need to track file in key — simplified
        ++it;
    }
}

void CompletionCache::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
}

} // namespace RawrXD
