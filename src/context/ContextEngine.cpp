// ============================================================================
// ContextEngine.cpp - Intelligent Context Assembly Implementation
// ============================================================================

#include "ContextEngine.hpp"
#include "../intelligence/codebase_intelligence.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <chrono>

namespace RawrXD {
namespace Context {

// ============================================================================
// Implementation
// ============================================================================
class ContextEngine::Impl {
public:
    Intelligence::CodebaseIntelligence* intelligence_ = nullptr;
    ContextBudget defaultBudget_;
    std::map<ContextStrategy, std::map<ContextItemType, float>> strategyWeights_;
    
    // Cache
    struct CacheEntry {
        AssembledContext context;
        std::chrono::system_clock::time_point timestamp;
    };
    std::map<std::string, CacheEntry> cache_;
    mutable std::mutex cacheMutex_;
    
    // Stats
    Stats stats_;
    mutable std::mutex statsMutex_;
    
    Impl() {
        // Default budget
        defaultBudget_.maxTokens = 4096;
        defaultBudget_.reservedForResponse = 1024;
        
        // Default weights for completion strategy
        strategyWeights_[ContextStrategy::Completion] = {
            {ContextItemType::CurrentFile, 1.0f},
            {ContextItemType::Import, 0.9f},
            {ContextItemType::Symbol, 0.8f},
            {ContextItemType::RecentEdit, 0.7f},
            {ContextItemType::OpenFile, 0.6f},
            {ContextItemType::Error, 0.5f},
            {ContextItemType::RepositoryPattern, 0.4f}
        };
        
        // Default weights for chat strategy
        strategyWeights_[ContextStrategy::Chat] = {
            {ContextItemType::CurrentFile, 0.9f},
            {ContextItemType::OpenFile, 0.8f},
            {ContextItemType::RecentEdit, 0.7f},
            {ContextItemType::Conversation, 0.9f},
            {ContextItemType::RepositoryPattern, 0.6f}
        };
        
        // Default weights for agent strategy
        strategyWeights_[ContextStrategy::AgentTask] = {
            {ContextItemType::CurrentFile, 1.0f},
            {ContextItemType::Import, 0.9f},
            {ContextItemType::Symbol, 0.9f},
            {ContextItemType::Error, 0.8f},
            {ContextItemType::Test, 0.7f},
            {ContextItemType::RepositoryPattern, 0.8f},
            {ContextItemType::Documentation, 0.6f}
        };
    }
    
    AssembledContext AssembleInternal(
        const EditorState& editor,
        ContextStrategy strategy,
        const std::string& userQuery
    ) {
        auto startTime = std::chrono::high_resolution_clock::now();
        
        AssembledContext result;
        result.budget = defaultBudget_;
        
        // Step 1: Gather context items
        std::vector<ContextItem> items = GatherContextItems(editor, strategy);
        
        // Step 2: Rank by relevance
        items = ContextRanker::Rank(items, editor, strategy);
        
        // Step 3: Select items to fit budget
        items = SelectItemsForBudget(items, result.budget);
        
        // Step 4: Build prompt
        result.prompt = PromptBuilder::Build(items, strategy, userQuery);
        result.items = items;
        result.totalTokens = TokenCounter::Count(items);
        result.budget.usedTokens = result.totalTokens;
        
        // Collect metadata
        for (const auto& item : items) {
            if (!item.source.empty() && item.type == ContextItemType::CurrentFile) {
                result.includedFiles.push_back(item.source);
            }
        }
        result.primaryLanguage = editor.language;
        
        // Update stats
        auto endTime = std::chrono::high_resolution_clock::now();
        double durationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.assembliesTotal++;
        stats_.avgAssemblyTimeMs = (stats_.avgAssemblyTimeMs * (stats_.assembliesTotal - 1) + durationMs) 
                                    / stats_.assembliesTotal;
        stats_.avgContextTokens = (stats_.avgContextTokens * (stats_.assembliesTotal - 1) + result.totalTokens)
                                   / stats_.assembliesTotal;
        
        return result;
    }
    
    std::vector<ContextItem> GatherContextItems(
        const EditorState& editor,
        ContextStrategy strategy
    ) {
        std::vector<ContextItem> items;
        
        // Current file (always critical)
        {
            ContextItem item;
            item.type = ContextItemType::CurrentFile;
            item.priority = ContextPriority::Critical;
            item.content = editor.prefix + "<CURSOR>" + editor.suffix;
            item.source = editor.filePath;
            item.tokens = TokenCounter::Count(item.content);
            item.relevance = 1.0f;
            item.timestamp = std::chrono::system_clock::now();
            items.push_back(item);
        }
        
        // Recent edits
        for (const auto& edit : editor.recentEdits) {
            ContextItem item;
            item.type = ContextItemType::RecentEdit;
            item.priority = ContextPriority::High;
            item.content = "Recent edit in " + edit.file + " at line " + std::to_string(edit.startLine) + ": " + edit.change;
            item.source = edit.file;
            item.tokens = TokenCounter::Count(item.content);
            item.relevance = 0.7f;
            item.timestamp = edit.timestamp;
            items.push_back(item);
        }
        
        // Open files
        for (const auto& file : editor.openFiles) {
            if (file != editor.filePath) {
                ContextItem item;
                item.type = ContextItemType::OpenFile;
                item.priority = ContextPriority::Medium;
                item.content = "Open file: " + file;
                item.source = file;
                item.tokens = TokenCounter::Count(item.content);
                item.relevance = 0.5f;
                item.timestamp = std::chrono::system_clock::now();
                items.push_back(item);
            }
        }
        
        // Diagnostics (errors/warnings)
        for (const auto& diag : editor.diagnostics) {
            ContextItem item;
            item.type = ContextItemType::Error;
            item.priority = ContextPriority::High;
            item.content = "[" + diag.severity + "] " + diag.file + ":" + std::to_string(diag.line) + " - " + diag.message;
            item.source = diag.file;
            item.tokens = TokenCounter::Count(item.content);
            item.relevance = 0.8f;
            item.timestamp = std::chrono::system_clock::now();
            items.push_back(item);
        }
        
        // Query codebase intelligence if available
        if (intelligence_) {
            // Add symbols from current file
            // Add imports/dependencies
            // Add related files
        }
        
        return items;
    }
    
    std::vector<ContextItem> SelectItemsForBudget(
        std::vector<ContextItem>& items,
        ContextBudget& budget
    ) {
        std::vector<ContextItem> selected;
        uint32_t totalTokens = 0;
        
        // Always include critical items
        for (const auto& item : items) {
            if (item.priority == ContextPriority::Critical) {
                selected.push_back(item);
                totalTokens += item.tokens;
            }
        }
        
        // Add high priority items that fit
        for (const auto& item : items) {
            if (item.priority == ContextPriority::High && budget.CanFit(totalTokens + item.tokens)) {
                selected.push_back(item);
                totalTokens += item.tokens;
            }
        }
        
        // Add medium priority items that fit
        for (const auto& item : items) {
            if (item.priority == ContextPriority::Medium && budget.CanFit(totalTokens + item.tokens)) {
                selected.push_back(item);
                totalTokens += item.tokens;
            }
        }
        
        // Add low priority items if space remains
        for (const auto& item : items) {
            if (item.priority == ContextPriority::Low && budget.CanFit(totalTokens + item.tokens)) {
                selected.push_back(item);
                totalTokens += item.tokens;
            }
        }
        
        budget.usedTokens = totalTokens;
        return selected;
    }
};

// ============================================================================
// ContextEngine Public Interface
// ============================================================================
ContextEngine::ContextEngine() : pImpl(std::make_unique<Impl>()) {}
ContextEngine::~ContextEngine() = default;

bool ContextEngine::Initialize(Intelligence::CodebaseIntelligence* intelligence) {
    pImpl->intelligence_ = intelligence;
    std::cout << "[ContextEngine] Initialized\n";
    return true;
}

AssembledContext ContextEngine::Assemble(
    const EditorState& editor,
    ContextStrategy strategy,
    const std::string& userQuery
) {
    return pImpl->AssembleInternal(editor, strategy, userQuery);
}

AssembledContext ContextEngine::AssembleForCompletion(const EditorState& editor) {
    return Assemble(editor, ContextStrategy::Completion, "");
}

AssembledContext ContextEngine::AssembleForChat(const EditorState& editor, const std::string& query) {
    return Assemble(editor, ContextStrategy::Chat, query);
}

AssembledContext ContextEngine::AssembleForAgent(const EditorState& editor, const std::string& task) {
    return Assemble(editor, ContextStrategy::AgentTask, task);
}

AssembledContext ContextEngine::AssembleForDebug(const EditorState& editor) {
    return Assemble(editor, ContextStrategy::Debug, "");
}

void ContextEngine::SetBudget(uint32_t maxTokens) {
    pImpl->defaultBudget_.maxTokens = maxTokens;
}

void ContextEngine::SetStrategyWeights(
    ContextStrategy strategy,
    const std::map<ContextItemType, float>& weights
) {
    pImpl->strategyWeights_[strategy] = weights;
}

void ContextEngine::InvalidateCache(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(pImpl->cacheMutex_);
    pImpl->cache_.erase(filePath);
}

void ContextEngine::ClearCache() {
    std::lock_guard<std::mutex> lock(pImpl->cacheMutex_);
    pImpl->cache_.clear();
}

ContextEngine::Stats ContextEngine::GetStats() const {
    std::lock_guard<std::mutex> lock(pImpl->statsMutex_);
    return pImpl->stats_;
}

// ============================================================================
// TokenCounter Implementation
// ============================================================================
uint32_t TokenCounter::Count(const std::string& text) {
    // Simple approximation: ~4 characters per token on average
    // This is a rough estimate - production would use actual tokenizer
    return static_cast<uint32_t>(text.length() / 4) + 1;
}

uint32_t TokenCounter::Count(const std::vector<ContextItem>& items) {
    uint32_t total = 0;
    for (const auto& item : items) {
        total += item.tokens;
    }
    return total;
}

uint32_t TokenCounter::CountCode(const std::string& code, const std::string& language) {
    // Code typically has higher token density
    uint32_t baseCount = Count(code);
    
    // Adjust for language
    if (language == "cpp" || language == "c++" || language == "c") {
        // C-style languages have more tokens per char due to symbols
        return static_cast<uint32_t>(baseCount * 1.2f);
    } else if (language == "python") {
        // Python is more token-efficient
        return static_cast<uint32_t>(baseCount * 0.9f);
    }
    
    return baseCount;
}

// ============================================================================
// ContextRanker Implementation
// ============================================================================
std::vector<ContextItem> ContextRanker::Rank(
    const std::vector<ContextItem>& items,
    const EditorState& editor,
    ContextStrategy strategy
) {
    std::vector<ContextItem> ranked = items;
    
    // Calculate relevance for each item
    for (auto& item : ranked) {
        item.relevance = CalculateRelevance(item, editor, strategy);
    }
    
    // Sort by relevance (highest first)
    std::sort(ranked.begin(), ranked.end(), [](const ContextItem& a, const ContextItem& b) {
        return a.relevance > b.relevance;
    });
    
    return ranked;
}

float ContextRanker::CalculateRelevance(
    const ContextItem& item,
    const EditorState& editor,
    ContextStrategy strategy
) {
    float score = 0.0f;
    
    // Base score from priority
    switch (item.priority) {
        case ContextPriority::Critical: score = 1.0f; break;
        case ContextPriority::High: score = 0.8f; break;
        case ContextPriority::Medium: score = 0.5f; break;
        case ContextPriority::Low: score = 0.3f; break;
        default: score = 0.0f;
    }
    
    // Boost for same file
    if (item.source == editor.filePath) {
        score += 0.2f;
    }
    
    // Boost for recent items
    auto now = std::chrono::system_clock::now();
    auto age = std::chrono::duration<double>(now - item.timestamp).count();
    if (age < 60.0) {  // Less than 1 minute old
        score += 0.1f;
    }
    
    // Strategy-specific adjustments
    if (strategy == ContextStrategy::Debug && item.type == ContextItemType::Error) {
        score += 0.3f;
    }
    
    if (strategy == ContextStrategy::Completion && item.type == ContextItemType::Import) {
        score += 0.15f;
    }
    
    return std::min(score, 1.0f);
}

// ============================================================================
// PromptBuilder Implementation
// ============================================================================
std::string PromptBuilder::Build(
    const std::vector<ContextItem>& items,
    ContextStrategy strategy,
    const std::string& userQuery
) {
    switch (strategy) {
        case ContextStrategy::Completion:
            return BuildFIMPrompt("", "", items);
        case ContextStrategy::Chat:
            return BuildChatPrompt(items, userQuery, {});
        case ContextStrategy::AgentTask:
            return BuildAgentPrompt(items, userQuery, {});
        default:
            return BuildChatPrompt(items, userQuery, {});
    }
}

std::string PromptBuilder::BuildFIMPrompt(
    const std::string& prefix,
    const std::string& suffix,
    const std::vector<ContextItem>& context
) {
    std::ostringstream prompt;
    
    // Add context items first
    if (!context.empty()) {
        prompt << "// Context:\n";
        for (const auto& item : context) {
            if (item.type != ContextItemType::CurrentFile) {
                prompt << "// " << item.content << "\n";
            }
        }
        prompt << "\n";
    }
    
    // FIM format: <fim_prefix>...<fim_suffix>...<fim_middle>
    prompt << "<fim_prefix>" << prefix << "<fim_suffix>" << suffix << "<fim_middle>";
    
    return prompt.str();
}

std::string PromptBuilder::BuildChatPrompt(
    const std::vector<ContextItem>& context,
    const std::string& query,
    const std::vector<std::pair<std::string, std::string>>& history
) {
    std::ostringstream prompt;
    
    prompt << "You are an AI coding assistant. Help the user with their programming task.\n\n";
    
    // Add context
    if (!context.empty()) {
        prompt << "Context:\n";
        for (const auto& item : context) {
            prompt << "- " << item.content << "\n";
        }
        prompt << "\n";
    }
    
    // Add history
    for (const auto& [role, message] : history) {
        prompt << role << ": " << message << "\n";
    }
    
    // Add current query
    prompt << "User: " << query << "\n";
    prompt << "Assistant: ";
    
    return prompt.str();
}

std::string PromptBuilder::BuildAgentPrompt(
    const std::vector<ContextItem>& context,
    const std::string& task,
    const std::vector<std::string>& availableTools
) {
    std::ostringstream prompt;
    
    prompt << "You are an autonomous software engineering agent. Your task is to:\n";
    prompt << task << "\n\n";
    
    prompt << "Rules:\n";
    prompt << "1. Analyze the context before making changes\n";
    prompt << "2. Make the smallest change that achieves the goal\n";
    prompt << "3. Use the available tools to interact with the codebase\n";
    prompt << "4. Test your changes before completing\n";
    prompt << "5. If you encounter errors, debug and retry\n\n";
    
    // Add context
    if (!context.empty()) {
        prompt << "Context:\n";
        for (const auto& item : context) {
            prompt << "- " << item.content << "\n";
        }
        prompt << "\n";
    }
    
    // Add available tools
    if (!availableTools.empty()) {
        prompt << "Available Tools:\n";
        for (const auto& tool : availableTools) {
            prompt << "- " << tool << "\n";
        }
        prompt << "\n";
    }
    
    prompt << "Begin by analyzing the current state and creating a plan.\n";
    
    return prompt.str();
}

} // namespace Context
} // namespace RawrXD
