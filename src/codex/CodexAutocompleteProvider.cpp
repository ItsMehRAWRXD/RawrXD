// ============================================================================
// RawrXD Codex Autocomplete Provider Implementation
// ============================================================================

#include "CodexAutocompleteProvider.hpp"
#include <algorithm>
#include <cctype>
#include <thread>

namespace RawrXD {
namespace Codex {

CodexAutocompleteProvider::CodexAutocompleteProvider() = default;
CodexAutocompleteProvider::~CodexAutocompleteProvider() {
    Shutdown();
}

bool CodexAutocompleteProvider::Initialize(std::shared_ptr<CodexCLI> cli) {
    m_cli = cli;
    if (!m_cli || !m_cli->IsInitialized()) {
        return false;
    }
    
    // Initialize LSP bridge for inline completions
    m_lspBridge = std::make_shared<CodexLSPBridge>();
    if (!m_lspBridge->Initialize(m_cli)) {
        m_lspBridge.reset();
    }
    
    m_initialized = true;
    return true;
}

void CodexAutocompleteProvider::Shutdown() {
    CancelPending();
    m_initialized = false;
    m_lspBridge.reset();
    m_cli.reset();
}

std::vector<AutocompleteItem> CodexAutocompleteProvider::ProvideCompletions(
    const AutocompleteContext& context,
    int maxItems
) {
    std::vector<AutocompleteItem> results;
    
    if (!m_initialized || !m_enabled || !m_cli) {
        return results;
    }
    
    // Check if we should provide completions
    if (!ShouldProvideCompletions(context)) {
        return results;
    }
    
    m_cancelled = false;
    
    // Try LSP bridge first for inline completions
    if (m_lspBridge) {
        CompletionContext lspCtx;
        lspCtx.filePath = context.filePath;
        lspCtx.language = context.language;
        lspCtx.cursor.line = context.line;
        lspCtx.cursor.character = context.column;
        lspCtx.prefix = context.prefix;
        lspCtx.suffix = context.suffix;
        lspCtx.surrounding = context.surrounding;
        
        auto inlineItems = m_lspBridge->ProvideInlineCompletions(lspCtx, maxItems);
        
        for (const auto& item : inlineItems) {
            if (m_cancelled) break;
            
            AutocompleteItem acItem;
            acItem.label = item.text.substr(0, 50); // Truncate for label
            acItem.insertText = item.insertText;
            acItem.detail = "AI Completion";
            acItem.documentation = item.insertText;
            acItem.kind = "snippet";
            acItem.confidence = item.confidence;
            acItem.source = "codex";
            acItem.sortOrder = static_cast<int>(item.confidence * 100);
            
            if (acItem.confidence >= m_confidenceThreshold) {
                results.push_back(acItem);
            }
        }
    }
    
    // If no results from LSP bridge, try direct completion
    if (results.empty() && !m_cancelled) {
        std::string prompt = BuildCompletionPrompt(context);
        std::string completion = m_cli->Complete(prompt);
        
        if (!completion.empty() && !m_cancelled) {
            AutocompleteItem item;
            item.label = completion.substr(0, 50);
            item.insertText = completion;
            item.detail = "AI Completion";
            item.documentation = completion;
            item.kind = "snippet";
            item.confidence = CalculateConfidence(completion);
            item.source = "codex";
            item.sortOrder = static_cast<int>(item.confidence * 100);
            
            if (item.confidence >= m_confidenceThreshold) {
                results.push_back(item);
            }
        }
    }
    
    // Sort by confidence
    std::sort(results.begin(), results.end(), 
        [](const AutocompleteItem& a, const AutocompleteItem& b) {
            return a.confidence > b.confidence;
        });
    
    // Limit results
    if (results.size() > static_cast<size_t>(maxItems)) {
        results.resize(maxItems);
    }
    
    return results;
}

bool CodexAutocompleteProvider::ShouldProvideCompletions(const AutocompleteContext& context) {
    // Don't provide if disabled
    if (!m_enabled) return false;
    
    // Don't provide if prefix is too short (unless after trigger)
    if (context.prefix.length() < 2 && !IsTriggerCharacter(context.prefix)) {
        return false;
    }
    
    // Don't provide in comments or strings (simple heuristic)
    if (context.lineText.find("//") != std::string::npos ||
        context.lineText.find("/*") != std::string::npos) {
        // Check if cursor is after comment start
        size_t commentPos = context.lineText.find("//");
        if (commentPos != std::string::npos && 
            static_cast<int>(commentPos) < context.column) {
            return false;
        }
    }
    
    // Check for string literals (simplified)
    int quoteCount = 0;
    for (int i = 0; i < context.column && i < static_cast<int>(context.lineText.length()); ++i) {
        if (context.lineText[i] == '"' && (i == 0 || context.lineText[i-1] != '\\')) {
            quoteCount++;
        }
    }
    if (quoteCount % 2 == 1) {
        return false; // Inside string literal
    }
    
    return true;
}

void CodexAutocompleteProvider::CancelPending() {
    m_cancelled = true;
    m_asyncPending = false;
    
    if (m_lspBridge) {
        m_lspBridge->CancelPendingCompletion();
    }
}

std::vector<AutocompleteItem> CodexAutocompleteProvider::MergeWithLSPCompletions(
    const std::vector<AutocompleteItem>& codexItems,
    const std::vector<AutocompleteItem>& lspItems,
    int maxTotal
) {
    std::vector<AutocompleteItem> merged;
    
    // Add all LSP items first
    for (const auto& item : lspItems) {
        merged.push_back(item);
    }
    
    // Add Codex items that don't duplicate LSP items
    for (const auto& codexItem : codexItems) {
        bool duplicate = false;
        for (const auto& lspItem : lspItems) {
            if (codexItem.insertText == lspItem.insertText ||
                codexItem.label == lspItem.label) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            merged.push_back(codexItem);
        }
    }
    
    // Sort by confidence/source priority
    std::sort(merged.begin(), merged.end(),
        [](const AutocompleteItem& a, const AutocompleteItem& b) {
            // LSP items get priority if confidence is similar
            if (a.source == "lsp" && b.source != "lsp") {
                return a.confidence > b.confidence * 0.8f;
            }
            if (b.source == "lsp" && a.source != "lsp") {
                return a.confidence * 0.8f > b.confidence;
            }
            return a.confidence > b.confidence;
        });
    
    // Limit results
    if (merged.size() > static_cast<size_t>(maxTotal)) {
        merged.resize(maxTotal);
    }
    
    return merged;
}

void CodexAutocompleteProvider::RequestAsyncCompletion(const AutocompleteContext& context) {
    if (!m_initialized || !m_enabled || m_asyncPending) {
        return;
    }
    
    m_asyncPending = true;
    m_cancelled = false;
    
    // Launch async worker
    std::thread worker([this, context]() {
        AsyncCompletionWorker(context);
    });
    worker.detach();
}

void CodexAutocompleteProvider::AsyncCompletionWorker(const AutocompleteContext& context) {
    auto results = ProvideCompletions(context);
    
    if (!m_cancelled && m_asyncCallback) {
        m_asyncCallback(results);
    }
    
    m_asyncPending = false;
}

std::string CodexAutocompleteProvider::BuildCompletionPrompt(const AutocompleteContext& ctx) {
    std::string prompt;
    prompt.reserve(ctx.prefix.length() + ctx.suffix.length() + 200);
    
    prompt += "Complete the " + ctx.language + " code at the cursor position:\n\n";
    prompt += "```" + ctx.language + "\n";
    
    // Add surrounding context
    if (!ctx.surrounding.empty()) {
        prompt += ctx.surrounding;
    } else {
        prompt += ctx.prefix;
        prompt += "<CURSOR>";
        prompt += ctx.suffix;
    }
    
    prompt += "\n```\n\n";
    prompt += "Provide only the completion text (what should replace <CURSOR>):";
    
    return prompt;
}

std::vector<AutocompleteItem> CodexAutocompleteProvider::ParseCompletionResponse(
    const std::string& response
) {
    std::vector<AutocompleteItem> items;
    
    // Simple parsing - treat entire response as one completion
    if (!response.empty()) {
        AutocompleteItem item;
        item.label = response.substr(0, 50);
        item.insertText = response;
        item.detail = "AI Completion";
        item.documentation = response;
        item.kind = "snippet";
        item.confidence = CalculateConfidence(response);
        item.source = "codex";
        items.push_back(item);
    }
    
    return items;
}

float CodexAutocompleteProvider::CalculateConfidence(const std::string& completion) {
    // Simple heuristic based on completion quality
    float confidence = 0.7f; // Base confidence
    
    // Longer completions might be less reliable
    if (completion.length() > 100) {
        confidence -= 0.1f;
    }
    if (completion.length() > 200) {
        confidence -= 0.1f;
    }
    
    // Check for balanced braces/parens
    int openBrace = 0, openParen = 0;
    for (char c : completion) {
        if (c == '{') openBrace++;
        if (c == '}') openBrace--;
        if (c == '(') openParen++;
        if (c == ')') openParen--;
    }
    if (openBrace == 0 && openParen == 0) {
        confidence += 0.1f;
    }
    
    // Check for common keywords (language agnostic)
    std::string lower = completion;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.find("function") != std::string::npos ||
        lower.find("class") != std::string::npos ||
        lower.find("return") != std::string::npos ||
        lower.find("if") != std::string::npos ||
        lower.find("for") != std::string::npos) {
        confidence += 0.05f;
    }
    
    return std::min(1.0f, std::max(0.0f, confidence));
}

bool CodexAutocompleteProvider::IsTriggerCharacter(const std::string& prefix) {
    for (const auto& trigger : m_triggerChars) {
        if (prefix.length() >= trigger.length()) {
            std::string suffix = prefix.substr(prefix.length() - trigger.length());
            if (suffix == trigger) {
                return true;
            }
        }
    }
    return false;
}

std::string CodexAutocompleteProvider::ExtractLanguage(const std::string& filePath) {
    size_t dot = filePath.rfind('.');
    if (dot == std::string::npos) {
        return "text";
    }
    
    std::string ext = filePath.substr(dot + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    
    if (ext == "cpp" || ext == "cc" || ext == "cxx" || ext == "h" || ext == "hpp") {
        return "cpp";
    } else if (ext == "c") {
        return "c";
    } else if (ext == "py") {
        return "python";
    } else if (ext == "js" || ext == "mjs") {
        return "javascript";
    } else if (ext == "ts" || ext == "tsx") {
        return "typescript";
    } else if (ext == "rs") {
        return "rust";
    } else if (ext == "go") {
        return "go";
    } else if (ext == "java") {
        return "java";
    } else if (ext == "cs") {
        return "csharp";
    }
    
    return "text";
}

} // namespace Codex
} // namespace RawrXD
