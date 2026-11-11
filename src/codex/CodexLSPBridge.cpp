// ============================================================================
// RawrXD Codex LSP Bridge Implementation
// ============================================================================

#include "CodexLSPBridge.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>

namespace RawrXD {
namespace Codex {

CodexLSPBridge::CodexLSPBridge() = default;
CodexLSPBridge::~CodexLSPBridge() {
    Shutdown();
}

bool CodexLSPBridge::Initialize(std::shared_ptr<CodexCLI> cli) {
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

void CodexLSPBridge::Shutdown() {
    m_initialized = false;
    m_eventBus.reset();
    m_cli.reset();
}

std::vector<InlineCompletionItem> CodexLSPBridge::ProvideInlineCompletions(
    const CompletionContext& context,
    int maxItems
) {
    std::vector<InlineCompletionItem> results;
    
    if (!m_initialized || !m_cli) {
        return results;
    }
    
    m_cancelled = false;
    
    // Build prompt from context
    std::string prompt = BuildCompletionPrompt(context);
    
    if (m_streamingEnabled && m_streamCallback) {
        // Streaming completion
        std::string accumulated;
        bool success = m_cli->CompleteStreaming(prompt, 
            [&accumulated, this](const std::string& chunk, bool isFinal) {
                if (m_cancelled) return;
                accumulated += chunk;
                if (m_streamCallback) {
                    m_streamCallback(chunk, isFinal);
                }
            });
        
        if (success && !accumulated.empty()) {
            InlineCompletionItem item;
            item.insertText = accumulated;
            item.text = accumulated;
            item.confidence = 0.85f;
            item.model = m_cli->GetConfig().model;
            item.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
            results.push_back(item);
        }
    } else {
        // Non-streaming completion
        std::string completion = m_cli->Complete(prompt);
        if (!completion.empty()) {
            InlineCompletionItem item;
            item.insertText = completion;
            item.text = completion;
            item.confidence = 0.85f;
            item.model = m_cli->GetConfig().model;
            item.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
            results.push_back(item);
        }
    }
    
    return results;
}

std::string CodexLSPBridge::CompleteAt(const CompletionContext& context) {
    if (!m_initialized || !m_cli) {
        return "";
    }
    
    std::string prompt = BuildCompletionPrompt(context);
    return m_cli->Complete(prompt);
}

void CodexLSPBridge::CancelPendingCompletion() {
    m_cancelled = true;
}

std::vector<CodexCodeAction> CodexLSPBridge::ProvideCodeActions(
    const std::string& filePath,
    const Range& range,
    const std::string& selectedText,
    const std::string& language
) {
    std::vector<CodexCodeAction> actions;
    
    // Always provide Explain action
    actions.push_back(ExplainCode(filePath, range, selectedText));
    
    // Provide Refactor action if text is substantial
    if (selectedText.length() > 20) {
        CodexCodeAction refactor;
        refactor.title = "Refactor with Codex";
        refactor.kind = "refactor";
        refactor.range = range;
        refactor.confidence = 0.8f;
        actions.push_back(refactor);
    }
    
    // Provide Generate Tests for functions/classes
    if (language == "cpp" || language == "python" || language == "javascript") {
        CodexCodeAction test;
        test.title = "Generate Tests";
        test.kind = "quickfix";
        test.range = range;
        test.confidence = 0.75f;
        actions.push_back(test);
    }
    
    return actions;
}

CodexCodeAction CodexLSPBridge::ExplainCode(
    const std::string& filePath,
    const Range& range,
    const std::string& selectedText
) {
    CodexCodeAction action;
    action.title = "Explain with Codex";
    action.kind = "explain";
    action.range = range;
    
    if (!m_initialized || !m_cli || selectedText.empty()) {
        action.confidence = 0.0f;
        return action;
    }
    
    std::string language = DetectLanguage(filePath);
    std::string prompt = BuildExplanationPrompt(selectedText, language);
    std::string explanation = m_cli->Complete(prompt);
    
    action.edit = explanation;
    action.confidence = 0.9f;
    
    return action;
}

CodexCodeAction CodexLSPBridge::RefactorCode(
    const std::string& filePath,
    const Range& range,
    const std::string& selectedText,
    const std::string& instruction
) {
    CodexCodeAction action;
    action.title = "Refactor: " + instruction;
    action.kind = "refactor";
    action.range = range;
    
    if (!m_initialized || !m_cli || selectedText.empty()) {
        action.confidence = 0.0f;
        return action;
    }
    
    std::string prompt = BuildRefactorPrompt(selectedText, instruction);
    std::string refactored = m_cli->Complete(prompt);
    
    action.edit = refactored;
    action.confidence = 0.85f;
    
    return action;
}

CodexCodeAction CodexLSPBridge::GenerateTests(
    const std::string& filePath,
    const Range& range,
    const std::string& selectedText
) {
    CodexCodeAction action;
    action.title = "Generate Tests";
    action.kind = "quickfix";
    action.range = range;
    
    if (!m_initialized || !m_cli || selectedText.empty()) {
        action.confidence = 0.0f;
        return action;
    }
    
    std::string language = DetectLanguage(filePath);
    std::string prompt = BuildTestPrompt(selectedText, language);
    std::string tests = m_cli->Complete(prompt);
    
    action.edit = tests;
    action.confidence = 0.8f;
    
    return action;
}

CodexCodeAction CodexLSPBridge::FixErrors(
    const std::string& filePath,
    const Range& range,
    const std::string& selectedText,
    const std::string& errorMessage
) {
    CodexCodeAction action;
    action.title = "Fix with Codex";
    action.kind = "quickfix";
    action.range = range;
    
    if (!m_initialized || !m_cli || selectedText.empty()) {
        action.confidence = 0.0f;
        return action;
    }
    
    std::string prompt = BuildFixPrompt(selectedText, errorMessage);
    std::string fixed = m_cli->Complete(prompt);
    
    action.edit = fixed;
    action.confidence = 0.85f;
    
    return action;
}

CodexHoverInfo CodexLSPBridge::ProvideHover(
    const std::string& filePath,
    const Position& position,
    const std::string& symbol,
    const std::string& surroundingContext
) {
    CodexHoverInfo info;
    info.range.start = position;
    info.range.end = position;
    
    if (!m_initialized || !m_cli || symbol.empty()) {
        return info;
    }
    
    std::string prompt = BuildHoverPrompt(symbol, surroundingContext);
    std::string explanation = m_cli->Complete(prompt);
    
    info.contents = explanation;
    info.valid = !explanation.empty();
    
    return info;
}

// Helper implementations

std::string CodexLSPBridge::BuildCompletionPrompt(const CompletionContext& ctx) {
    std::string prompt;
    prompt.reserve(ctx.prefix.length() + ctx.suffix.length() + 100);
    
    prompt += "Complete the following " + ctx.language + " code:\n\n";
    prompt += "```" + ctx.language + "\n";
    prompt += ctx.prefix;
    prompt += "<CURSOR>";
    prompt += ctx.suffix;
    prompt += "\n```\n\n";
    prompt += "Provide only the code that should replace <CURSOR>, without explanation:";
    
    return prompt;
}

std::string CodexLSPBridge::BuildExplanationPrompt(const std::string& code, const std::string& language) {
    std::string prompt;
    prompt += "Explain the following " + language + " code:\n\n";
    prompt += "```" + language + "\n";
    prompt += code;
    prompt += "\n```\n\n";
    prompt += "Provide a clear, concise explanation:";
    return prompt;
}

std::string CodexLSPBridge::BuildRefactorPrompt(const std::string& code, const std::string& instruction) {
    std::string prompt;
    prompt += "Refactor the following code to " + instruction + ":\n\n";
    prompt += "```\n";
    prompt += code;
    prompt += "\n```\n\n";
    prompt += "Provide only the refactored code:";
    return prompt;
}

std::string CodexLSPBridge::BuildTestPrompt(const std::string& code, const std::string& language) {
    std::string prompt;
    prompt += "Generate unit tests for the following " + language + " code:\n\n";
    prompt += "```" + language + "\n";
    prompt += code;
    prompt += "\n```\n\n";
    prompt += "Provide comprehensive test cases:";
    return prompt;
}

std::string CodexLSPBridge::BuildFixPrompt(const std::string& code, const std::string& error) {
    std::string prompt;
    prompt += "Fix the following error in this code:\n";
    prompt += "Error: " + error + "\n\n";
    prompt += "```\n";
    prompt += code;
    prompt += "\n```\n\n";
    prompt += "Provide the fixed code:";
    return prompt;
}

std::string CodexLSPBridge::BuildHoverPrompt(const std::string& symbol, const std::string& context) {
    std::string prompt;
    prompt += "Explain what the following symbol does:\n";
    prompt += "Symbol: " + symbol + "\n\n";
    prompt += "Context:\n";
    prompt += "```\n";
    prompt += TruncateToContext(context, 2000);
    prompt += "\n```\n\n";
    prompt += "Provide a brief description:";
    return prompt;
}

std::string CodexLSPBridge::DetectLanguage(const std::string& filePath) {
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
    } else if (ext == "php") {
        return "php";
    } else if (ext == "rb") {
        return "ruby";
    } else if (ext == "swift") {
        return "swift";
    } else if (ext == "kt") {
        return "kotlin";
    } else if (ext == "scala") {
        return "scala";
    } else if (ext == "r") {
        return "r";
    } else if (ext == "m") {
        return "matlab";
    } else if (ext == "sql") {
        return "sql";
    } else if (ext == "sh" || ext == "bash") {
        return "bash";
    } else if (ext == "ps1") {
        return "powershell";
    } else if (ext == "html" || ext == "htm") {
        return "html";
    } else if (ext == "css") {
        return "css";
    } else if (ext == "json") {
        return "json";
    } else if (ext == "xml") {
        return "xml";
    } else if (ext == "yaml" || ext == "yml") {
        return "yaml";
    } else if (ext == "md" || ext == "markdown") {
        return "markdown";
    } else if (ext == "asm" || ext == "s") {
        return "asm";
    }
    
    return "text";
}

std::string CodexLSPBridge::TruncateToContext(const std::string& text, size_t maxChars) {
    if (text.length() <= maxChars) {
        return text;
    }
    
    // Try to truncate at a line boundary
    size_t half = maxChars / 2;
    size_t start = 0;
    size_t end = text.length();
    
    // Find line boundary before half point
    for (size_t i = half; i > 0; --i) {
        if (text[i] == '\n') {
            start = i + 1;
            break;
        }
    }
    
    // Find line boundary after length - half
    for (size_t i = text.length() - half; i < text.length(); ++i) {
        if (text[i] == '\n') {
            end = i;
            break;
        }
    }
    
    if (start >= end) {
        // Fallback: just truncate
        return text.substr(0, maxChars) + "\n... (truncated)";
    }
    
    return text.substr(start, end - start);
}

} // namespace Codex
} // namespace RawrXD
