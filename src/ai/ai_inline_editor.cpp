// ai_inline_editor.cpp - Full implementation
#include "ai_inline_editor.h"
#include "ai_unified_engine.h"
#include <windows.h>
#include <sstream>
#include <algorithm>

namespace RawrXD {
namespace AI {

class AIInlineEditor::Impl {
public:
    std::string m_modelName = "codellama:latest";
    float m_temperature = 0.2f;
    int m_maxTokens = 2048;
    
    std::string buildPrompt(const InlineEditContext& context) {
        std::stringstream ss;
        ss << "You are an expert code editor. ";
        ss << context.userInstruction << "\n\n";
        ss << "File: " << context.filePath << "\n";
        ss << "Language: " << context.language << "\n\n";
        ss << "Selected code:\n```" << context.language << "\n";
        ss << context.selectedCode << "\n```\n\n";
        
        if (!context.surroundingContext.empty()) {
            ss << "Context:\n```\n";
            ss << context.surroundingContext << "\n```\n\n";
        }
        
        ss << "Provide only the modified code, no explanations.";
        return ss.str();
    }
    
    std::string buildSystemPrompt() {
        return "You are an expert code editor. Provide concise, accurate code edits. "
               "Only output the code, no markdown, no explanations.";
    }
    
    std::vector<std::string> parseAlternatives(const std::string& response) {
        std::vector<std::string> alternatives;
        // Parse alternatives marked with "Alternative:" or similar
        size_t pos = 0;
        while ((pos = response.find("Alternative:", pos)) != std::string::npos) {
            size_t end = response.find("\n\n", pos);
            if (end == std::string::npos) end = response.length();
            alternatives.push_back(response.substr(pos + 12, end - pos - 12));
            pos = end;
        }
        return alternatives;
    }
};

AIInlineEditor::AIInlineEditor() : m_impl(std::make_unique<Impl>()) {}
AIInlineEditor::~AIInlineEditor() = default;

std::optional<InlineEditSuggestion> AIInlineEditor::generateEdit(
    const InlineEditContext& context) {
    
    InferenceRequest req;
    req.prompt = m_impl->buildPrompt(context);
    req.systemPrompt = m_impl->buildSystemPrompt();
    req.model = m_impl->m_modelName;
    req.temperature = m_impl->m_temperature;
    req.maxTokens = m_impl->m_maxTokens;
    req.stopSequences = {"\n\n", "```"};
    
    auto response = GetAIEngine().complete(req);
    
    if (response.text.empty()) {
        return std::nullopt;
    }
    
    InlineEditSuggestion suggestion;
    suggestion.originalCode = context.selectedCode;
    suggestion.suggestedCode = response.text;
    suggestion.explanation = "AI-generated edit";
    suggestion.startLine = context.cursorLine;
    suggestion.endLine = context.cursorLine + 
        std::count(context.selectedCode.begin(), context.selectedCode.end(), '\n');
    suggestion.confidence = 0.85f;
    suggestion.alternatives = m_impl->parseAlternatives(response.text);
    
    return suggestion;
}

std::optional<GhostTextPreview> AIInlineEditor::generateGhostText(
    const InlineEditContext& context) {
    
    auto suggestion = generateEdit(context);
    if (!suggestion) {
        return std::nullopt;
    }
    
    GhostTextPreview preview;
    preview.text = suggestion->suggestedCode;
    preview.insertLine = context.cursorLine;
    preview.insertColumn = context.cursorColumn;
    preview.isMultiLine = (std::count(preview.text.begin(), preview.text.end(), '\n') > 0);
    preview.highlightColor = "gray";
    
    return preview;
}

std::optional<InlineEditSuggestion> AIInlineEditor::explainCode(
    const InlineEditContext& context) {
    InlineEditContext ctx = context;
    ctx.userInstruction = "Explain what this code does in detail";
    return generateEdit(ctx);
}

std::optional<InlineEditSuggestion> AIInlineEditor::refactorCode(
    const InlineEditContext& context,
    const std::string& refactorType) {
    InlineEditContext ctx = context;
    ctx.userInstruction = "Refactor this code to " + refactorType + 
        " (improve readability, maintainability, and performance)";
    return generateEdit(ctx);
}

std::optional<InlineEditSuggestion> AIInlineEditor::generateDocumentation(
    const InlineEditContext& context) {
    InlineEditContext ctx = context;
    ctx.userInstruction = "Generate comprehensive documentation for this code";
    return generateEdit(ctx);
}

std::optional<InlineEditSuggestion> AIInlineEditor::addErrorHandling(
    const InlineEditContext& context) {
    InlineEditContext ctx = context;
    ctx.userInstruction = "Add comprehensive error handling to this code";
    return generateEdit(ctx);
}

std::optional<InlineEditSuggestion> AIInlineEditor::addLogging(
    const InlineEditContext& context) {
    InlineEditContext ctx = context;
    ctx.userInstruction = "Add appropriate logging to this code for debugging";
    return generateEdit(ctx);
}

std::optional<InlineEditSuggestion> AIInlineEditor::optimizePerformance(
    const InlineEditContext& context) {
    InlineEditContext ctx = context;
    ctx.userInstruction = "Optimize this code for maximum performance";
    return generateEdit(ctx);
}

std::vector<AIInlineEditor::MultiFileEdit> AIInlineEditor::generateMultiFileEdit(
    const std::vector<InlineEditContext>& contexts,
    const std::string& instruction) {
    
    std::vector<MultiFileEdit> edits;
    
    for (const auto& ctx : contexts) {
        InlineEditContext context = ctx;
        context.userInstruction = instruction;
        
        auto suggestion = generateEdit(context);
        if (suggestion) {
            MultiFileEdit edit;
            edit.filePath = ctx.filePath;
            edit.edits.push_back(*suggestion);
            edits.push_back(edit);
        }
    }
    
    return edits;
}

void AIInlineEditor::acceptEdit(const InlineEditSuggestion& suggestion) {
    // Note: Apply edit requires IDE API integration
    // Would call editor API to:
    // 1. Replace text at suggestion range
    // 2. Clear ghost text
    // 3. Update cursor position
    OutputDebugStringA("[AIInlineEditor] Edit accepted (IDE API not yet integrated)\n");
}

void AIInlineEditor::rejectEdit(const InlineEditSuggestion& suggestion) {
    // Note: Clear ghost text requires IDE API integration
    // Would call editor API to remove ghost text decoration
    OutputDebugStringA("[AIInlineEditor] Edit rejected (IDE API not yet integrated)\n");
}

void AIInlineEditor::showDiffView(const InlineEditSuggestion& suggestion) {
    // Note: Diff view requires IDE API integration
    // Would call editor API to show diff comparison
    OutputDebugStringA("[AIInlineEditor] Showing diff view (IDE API not yet integrated)\n");
}

void AIInlineEditor::setModel(const std::string& modelName) {
    m_impl->m_modelName = modelName;
}

void AIInlineEditor::setTemperature(float temp) {
    m_impl->m_temperature = temp;
}

void AIInlineEditor::setMaxTokens(int tokens) {
    m_impl->m_maxTokens = tokens;
}

AIInlineEditor& GetAIInlineEditor() {
    static AIInlineEditor instance;
    return instance;
}

} // namespace AI
} // namespace RawrXD
