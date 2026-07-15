// ============================================================================
// RawrXD Codex Command Handlers Implementation
// ============================================================================

#include "CodexCommandHandlers.hpp"
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Codex {

CodexCommandRouter::CodexCommandRouter() = default;
CodexCommandRouter::~CodexCommandRouter() = default;

bool CodexCommandRouter::Initialize(std::shared_ptr<CodexCLI> cli) {
    m_cli = cli;
    if (!m_cli || !m_cli->IsInitialized()) {
        return false;
    }
    m_initialized = true;
    return true;
}

void CodexCommandRouter::RegisterWithIDE() {
    // This would register with the IDE's command router
    // For now, this is a placeholder for IDE integration
}

CodexCommandResult CodexCommandRouter::HandleCommand(const std::string& subcommand, const CodexCommandContext& ctx) {
    if (!m_initialized) {
        return CodexCommandResult::error("Codex not initialized");
    }
    
    if (subcommand == "complete" || subcommand == "c") {
        return HandleComplete(ctx);
    } else if (subcommand == "stream" || subcommand == "s") {
        return HandleStream(ctx);
    } else if (subcommand == "explain" || subcommand == "e") {
        return HandleExplain(ctx);
    } else if (subcommand == "refactor" || subcommand == "r") {
        return HandleRefactor(ctx);
    } else if (subcommand == "complete-line" || subcommand == "cl") {
        return HandleCompleteLine(ctx);
    } else if (subcommand == "complete-block" || subcommand == "cb") {
        return HandleCompleteBlock(ctx);
    } else if (subcommand == "generate-tests" || subcommand == "gt") {
        return HandleGenerateTests(ctx);
    } else if (subcommand == "generate-docs" || subcommand == "gd") {
        return HandleGenerateDocs(ctx);
    } else if (subcommand == "fix-errors" || subcommand == "fix") {
        return HandleFixErrors(ctx);
    } else if (subcommand == "optimize" || subcommand == "opt") {
        return HandleOptimize(ctx);
    }
    
    return CodexCommandResult::error("Unknown Codex command: " + subcommand);
}

CodexCommandResult CodexCommandRouter::HandleComplete(const CodexCommandContext& ctx) {
    std::string prompt = ctx.args.empty() ? ctx.selectedText : ctx.args;
    if (prompt.empty()) {
        return CodexCommandResult::error("No prompt provided");
    }
    
    Output(ctx, "Generating completion...\n");
    
    std::string response = m_cli->Complete(prompt);
    if (!response.empty()) {
        Output(ctx, response);
        return CodexCommandResult::ok("Completion generated");
    } else {
        return CodexCommandResult::error(m_cli->GetLastError());
    }
}

CodexCommandResult CodexCommandRouter::HandleStream(const CodexCommandContext& ctx) {
    std::string prompt = ctx.args.empty() ? ctx.selectedText : ctx.args;
    if (prompt.empty()) {
        return CodexCommandResult::error("No prompt provided");
    }
    
    Output(ctx, "Streaming response...\n");
    
    bool success = m_cli->CompleteStreaming(prompt, 
        [&ctx, this](const std::string& chunk, bool isFinal) {
            if (!isFinal && !chunk.empty()) {
                OutputChunk(ctx, chunk);
            }
        });
    
    if (success) {
        return CodexCommandResult::ok("Stream completed");
    } else {
        return CodexCommandResult::error(m_cli->GetLastError());
    }
}

CodexCommandResult CodexCommandRouter::HandleExplain(const CodexCommandContext& ctx) {
    std::string code = ctx.selectedText;
    if (code.empty()) {
        return CodexCommandResult::error("No code selected");
    }
    
    std::string prompt = BuildPrompt(
        "Explain the following code in detail:\n\n```\n{code}\n```\n\n"
        "Please explain:\n1. What this code does\n2. How it works\n3. Any potential issues or improvements",
        ctx);
    
    Output(ctx, "Analyzing code...\n");
    
    std::string response = m_cli->Complete(prompt);
    if (!response.empty()) {
        Output(ctx, response);
        return CodexCommandResult::ok("Explanation generated");
    } else {
        return CodexCommandResult::error(m_cli->GetLastError());
    }
}

CodexCommandResult CodexCommandRouter::HandleRefactor(const CodexCommandContext& ctx) {
    std::string code = ctx.selectedText;
    if (code.empty()) {
        return CodexCommandResult::error("No code selected");
    }
    
    std::string prompt = BuildPrompt(
        "Refactor the following code to improve readability, performance, and maintainability:\n\n"
        "```\n{code}\n```\n\n"
        "Provide the refactored code with explanations of the changes.",
        ctx);
    
    Output(ctx, "Refactoring...\n");
    
    std::string response = m_cli->Complete(prompt);
    if (!response.empty()) {
        Output(ctx, response);
        return CodexCommandResult::ok("Refactoring complete");
    } else {
        return CodexCommandResult::error(m_cli->GetLastError());
    }
}

CodexCommandResult CodexCommandRouter::HandleCompleteLine(const CodexCommandContext& ctx) {
    std::string prompt = BuildPrompt(
        "Complete the current line of code. Context:\n"
        "File: {filepath}\n"
        "Line: {line}\n\n"
        "Current line:\n{code}\n\n"
        "Provide only the completion, no explanations.",
        ctx);
    
    std::string response = m_cli->Complete(prompt);
    if (!response.empty()) {
        Output(ctx, response);
        return CodexCommandResult::ok("Line completion generated");
    } else {
        return CodexCommandResult::error(m_cli->GetLastError());
    }
}

CodexCommandResult CodexCommandRouter::HandleCompleteBlock(const CodexCommandContext& ctx) {
    std::string prompt = BuildPrompt(
        "Complete the current code block. Context:\n"
        "File: {filepath}\n"
        "Line: {line}\n\n"
        "Current code:\n{code}\n\n"
        "Provide the completed block with explanations.",
        ctx);
    
    std::string response = m_cli->Complete(prompt);
    if (!response.empty()) {
        Output(ctx, response);
        return CodexCommandResult::ok("Block completion generated");
    } else {
        return CodexCommandResult::error(m_cli->GetLastError());
    }
}

CodexCommandResult CodexCommandRouter::HandleGenerateTests(const CodexCommandContext& ctx) {
    std::string code = ctx.selectedText;
    if (code.empty()) {
        return CodexCommandResult::error("No code selected");
    }
    
    std::string prompt = BuildPrompt(
        "Generate comprehensive unit tests for the following code:\n\n"
        "```\n{code}\n```\n\n"
        "Include tests for:\n"
        "- Normal cases\n"
        "- Edge cases\n"
        "- Error conditions\n"
        "- Boundary values",
        ctx);
    
    Output(ctx, "Generating tests...\n");
    
    std::string response = m_cli->Complete(prompt);
    if (!response.empty()) {
        Output(ctx, response);
        return CodexCommandResult::ok("Tests generated");
    } else {
        return CodexCommandResult::error(m_cli->GetLastError());
    }
}

CodexCommandResult CodexCommandRouter::HandleGenerateDocs(const CodexCommandContext& ctx) {
    std::string code = ctx.selectedText;
    if (code.empty()) {
        return CodexCommandResult::error("No code selected");
    }
    
    std::string prompt = BuildPrompt(
        "Generate comprehensive documentation for the following code:\n\n"
        "```\n{code}\n```\n\n"
        "Include:\n"
        "- Function/class description\n"
        "- Parameter descriptions\n"
        "- Return value description\n"
        "- Usage examples\n"
        "- Any important notes",
        ctx);
    
    Output(ctx, "Generating documentation...\n");
    
    std::string response = m_cli->Complete(prompt);
    if (!response.empty()) {
        Output(ctx, response);
        return CodexCommandResult::ok("Documentation generated");
    } else {
        return CodexCommandResult::error(m_cli->GetLastError());
    }
}

CodexCommandResult CodexCommandRouter::HandleFixErrors(const CodexCommandContext& ctx) {
    std::string code = ctx.selectedText;
    if (code.empty()) {
        return CodexCommandResult::error("No code selected");
    }
    
    std::string prompt = BuildPrompt(
        "Fix any errors or issues in the following code:\n\n"
        "```\n{code}\n```\n\n"
        "Provide the corrected code with explanations of what was fixed.",
        ctx);
    
    Output(ctx, "Analyzing for errors...\n");
    
    std::string response = m_cli->Complete(prompt);
    if (!response.empty()) {
        Output(ctx, response);
        return CodexCommandResult::ok("Errors fixed");
    } else {
        return CodexCommandResult::error(m_cli->GetLastError());
    }
}

CodexCommandResult CodexCommandRouter::HandleOptimize(const CodexCommandContext& ctx) {
    std::string code = ctx.selectedText;
    if (code.empty()) {
        return CodexCommandResult::error("No code selected");
    }
    
    std::string prompt = BuildPrompt(
        "Optimize the following code for better performance:\n\n"
        "```\n{code}\n```\n\n"
        "Provide the optimized code with explanations of the performance improvements.",
        ctx);
    
    Output(ctx, "Optimizing...\n");
    
    std::string response = m_cli->Complete(prompt);
    if (!response.empty()) {
        Output(ctx, response);
        return CodexCommandResult::ok("Optimization complete");
    } else {
        return CodexCommandResult::error(m_cli->GetLastError());
    }
}

std::string CodexCommandRouter::BuildPrompt(const std::string& template_, const CodexCommandContext& ctx) {
    std::string result = template_;
    
    // Replace placeholders
    size_t pos = 0;
    while ((pos = result.find("{code}", pos)) != std::string::npos) {
        result.replace(pos, 6, ctx.selectedText);
        pos += ctx.selectedText.length();
    }
    
    pos = 0;
    while ((pos = result.find("{filepath}", pos)) != std::string::npos) {
        result.replace(pos, 10, ctx.filePath);
        pos += ctx.filePath.length();
    }
    
    pos = 0;
    while ((pos = result.find("{line}", pos)) != std::string::npos) {
        result.replace(pos, 6, std::to_string(ctx.lineNumber));
        pos += std::to_string(ctx.lineNumber).length();
    }
    
    return result;
}

void CodexCommandRouter::Output(const CodexCommandContext& ctx, const std::string& text) {
    if (ctx.outputFn) {
        ctx.outputFn(text);
    }
}

void CodexCommandRouter::OutputChunk(const CodexCommandContext& ctx, const std::string& chunk) {
    if (ctx.outputFn) {
        ctx.outputFn(chunk);
    }
}

void CodexCommandRouter::Error(const CodexCommandContext& ctx, const std::string& text) {
    if (ctx.errorFn) {
        ctx.errorFn(text);
    }
}

} // namespace Codex
} // namespace RawrXD
