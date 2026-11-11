// ============================================================================
// Win32IDE_CodexCommands.cpp - Codex Command Handler Implementations
// ============================================================================
// Implements all Codex menu command handlers that were previously unresolved
//
// Commands implemented:
//   - handleCodexComplete: Ghost text completion at cursor
//   - handleCodexCompleteBlock: Complete entire code block
//   - handleCodexCompleteLine: Complete current line
//   - handleCodexExplain: Explain selected code
//   - handleCodexFixErrors: Fix errors in selected code
//   - handleCodexGenerateDocs: Generate documentation
//   - handleCodexGenerateTests: Generate unit tests
//   - handleCodexOptimize: Optimize selected code
//   - handleCodexRefactor: Refactor selected code
//   - handleCodexStream: Stream completion to chat
// ============================================================================

#include "Win32IDE.h"
#include "IDELogger.h"
#include "../core/shared_feature_dispatch.h"
#include <sstream>
#include <cstring>

// ============================================================================
// CODEX COMMAND IMPLEMENTATIONS
// ============================================================================

CommandResult handleCodexComplete(const CommandContext& ctx) {
    // Trigger ghost text completion via IDE
    if (ctx.hwnd) {
        HWND hwndMain = static_cast<HWND>(ctx.hwnd);
        PostMessage(hwndMain, WM_APP + 1000, 0, 0);
    }
    return CommandResult::ok("Ghost text completion triggered");
}

CommandResult handleCodexCompleteBlock(const CommandContext& ctx) {
    std::ostringstream prompt;
    prompt << "/complete\n";
    prompt << "Complete this code block:\n";
    prompt << "```\n";
    if (ctx.selectedText) {
        prompt << ctx.selectedText;
    }
    prompt << "\n```";
    
    return CommandResult::ok(prompt.str().c_str());
}

CommandResult handleCodexCompleteLine(const CommandContext& ctx) {
    std::ostringstream prompt;
    prompt << "/complete\n";
    prompt << "Complete this line:\n";
    if (ctx.selectedText) {
        prompt << ctx.selectedText;
    }
    
    return CommandResult::ok(prompt.str().c_str());
}

CommandResult handleCodexExplain(const CommandContext& ctx) {
    if (!ctx.selectedText || strlen(ctx.selectedText) == 0) {
        return CommandResult::error("No code selected");
    }
    
    std::ostringstream prompt;
    prompt << "/explain\n";
    prompt << "Explain this code:\n";
    prompt << "```\n";
    prompt << ctx.selectedText;
    prompt << "\n```";
    
    return CommandResult::ok(prompt.str().c_str());
}

CommandResult handleCodexFixErrors(const CommandContext& ctx) {
    if (!ctx.selectedText || strlen(ctx.selectedText) == 0) {
        return CommandResult::error("No code selected");
    }
    
    std::ostringstream prompt;
    prompt << "/fix\n";
    prompt << "Fix any errors in this code:\n";
    prompt << "```\n";
    prompt << ctx.selectedText;
    prompt << "\n```";
    
    return CommandResult::ok(prompt.str().c_str());
}

CommandResult handleCodexGenerateDocs(const CommandContext& ctx) {
    if (!ctx.selectedText || strlen(ctx.selectedText) == 0) {
        return CommandResult::error("No code selected");
    }
    
    std::ostringstream prompt;
    prompt << "/doc\n";
    prompt << "Generate documentation for this code:\n";
    prompt << "```\n";
    prompt << ctx.selectedText;
    prompt << "\n```";
    
    return CommandResult::ok(prompt.str().c_str());
}

CommandResult handleCodexGenerateTests(const CommandContext& ctx) {
    if (!ctx.selectedText || strlen(ctx.selectedText) == 0) {
        return CommandResult::error("No code selected");
    }
    
    std::ostringstream prompt;
    prompt << "/test\n";
    prompt << "Generate unit tests for this code:\n";
    prompt << "```\n";
    prompt << ctx.selectedText;
    prompt << "\n```";
    
    return CommandResult::ok(prompt.str().c_str());
}

CommandResult handleCodexOptimize(const CommandContext& ctx) {
    if (!ctx.selectedText || strlen(ctx.selectedText) == 0) {
        return CommandResult::error("No code selected");
    }
    
    std::ostringstream prompt;
    prompt << "/optimize\n";
    prompt << "Optimize this code for performance:\n";
    prompt << "```\n";
    prompt << ctx.selectedText;
    prompt << "\n```";
    
    return CommandResult::ok(prompt.str().c_str());
}

CommandResult handleCodexRefactor(const CommandContext& ctx) {
    if (!ctx.selectedText || strlen(ctx.selectedText) == 0) {
        return CommandResult::error("No code selected");
    }
    
    std::ostringstream prompt;
    prompt << "/refactor\n";
    prompt << "Refactor this code:\n";
    prompt << "```\n";
    prompt << ctx.selectedText;
    prompt << "\n```";
    
    return CommandResult::ok(prompt.str().c_str());
}

CommandResult handleCodexStream(const CommandContext& ctx) {
    // Stream to chat panel
    if (ctx.hwnd) {
        HWND hwndMain = static_cast<HWND>(ctx.hwnd);
        PostMessage(hwndMain, WM_APP + 1001, 0, 0);
    }
    
    return CommandResult::ok("Stream completion triggered");
}

// ============================================================================
// Win32IDE CodexCLI accessor implementation
// ============================================================================

std::shared_ptr<RawrXD::Codex::CodexCLI> Win32IDE::GetCodexCLI() {
    if (!m_codexCLI) {
        m_codexCLI = std::make_shared<RawrXD::Codex::CodexCLI>();
        RawrXD::Codex::CodexCLI::Config config;
        config.AutoDetect();
        m_codexCLI->Initialize(config);
    }
    return m_codexCLI;
}

// ============================================================================
// Semantic Index stub implementation
// ============================================================================

void Win32IDE::showSemanticIndex() {
    // Stub implementation - semantic index functionality is in Win32IDE_CursorParity.cpp
    // This stub satisfies the linker requirement from Win32IDE_Commands.cpp
    OutputDebugStringA("showSemanticIndex() called\n");
}
