// ============================================================================
// Win32IDE_CodexCommands.cpp - native shared-command handlers
// ============================================================================
#include "Win32IDE.h"
#include "../core/shared_feature_dispatch.h"
#include <sstream>
#include <cstring>

namespace {
CommandResult makePrompt(const std::string& prompt) {
    // CommandResult is a legacy non-owning result; retain the latest prompt
    // until the dispatcher consumes it, avoiding a pointer to a dead stream.
    thread_local std::string storage;
    storage = prompt;
    return CommandResult::ok(storage.c_str());
}
const char* inputText(const CommandContext& ctx) {
    return ctx.args ? ctx.args : "";
}
CommandResult requireInput(const CommandContext& ctx, const char* verb,
                           const char* instruction) {
    const char* text = inputText(ctx);
    if (!text[0]) return CommandResult::error("No code selected");
    std::ostringstream prompt;
    prompt << verb << "\n" << instruction << "\n```\n" << text << "\n```";
    return makePrompt(prompt.str());
}
}

CommandResult handleCodexComplete(const CommandContext& ctx) {
    if (ctx.hwnd) PostMessage(static_cast<HWND>(ctx.hwnd), WM_APP + 1000, 0, 0);
    return CommandResult::ok("Ghost text completion triggered");
}

CommandResult handleCodexCompleteBlock(const CommandContext& ctx) {
    return requireInput(ctx, "/complete", "Complete this code block:");
}
CommandResult handleCodexCompleteLine(const CommandContext& ctx) {
    const char* text = inputText(ctx);
    if (!text[0]) return CommandResult::error("No code selected");
    std::ostringstream prompt;
    prompt << "/complete\nComplete this line:\n" << text;
    return makePrompt(prompt.str());
}
CommandResult handleCodexExplain(const CommandContext& ctx) {
    return requireInput(ctx, "/explain", "Explain this code:");
}
CommandResult handleCodexFixErrors(const CommandContext& ctx) {
    return requireInput(ctx, "/fix", "Fix any errors in this code:");
}
CommandResult handleCodexGenerateDocs(const CommandContext& ctx) {
    return requireInput(ctx, "/doc", "Generate documentation for this code:");
}
CommandResult handleCodexGenerateTests(const CommandContext& ctx) {
    return requireInput(ctx, "/test", "Generate unit tests for this code:");
}
CommandResult handleCodexOptimize(const CommandContext& ctx) {
    return requireInput(ctx, "/optimize", "Optimize this code for performance:");
}
CommandResult handleCodexRefactor(const CommandContext& ctx) {
    return requireInput(ctx, "/refactor", "Refactor this code:");
}
CommandResult handleCodexStream(const CommandContext& ctx) {
    if (ctx.hwnd) PostMessage(static_cast<HWND>(ctx.hwnd), WM_APP + 1001, 0, 0);
    return CommandResult::ok("Stream completion triggered");
}
