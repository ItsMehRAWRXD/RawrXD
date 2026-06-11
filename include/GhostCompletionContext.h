// GhostCompletionContext.h — Stub for build compatibility
// Provides minimal GhostCompletionContext for Win32IDE compilation

#pragma once
#include <string>
#include <vector>

namespace rawrxd {
namespace ghost_completion {

struct GhostCompletionContext {
    std::string filePath;
    int line = 0;
    int column = 0;
    std::vector<std::string> symbolNames;
    std::string surroundingLines;
    std::string language;
    bool lspRunning = false;
    std::string lspSymbolDigest;

    static GhostCompletionContext build(const std::string& path, int ln, int col,
                                         const std::vector<std::string>& syms,
                                         const std::string& surrounding,
                                         const std::string& lang, bool lspOk) {
        GhostCompletionContext ctx;
        ctx.filePath = path;
        ctx.line = ln;
        ctx.column = col;
        ctx.symbolNames = syms;
        ctx.surroundingLines = surrounding;
        ctx.language = lang;
        ctx.lspRunning = lspOk;
        return ctx;
    }
};

} // namespace ghost_completion
} // namespace rawrxd
