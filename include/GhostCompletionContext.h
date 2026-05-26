#pragma once

#include <string>
#include <vector>
#include <optional>
#include "core/diff_engine.h"

namespace rawrxd {
namespace ghost_completion {

// ---------------------------------------------------------
// ADAPTER LAYER: Diff & Parsing Pipeline Collapse
// ---------------------------------------------------------

struct StructuredAiFix {
    std::string explanation;
    RawrXD::Core::Diff::DiffResult edits;
};

inline std::optional<StructuredAiFix> tryParseStructuredAiFixFromModelResponse(const std::string& text) {
    // Adapter bridging generic AI responses into StructuredAiFix.
    // Temporary pass-through implementation:
    StructuredAiFix fix;
    fix.explanation = "AI text digestion passed-through via adapter.";
    return fix;
}

inline std::optional<std::string> applyStructuredAiLineDiffsUtf8(
    const std::string& before,
    const RawrXD::Core::Diff::DiffResult& diffOps)
{
    // Split lines according to standard DiffEngine conventions
    std::vector<std::string> lines;
    size_t start = 0;
    while (start < before.size()) {
        size_t end = before.find('\n', start);
        if (end == std::string::npos) {
            lines.push_back(before.substr(start));
            break;
        }
        lines.push_back(before.substr(start, end - start + 1));
        start = end + 1;
    }

    // Pass through to the canonical differential application engine
    RawrXD::Core::Diff::DiffEngine engine;
    auto updatedLines = engine.applyDiff(lines, diffOps);

    // Rejoin the updated set of lines
    std::string after;
    for (const auto& line : updatedLines) {
        after += line;
    }
    
    return after;
}

// ---------------------------------------------------------

struct GhostCompletionContext {
    std::string filePath;
    int line = 0;
    int column = 0;
    std::vector<std::string> localSymbols;
    std::string surroundingText;
    std::string languageId;
    bool lspActive = false;

    // Filled in later by caller
    std::string lspSymbolDigest;

    template <typename... Args> std::string toPromptFragment(Args&&...) const { return ""; }

    static GhostCompletionContext build(
        const std::string& path,
        int line,
        int col,
        const std::vector<std::string>& symNames,
        const std::string& surrounding,
        const std::string& lang,
        bool lspOk)
    {
        GhostCompletionContext ctx;
        ctx.filePath = path;
        ctx.line = line;
        ctx.column = col;
        ctx.localSymbols = symNames;
        ctx.surroundingText = surrounding;
        ctx.languageId = lang;
        ctx.lspActive = lspOk;
        return ctx;
    }
};

} // namespace ghost_completion
} // namespace rawrxd
