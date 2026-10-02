// ============================================================================
// RefactorChainIdeSurface.cpp — RAWRXD_P1_REFACTOR_CHAIN_001
//
// THE PRODUCT BINDING for the refactoring chain.
//
// Why this file exists, in the measured order of the evidence:
//
//   1. The shipping command surface is the SSOT X-macro table COMMAND_TABLE in
//      src/core/command_registry.hpp. src/core/unified_command_dispatch.cpp
//      iterates g_commandRegistry[] and registers every entry into
//      SharedFeatureRegistry, and both files are in the RawrXD-Win32IDE link.
//
//   2. The function pointer the table names for `lsp.gotoDef`, `lsp.findRefs`,
//      `lsp.rename`, `lsp.diagnostics` and `lsp.symbolInfo` resolved, in that
//      link, to src/core/win32ide_handler_impls.cpp -- where all 376 handler
//      definitions are the single line
//
//          CommandResult handleX(const CommandContext& ctx)
//              { (void)ctx; return CommandResult::ok(); }
//
//      So the IDE answered "success" to goto-definition, find-references,
//      rename, diagnostics and symbol-info without doing any of them. That is
//      worse than an absent feature, because the return code is the authority
//      every caller and receipt trusts.
//
//   3. A second registry exists -- 432 features registered by
//      src/core/auto_feature_registry.cpp through initAutoFeatureRegistry() --
//      but that function has no caller anywhere in the repository, so a repair
//      made there is never dispatched. Repairing a handler that nothing calls
//      changes no behaviour the product can exhibit.
//
// This file closes both gaps at once: it provides the nine chain handlers with
// real bodies that report measured results, and it is the translation unit the
// table's pointers are verified against.
//
// INVARIANTS ENFORCED HERE, not merely documented:
//
//   RENAME_SUCCESS_REQUIRES_EDIT_COUNT_GT_0
//   GOTO_DEFINITION_SUCCESS_REQUIRES_RESOLVED_LOCATION
//   NO_MUTATION_WITHOUT_A_REPORTED_EFFECT
//
// A handler returns CommandResult::ok() only after the operation reports what
// it actually did. Every failure path prints the reason it did not act.
// ============================================================================

#include "shared_feature_dispatch.h"
#include "refactor/RefactorChain.h"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <string>

using rawrxd::refactor::CodeAction;
using rawrxd::refactor::Diagnostic;
using rawrxd::refactor::ExtractResult;
using rawrxd::refactor::FormatResult;
using rawrxd::refactor::RefactorChain;
using rawrxd::refactor::RenameResult;

namespace {

// The workspace the chain operates on. RAWRXD_REFACTOR_ROOT wins so a caller can
// point the IDE at a specific tree; otherwise the process working directory is
// used, which is what the CLI surface already treats as the workspace.
std::string ResolveWorkspaceRoot() {
    // Read the Win32 environment directly. The CRT's getenv_s is deliberately not
    // used here, because the failure mode of a mismatch between two views of the
    // environment is the worst one available to this authority: the lookup
    // returns nothing, the handler falls back to the process working directory,
    // and the chain begins indexing the entire repository -- tens of thousands of
    // files -- which presents as a command that hangs with no output rather than
    // as an error anyone can read.
    char env[1024] = {0};
    const DWORD n = GetEnvironmentVariableA("RAWRXD_REFACTOR_ROOT", env,
                                            static_cast<DWORD>(sizeof(env)));
    if (n > 0 && n < sizeof(env)) return std::string(env, n);
    char buf[1024];
    const DWORD cwd = GetCurrentDirectoryA(sizeof(buf), buf);
    if (cwd > 0 && cwd < sizeof(buf)) return std::string(buf, cwd);
    return std::string();
}

// Opens the workspace once. A failure is sticky and is reported by every caller
// as an error with the reason; it is never silently treated as "no results".
bool EnsureWorkspace(const CommandContext& ctx) {
    static bool attempted = false;
    static bool ok = false;
    static std::string reason;
    RefactorChain& chain = RefactorChain::instance();
    const bool trace = std::getenv("RAWRXD_REFACTOR_TRACE") != nullptr;
    if (trace) fprintf(stderr, "[trace] ensure entered attempted=%d\n", attempted ? 1 : 0);
    if (attempted && chain.isOpen()) return true;
    if (attempted && ok) return true;
    if (attempted && !ok) {
        ctx.output(("[refactor] workspace unavailable: " + reason + "\n").c_str());
        return false;
    }
    attempted = true;
    std::string err;
    const std::string root = ResolveWorkspaceRoot();
    if (trace) fprintf(stderr, "[trace] ensure opening [%s]\n", root.c_str());
    ok = chain.open(root, &err);
    if (trace) {
        char tb[128];
        snprintf(tb, sizeof(tb), "[trace] ensure: open returned %d err=%s\n",
                 ok ? 1 : 0, err.c_str());
        fprintf(stderr, "%s", tb);
    }
    if (!ok) {
        reason = err.empty() ? ("could not index workspace root '" + root + "'") : err;
        ctx.output(("[refactor] workspace unavailable: " + reason + "\n").c_str());
        return false;
    }
    const auto& ws = chain.workspace();
    char buf[512];
    snprintf(buf, sizeof(buf),
             "[refactor] workspace open: root=%s files=%u symbols=%u occurrences=%u roots=%u\n",
             ws.root.c_str(), ws.filesIndexed, ws.symbolsIndexed,
             ws.occurrencesIndexed, static_cast<unsigned>(ws.roots.size()));
    ctx.output(buf);
    return true;
}

std::vector<std::string> SplitArgs(const char* args) {
    std::vector<std::string> out;
    if (!args) return out;
    std::string s(args);
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r')) ++i;
        const size_t start = i;
        while (i < s.size() && !(s[i] == ' ' || s[i] == '\t' || s[i] == '\r')) ++i;
        if (i > start) out.push_back(s.substr(start, i - start));
    }
    return out;
}

std::string FirstToken(const char* args) {
    const auto v = SplitArgs(args);
    return v.empty() ? std::string() : v[0];
}

std::string SecondToken(const char* args) {
    const auto v = SplitArgs(args);
    return v.size() < 2 ? std::string() : v[1];
}

bool ParseUint(const std::string& s, uint32_t* out) {
    if (s.empty()) return false;
    unsigned long v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<unsigned long>(c - '0');
    }
    *out = static_cast<uint32_t>(v);
    return true;
}

}  // namespace

// ===========================================================================
// 1. definition
// ===========================================================================

CommandResult handleLspGotoDef(const CommandContext& ctx) {
    if (!EnsureWorkspace(ctx)) return CommandResult::error("workspace unavailable", -1);
    const std::string name = FirstToken(ctx.args);
    if (name.empty()) {
        ctx.output("Usage: !lsp goto <symbol>\n");
        return CommandResult::error("missing symbol", -1);
    }
    const auto r = RefactorChain::instance().definition(name);
    if (!r.resolved) {
        // GOTO_DEFINITION_SUCCESS_REQUIRES_RESOLVED_LOCATION: a lookup that did
        // not resolve is a failure. The previous body printed "not found" and
        // then returned ok, so every caller recorded a success for a miss.
        char buf[512];
        snprintf(buf, sizeof(buf),
                 "[lsp] definition: NOT RESOLVED for '%s' (%u candidates, %s)\n",
                 name.c_str(), r.candidates, r.reason.c_str());
        ctx.output(buf);
        return CommandResult::error("definition not resolved", -1);
    }
    char buf[640];
    snprintf(buf, sizeof(buf),
             "[lsp] definition: %s -> %s:%u:%u (qualified=%s, candidates=%u, symbolsIndexed=%u)\n",
             name.c_str(), r.location.file.c_str(), r.location.line, r.location.col,
             r.qualifiedName.c_str(), r.candidates, r.symbolsIndexed);
    ctx.output(buf);
    return CommandResult::ok("lsp.gotoDef");
}

// ===========================================================================
// 2. references
// ===========================================================================

CommandResult handleLspFindRefs(const CommandContext& ctx) {
    if (!EnsureWorkspace(ctx)) return CommandResult::error("workspace unavailable", -1);
    const std::string name = FirstToken(ctx.args);
    if (name.empty()) {
        ctx.output("Usage: !lsp refs <symbol>\n");
        return CommandResult::error("missing symbol", -1);
    }
    const auto r = RefactorChain::instance().references(name);
    if (r.sites.empty()) {
        char buf[512];
        snprintf(buf, sizeof(buf), "[lsp] references: none for '%s' (%s)\n",
                 name.c_str(), r.reason.c_str());
        ctx.output(buf);
        return CommandResult::error("no references", -1);
    }
    char buf[512];
    snprintf(buf, sizeof(buf),
             "[lsp] references: %s total=%zu definitions=%u declarations=%u uses=%u calls=%u "
             "commentOccurrencesSkipped=%u stringOccurrencesSkipped=%u\n",
             name.c_str(), r.sites.size(), r.definitionCount, r.declarationCount,
             r.useCount, r.callCount, r.commentOccurrencesSkipped,
             r.stringOccurrencesSkipped);
    ctx.output(buf);
    for (const auto& L : r.sites) {
        char line[512];
        snprintf(line, sizeof(line), "  %s:%u:%u\n", L.file.c_str(), L.line, L.col);
        ctx.output(line);
    }
    return CommandResult::ok("lsp.findRefs");
}

// ===========================================================================
// 3. rename
// ===========================================================================

CommandResult handleLspRename(const CommandContext& ctx) {
    if (!EnsureWorkspace(ctx)) return CommandResult::error("workspace unavailable", -1);
    const std::string oldName = FirstToken(ctx.args);
    const std::string newName = SecondToken(ctx.args);
    if (oldName.empty() || newName.empty()) {
        ctx.output("Usage: !lsp rename <old_name> <new_name>\n");
        return CommandResult::error("need two names", -1);
    }
    const RenameResult r = RefactorChain::instance().renameSymbol(oldName, newName, false);

    // RENAME_SUCCESS_REQUIRES_EDIT_COUNT_GT_0. The previous body rebuilt the
    // index and printed "Renamed" without opening a file.
    if (!r.applied || r.editCount == 0) {
        char buf[768];
        snprintf(buf, sizeof(buf),
                 "[lsp] rename FAILED: %s (edits=%u files=%u commentsSkipped=%u "
                 "stringsSkipped=%u nearMissTokensSkipped=%u)\n",
                 r.reason.c_str(), r.editCount, r.filesTouched, r.commentsSkipped,
                 r.stringsSkipped, r.nearMissTokensSkipped);
        ctx.output(buf);
        return CommandResult::error("rename applied no edits", -1);
    }
    char buf[768];
    snprintf(buf, sizeof(buf),
             "[lsp] rename OK: %s -> %s edits=%u files=%u commentsSkipped=%u "
             "stringsSkipped=%u nearMissTokensSkipped=%u\n",
             r.oldName.c_str(), r.newName.c_str(), r.editCount, r.filesTouched,
             r.commentsSkipped, r.stringsSkipped, r.nearMissTokensSkipped);
    ctx.output(buf);
    for (const auto& L : r.edited) {
        char line[512];
        snprintf(line, sizeof(line), "  edited %s:%u:%u\n", L.file.c_str(), L.line, L.col);
        ctx.output(line);
    }
    return CommandResult::ok("lsp.rename");
}

// ===========================================================================
// 4. symbol search
// ===========================================================================

CommandResult handleLspSymbolInfo(const CommandContext& ctx) {
    if (!EnsureWorkspace(ctx)) return CommandResult::error("workspace unavailable", -1);
    const std::string query = FirstToken(ctx.args);
    if (query.empty()) {
        ctx.output("Usage: !lsp symbol <query>\n");
        return CommandResult::error("missing query", -1);
    }
    const auto r = RefactorChain::instance().symbolSearch(query, 16);
    if (r.ranked.empty()) {
        char buf[512];
        snprintf(buf, sizeof(buf), "[lsp] symbol search: no match for '%s'\n", query.c_str());
        ctx.output(buf);
        return CommandResult::error("no symbol matched", -1);
    }
    char buf[512];
    snprintf(buf, sizeof(buf), "[lsp] symbol search: '%s' considered=%u ranked=%zu\n",
             query.c_str(), r.considered, r.ranked.size());
    ctx.output(buf);
    for (const auto& L : r.ranked) {
        char line[512];
        snprintf(line, sizeof(line), "  %s:%u:%u  %s\n",
                 L.file.c_str(), L.line, L.col, L.symbol.c_str());
        ctx.output(line);
    }
    return CommandResult::ok("lsp.symbolInfo");
}

// ===========================================================================
// 5. workspace symbols  (new command; the capability had no table entry at all)
// ===========================================================================

CommandResult handleLspWorkspaceSymbols(const CommandContext& ctx) {
    if (!EnsureWorkspace(ctx)) return CommandResult::error("workspace unavailable", -1);
    const std::string query = FirstToken(ctx.args);
    if (query.empty()) {
        ctx.output("Usage: !lsp wssymbols <query>\n");
        return CommandResult::error("missing query", -1);
    }
    const auto& chain = RefactorChain::instance();
    const auto r = chain.workspaceSymbols(query, 32);
    if (r.ranked.empty()) {
        char buf[512];
        snprintf(buf, sizeof(buf), "[lsp] workspace symbols: no match for '%s'\n", query.c_str());
        ctx.output(buf);
        return CommandResult::error("no symbol matched", -1);
    }
    const auto roots = chain.knownRoots();
    std::vector<std::string> rootsHit;
    for (const auto& root : roots) {
        for (const auto& L : r.ranked) {
            const std::string prefix = root + "/";
            if (L.file.compare(0, prefix.size(), prefix) == 0) {
                bool already = false;
                for (const auto& x : rootsHit) if (x == root) { already = true; break; }
                if (!already) rootsHit.push_back(root);
                break;
            }
        }
    }
    std::string rootText;
    for (size_t i = 0; i < rootsHit.size(); ++i) {
        if (i) rootText += "|";
        rootText += rootsHit[i];
    }
    char buf[640];
    snprintf(buf, sizeof(buf),
             "[lsp] workspace symbols: '%s' roots=%u matchedRoots=[%s] ranked=%zu\n",
             query.c_str(), static_cast<unsigned>(roots.size()),
             rootText.c_str(), r.ranked.size());
    ctx.output(buf);
    for (const auto& L : r.ranked) {
        char line[512];
        snprintf(line, sizeof(line), "  %s:%u:%u  %s\n",
                 L.file.c_str(), L.line, L.col, L.symbol.c_str());
        ctx.output(line);
    }
    return CommandResult::ok("lsp.workspaceSymbols");
}

// ===========================================================================
// 6. diagnostics  (whole workspace, or one file when the argument names one)
// ===========================================================================

CommandResult handleLspDiagnostics(const CommandContext& ctx) {
    if (!EnsureWorkspace(ctx)) return CommandResult::error("workspace unavailable", -1);
    RefactorChain& chain = RefactorChain::instance();
    const std::string arg = FirstToken(ctx.args);
    std::vector<Diagnostic> all;
    if (arg.empty()) {
        for (const auto& root : chain.knownRoots()) (void)root;
        char buf[512];
        snprintf(buf, sizeof(buf), "[lsp] diagnostics: scanning the whole workspace\n");
        ctx.output(buf);
        // The authority reports per file; walk the indexed roots.
        const auto files = chain.indexedFiles();
        for (const auto& f : files) {
            const auto d = chain.diagnostics(f);
            all.insert(all.end(), d.begin(), d.end());
        }
    } else {
        const auto d = chain.diagnostics(arg);
        if (d.empty() && chain.indexedFiles().empty()) {
            ctx.output(("[lsp] diagnostics: '" + arg + "' is not an indexed file\n").c_str());
            return CommandResult::error("not an indexed file", -1);
        }
        all = d;
    }
    char buf[512];
    snprintf(buf, sizeof(buf), "[lsp] diagnostics: %u reported\n",
             static_cast<unsigned>(all.size()));
    ctx.output(buf);
    for (const auto& d : all) {
        char line[768];
        snprintf(line, sizeof(line), "  %s:%u:%u  %s  %s\n",
                 d.file.c_str(), d.line, d.col, d.code.c_str(), d.message.c_str());
        ctx.output(line);
    }
    return CommandResult::ok("lsp.diagnostics");
}

// ===========================================================================
// 7. code actions
// ===========================================================================

CommandResult handleLspCodeAction(const CommandContext& ctx) {
    if (!EnsureWorkspace(ctx)) return CommandResult::error("workspace unavailable", -1);
    RefactorChain& chain = RefactorChain::instance();
    const auto argv = SplitArgs(ctx.args);
    if (argv.empty()) {
        ctx.output("Usage: !lsp codeaction <rel_file> [apply <index>]\n");
        return CommandResult::error("missing file", -1);
    }
    const std::string file = argv[0];
    const std::string verb = argv.size() > 1 ? argv[1] : std::string("list");
    std::string idxText = argv.size() > 2 ? argv[2] : std::string();

    const auto actions = chain.codeActions(file);
    if (verb == "list") {
        char buf[512];
        snprintf(buf, sizeof(buf), "[lsp] code actions for %s: %u\n",
                 file.c_str(), static_cast<unsigned>(actions.size()));
        ctx.output(buf);
        for (size_t i = 0; i < actions.size(); ++i) {
            char line[768];
            snprintf(line, sizeof(line), "  [%u] %s\n", static_cast<unsigned>(i),
                     actions[i].title.c_str());
            ctx.output(line);
        }
        return CommandResult::ok("lsp.codeAction");
    }
    if (verb != "apply") {
        ctx.output("Usage: !lsp codeaction <rel_file> [apply <index>]\n");
        return CommandResult::error("unknown verb", -1);
    }
    uint32_t idx = 0;
    if (!ParseUint(idxText, &idx)) {
        ctx.output("Usage: !lsp codeaction <rel_file> apply <index>\n");
        return CommandResult::error("missing action index", -1);
    }
    const std::vector<Diagnostic> before = chain.diagnostics(file);
    std::string err;
    if (!chain.applyCodeAction(file, idx, &err)) {
        ctx.output(("[lsp] code action FAILED: " + err + "\n").c_str());
        return CommandResult::error("code action failed", -1);
    }
    const auto after = chain.diagnostics(file);
    char buf[512];
    snprintf(buf, sizeof(buf),
             "[lsp] code action applied: %s index=%u diagnosticsBefore=%u diagnosticsAfter=%u\n",
             file.c_str(), idx, static_cast<unsigned>(before.size()),
             static_cast<unsigned>(after.size()));
    ctx.output(buf);
    return CommandResult::ok("lsp.codeAction");
}

// ===========================================================================
// 8. format
// ===========================================================================

CommandResult handleEditorFormatDocument(const CommandContext& ctx) {
    if (!EnsureWorkspace(ctx)) return CommandResult::error("workspace unavailable", -1);
    RefactorChain& chain = RefactorChain::instance();
    const std::string arg = FirstToken(ctx.args);
    if (arg.empty()) {
        uint32_t filesChanged = 0;
        const FormatResult r = chain.formatAll(&filesChanged);
        if (!r.ok) {
            ctx.output(("[editor] format FAILED: " + r.reason + "\n").c_str());
            return CommandResult::error("format failed", -1);
        }
        char buf[512];
        snprintf(buf, sizeof(buf),
                 "[editor] format: whole workspace, filesChanged=%u linesChanged=%u\n",
                 filesChanged, r.linesChanged);
        ctx.output(buf);
        return CommandResult::ok("editor.formatDocument");
    }
    const FormatResult r = chain.formatFile(arg, false);
    if (!r.ok) {
        ctx.output(("[editor] format FAILED: " + r.reason + "\n").c_str());
        return CommandResult::error("format failed", -1);
    }
    char buf[768];
    std::string rules;
    for (size_t i = 0; i < r.rulesApplied.size(); ++i) {
        if (i) rules += ",";
        rules += r.rulesApplied[i];
    }
    snprintf(buf, sizeof(buf),
             "[editor] format: %s changed=%u linesChanged=%u bytesBefore=%u bytesAfter=%u "
             "rules=[%s]\n",
             r.file.c_str(), r.changed ? 1u : 0u, r.linesChanged, r.bytesBefore,
             r.bytesAfter, rules.c_str());
    ctx.output(buf);
    // A format that changed nothing is not an error, but it is reported as such
    // so the caller can distinguish "already formatted" from "did not run".
    return CommandResult::ok("editor.formatDocument");
}

// ===========================================================================
// 9. extract function
// ===========================================================================

CommandResult handleEditorExtractFunction(const CommandContext& ctx) {
    if (!EnsureWorkspace(ctx)) return CommandResult::error("workspace unavailable", -1);
    RefactorChain& chain = RefactorChain::instance();
    const auto argv = SplitArgs(ctx.args);
    if (argv.size() < 4) {
        ctx.output("Usage: !editor extract <rel_file> <first_line> <last_line> <new_name>\n");
        return CommandResult::error("missing arguments", -1);
    }
    const std::string file = argv[0];
    uint32_t first = 0, last = 0;
    if (!ParseUint(argv[1], &first) || !ParseUint(argv[2], &last)) {
        ctx.output("Usage: !editor extract <rel_file> <first_line> <last_line> <new_name>\n");
        return CommandResult::error("line numbers must be integers", -1);
    }
    const std::string name = argv[3];
    const ExtractResult r = chain.extractFunction(file, first, last, name);
    if (!r.applied) {
        char buf[768];
        snprintf(buf, sizeof(buf), "[editor] extract FAILED: %s\n", r.reason.c_str());
        ctx.output(buf);
        return CommandResult::error("extract function failed", -1);
    }
    char buf[768];
    snprintf(buf, sizeof(buf),
             "[editor] extract OK: %s %u..%u -> %s in %s\n"
             "    enclosing=%s params=%u functionLine=%u callsiteLine=%u edits=%u\n"
             "    parameterTypes=",
             r.file.c_str(), r.blockFirstLine, r.blockLastLine, r.newSymbol.c_str(),
             r.file.c_str(), r.enclosingSymbol.c_str(), r.paramCount,
             r.functionLine, r.callsiteLine, r.editCount);
    ctx.output(buf);
    std::string types;
    for (size_t i = 0; i < r.parameterTypes.size(); ++i) {
        if (i) types += ", ";
        types += r.parameterTypes[i];
    }
    ctx.output((types + "\n").c_str());
    return CommandResult::ok("editor.extractFunction");
}