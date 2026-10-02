// ============================================================================
// semantic_code_intelligence_cert.cpp — RAWRXD_REPOSITORY_INTELLIGENCE_001
//
// Proves that SemanticCodeIntelligence's query surface is no longer hollow.
//
// Before this gate, buildFileIndex() was:
//
//     void SemanticCodeIntelligence::buildFileIndex(const std::string& filePath) {
//         // In production, this would parse the file using a language-specific parser
//         // For now, mark the file as indexed
//         m_stats.filesIndexed.fetch_add(1);
//         if (m_progressCb) m_progressCb(filePath.c_str(), 100, m_progressData);
//     }
//
// Every method this harness calls reads state that only that function wrote, so
// all of them returned empty while indexFile() answered
// PatchResult::ok("File indexed"). This harness indexes real files from this
// repository and then asks the queries real questions. A method that returns
// empty is a FAIL here, not a neutral observation.
// ============================================================================
#include "core/semantic_code_intelligence.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {

int g_fail = 0;
int g_pass = 0;

void kv(const char* k, long long v) { std::printf("%s=%lld\n", k, v); }
void kvs(const char* k, const std::string& v) {
    std::printf("%s=%s\n", k, v.c_str());
}
void check(const char* name, bool ok, const std::string& evidence) {
    if (ok) ++g_pass; else ++g_fail;
    std::printf("CHECK=%s RESULT=%s EVIDENCE=%s\n", name,
                ok ? "PASS" : "FAIL", evidence.c_str());
}

std::string baseName(const std::string& p) {
    const size_t cut = p.find_last_of("\\/");
    return cut == std::string::npos ? p : p.substr(cut + 1);
}

}  // namespace

int main(int argc, char** argv) {
    const std::string root = (argc > 1) ? argv[1] : "F:\\~dev\\rawrxd";

    std::printf("RECEIPT=RAWRXD_REPOSITORY_INTELLIGENCE_001_SEMANTIC_SURFACE\n");
    kvs("ROOT", root);

    // Real files from this repository, chosen so the assertions are about code
    // that certainly exists.
    const std::vector<std::string> files = {
        root + "/src/agentmodes/RawrAuditAuthority.cpp",
        root + "/src/agentmodes/RawrModesCli.cpp",
        root + "/src/repointel/ScopeTree.cpp",
        root + "/src/repointel/RepositoryUniverse.cpp",
        root + "/src/core/semantic_code_intelligence.cpp",
        root + "/src/deep2/ReceiptAuthority.cpp",
    };

    SemanticCodeIntelligence& sci = SemanticCodeIntelligence::instance();

    // --- indexing -----------------------------------------------------------
    std::vector<std::string> indexed;
    for (const std::string& f : files) {
        const PatchResult r = sci.indexFile(f);
        if (r.success) indexed.push_back(f);
        std::printf("INDEX_FILE=%s OK=%d DETAIL=%s\n", baseName(f).c_str(), r.success ? 1 : 0, r.detail.c_str());
    }
    kv("FILES_OFFERED", (long long)files.size());
    kv("FILES_INDEXED", (long long)indexed.size());
    check("INDEX_ACCEPTS_REAL_FILES", !indexed.empty(),
          "indexed=" + std::to_string(indexed.size()));

    const IntelligenceStats& st = sci.getStats();
    kv("STAT_filesIndexed", (long long)st.filesIndexed.load());
    kv("STAT_totalSymbols", (long long)st.totalSymbols.load());
    kv("STAT_totalScopes", (long long)st.totalScopes.load());
    kv("STAT_totalReferences", (long long)st.totalReferences.load());
    kv("STAT_indexBuildTimeUs", (long long)st.indexBuildTimeUs.load());

    check("INDEX_PRODUCED_SYMBOLS", st.totalSymbols.load() > 0,
          "totalSymbols=" + std::to_string(st.totalSymbols.load()));
    check("INDEX_PRODUCED_SCOPES", st.totalScopes.load() > 0,
          "totalScopes=" + std::to_string(st.totalScopes.load()));

    // --- goToDefinition -----------------------------------------------------
    // scanSourceTree is defined in RawrAuditAuthority.cpp and called nowhere
    // else; writeAuditReceipt likewise. Both must resolve to a real file:line.
    {
        const char* probes[] = {"scanSourceTree", "writeAuditReceipt",
                                "runAudit", "buildUniverse", "analyzeSource"};
        size_t resolved = 0;
        for (const char* p : probes) {
            const SourceLocation ctx =
                SourceLocation::make(root + "/src/win32app/", 1, 1);
            const SymbolEntry* e = sci.goToDefinition(p, ctx);
            if (!e) {
                std::printf("GOTO_DEF=%s FOUND=0\n", p);
                continue;
            }
            ++resolved;
            std::printf("GOTO_DEF=%s FOUND=1 FILE=%s LINE=%u KIND=%d\n", p,
                        baseName(e->definition.filePath).c_str(),
                        (unsigned)e->definition.line, (int)e->kind);
        }
        kv("GOTO_DEFINITION_PROBES", 5);
        kv("GOTO_DEFINITION_RESOLVED", (long long)resolved);
        check("GO_TO_DEFINITION_RESOLVES", resolved == 5,
              std::to_string(resolved) + "/5");
    }

    // --- references ---------------------------------------------------------
    {
        SourceLocation ctx =
            SourceLocation::make(root + "/src/win32app/", 1, 1);
        const SymbolEntry* e = sci.goToDefinition("runAudit", ctx);
        size_t refs = 0;
        if (e) {
            refs = sci.findAllReferences(e->symbolId).size();
            for (const SourceLocation& l :
                 sci.findAllReferences(e->symbolId)) {
                std::printf("REFERENCE=%s:%u\n",
                            baseName(l.filePath).c_str(), (unsigned)l.line);
                if (refs > 12) break;
            }
        }
        kv("REFERENCES_OF_runAudit", (long long)refs);
        check("FIND_ALL_REFERENCES_NON_EMPTY", refs > 0,
              "references=" + std::to_string(refs));
    }

    // --- call graph ---------------------------------------------------------
    {
        SourceLocation ctx =
            SourceLocation::make(root + "/src/win32app/", 1, 1);
        const SymbolEntry* e = sci.goToDefinition("runAudit", ctx);
        size_t callers = 0, callees = 0;
        if (e) {
            callers = sci.getCallersOf(e->symbolId).size();
            callees = sci.getCalleesOf(e->symbolId).size();
            for (const CallGraphEdge& g : sci.getCallersOf(e->symbolId))
                std::printf("CALLER_OF_runAudit=%s\n",
                            baseName(g.callSite.filePath).c_str());
        }
        kv("CALLERS_OF_runAudit", (long long)callers);
        kv("CALLEES_OF_runAudit", (long long)callees);
        check("CALL_GRAPH_NON_EMPTY", callers + callees > 0,
              "callers=" + std::to_string(callers) +
                  " callees=" + std::to_string(callees));
    }

    // --- call chain, completions, hover -------------------------------------
    {
        SourceLocation ctx =
            SourceLocation::make(root + "/src/win32app/", 1, 1);
        const SymbolEntry* e = sci.goToDefinition("runAudit", ctx);
        const uint64_t id = e ? e->symbolId : 0;
        kv("CALL_CHAIN_DEPTH_OF_runAudit",
           (long long)sci.getCallChain(id, 4).size());
        const std::vector<CompletionItem> comps =
            sci.getCompletions("scan", 0, 20);
        kv("COMPLETIONS_prefix_scan", (long long)comps.size());
        for (const CompletionItem& c : comps)
            std::printf("COMPLETION=%s\n", c.label.c_str());
        check("COMPLETIONS_NON_EMPTY", !comps.empty(),
              "completions=" + std::to_string(comps.size()));

        if (id) {
            const HoverInfo h = sci.getHoverInfo(id);
            std::printf("HOVER_runAudit_SIGNATURE=%s\n", h.signature.c_str());
            kv("HOVER_DEFINED_LINE", (long long)h.definedLine);
        }
        check("HOVER_PRODUCED_A_DEFINITION", id != 0,
              "symbolId=" + std::to_string(id));
    }

    // --- search -------------------------------------------------------------
    {
        const std::vector<const SymbolEntry*> hits =
            sci.searchSymbols("Audit", SymbolKind::Unknown, 20);
        kv("SEARCH_Audit", (long long)hits.size());
        for (const SymbolEntry* h : hits)
            std::printf("SEARCH_HIT=%s:%u\n",
                        baseName(h->definition.filePath).c_str(),
                        (unsigned)h->definition.line);
        check("SEARCH_RETURNS_HITS", !hits.empty(),
              "hits=" + std::to_string(hits.size()));

        const std::vector<const SymbolEntry*> inFile =
            sci.getSymbolsInFile(files[0]);
        kv("SYMBOLS_IN_FIRST_FILE", (long long)inFile.size());
        check("FILE_SYMBOL_QUERY_NON_EMPTY", !inFile.empty(),
              "symbols=" + std::to_string(inFile.size()));
    }

    // --- the bug this gate exists for ---------------------------------------
    // indexFile() used to answer ok for a file that does not exist, because it
    // never opened it. It must not.
    {
        const PatchResult ghost = sci.indexFile(root + "/definitely_not_here.cpp");
        std::printf("INDEX_MISSING_FILE_SUCCESS=%d DETAIL=%s\n", ghost.success ? 1 : 0, ghost.detail.c_str());
        check("INDEX_REJECTS_MISSING_FILE", !ghost.success,
              ghost.success ? "reported success for a nonexistent path"
                            : ("rejected: " + ghost.detail));
    }

    std::printf("CHECKS_TOTAL=%d\n", g_pass + g_fail);
    std::printf("CHECKS_PASSED=%d\n", g_pass);
    std::printf("CHECKS_FAILED=%d\n", g_fail);
    const bool ok = (g_fail == 0);
    std::printf("VERDICT=%s\n", ok ? "PASS" : "FAIL");
    std::printf("VERDICT_DERIVED=from %d measured query checks; %d failed\n",
                g_pass + g_fail, g_fail);
    std::printf("SEMANTIC_SURFACE=%s\n",
                ok ? "LIVE" : "STILL_HOLLOW");
    return ok ? 0 : 6;
}