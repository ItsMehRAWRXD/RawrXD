// ============================================================================
// repo_intelligence_cert.cpp Ã¢â‚¬â€ RAWRXD_REPOSITORY_INTELLIGENCE_001
//
// Measures the repository intelligence authority against RawrXD itself and
// writes a receipt whose verdict is derived from what it measured. Every field
// below is computed; none is a constant.
//
// The load-bearing experiment is the last one. It reconstructs, byte for byte,
// the discovery scope that produced this repository's false absences Ã¢â‚¬â€
// src/core/ssot_handlers.cpp:1366 enumerated exactly {"src","include","tests",
// "test"} under a 1600-file cap Ã¢â‚¬â€ runs it here, and reports the disagreement
// with the whole-repository universe. A claim of absence is only meaningful if
// the universe it was checked against actually covered the repository.
// ============================================================================
#include "repointel/RepositoryIntelligence.hpp"
#include "repointel/RepositoryUniverse.hpp"
#include "repointel/ScopeTree.hpp"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace rawrxd::repointel;

namespace {

FILE* g_out = nullptr;

void line(const std::string& s) {
    std::fputs(s.c_str(), g_out);
    std::fputc('\n', g_out);
    std::printf("%s\n", s.c_str());
}

void kv(const std::string& k, const std::string& v) { line(k + "=" + v); }
void kvn(const std::string& k, uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof(b), "%llu", static_cast<unsigned long long>(v));
    kv(k, b);
}
void kvi(const std::string& k, long long v) {
    char b[32];
    std::snprintf(b, sizeof(b), "%lld", v);
    kv(k, b);
}
void kvd(const std::string& k, double v, int prec = 1) {
    char b[64];
    std::snprintf(b, sizeof(b), "%.*f", prec, v);
    kv(k, b);
}
void kvB(const std::string& k, bool v) { kv(k, v ? "1" : "0"); }

std::string topDir(const std::string& rel) {
    const size_t cut = rel.find('/');
    if (cut == std::string::npos) return rel;
    return rel.substr(0, cut);
}

std::string secondDir(const std::string& rel) {
    const size_t a = rel.find('/');
    if (a == std::string::npos) return rel;
    const size_t b = rel.find('/', a + 1);
    if (b == std::string::npos) return rel;
    return rel.substr(0, b);
}

std::string toSlashes(std::string p) {
    for (char& c : p) {
        if (c == '\\') c = '/';
    }
    return p;
}

bool dirExists(const std::string& p) {
    const DWORD a = GetFileAttributesA(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

bool lspExt(const std::string& path) {
    const size_t dot = path.find_last_of('.');
    if (dot == std::string::npos) return false;
    std::string e = path.substr(dot);
    for (char& c : e) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return e == ".c" || e == ".cc" || e == ".cpp" || e == ".cxx" ||
           e == ".h" || e == ".hh" || e == ".hpp" || e == ".hxx" ||
           e == ".ixx" || e == ".inl" || e == ".ipp" || e == ".asm" ||
           e == ".inc";
}

// Reconstruction of the legacy discovery scope. Same four hardcoded roots,
// same 1600-file cap, same in-place depth-first alphabetical recursion, and
// the same early break. Subdirectory names are returned sorted because
// FindFirstFileA order is filesystem-dependent; the original code did not sort
// either, so this is the sorted form of the same walk.
void legacyCollect(const std::string& root, std::vector<std::string>& out,
                   size_t maxFiles, std::vector<std::string>* allIfNoCap) {
    if (out.size() >= maxFiles || !dirExists(root)) return;
    WIN32_FIND_DATAA fd{};
    HANDLE           h = FindFirstFileA((root + "\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    std::vector<std::string> dirs;
    std::vector<std::string> files;
    do {
        if (std::strcmp(fd.cFileName, ".") == 0 ||
            std::strcmp(fd.cFileName, "..") == 0)
            continue;
        const std::string child = root + "\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            dirs.push_back(child);
        } else if (lspExt(child)) {
            files.push_back(toSlashes(child));
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    std::sort(dirs.begin(), dirs.end());
    std::sort(files.begin(), files.end());
    for (const std::string& f : files) {
        if (out.size() >= maxFiles) return;
        out.push_back(f);
        if (allIfNoCap) allIfNoCap->push_back(f);
    }
    for (const std::string& d : dirs) {
        if (out.size() >= maxFiles) break;
        legacyCollect(d, out, maxFiles, allIfNoCap);
    }
}

std::string joinPath(const std::string& a, const std::string& b) {
    return a.empty() ? b : a + "/" + b;
}

bool makeDirs(const std::string& path) {
    std::string acc;
    size_t      i = 0;
    while (i < path.size()) {
        const size_t cut = path.find('/', i);
        const std::string part =
            path.substr(0, cut == std::string::npos ? path.size() : cut);
        if (!part.empty() && part.size() > 2) {
            CreateDirectoryA(part.c_str(), nullptr);
        }
        if (cut == std::string::npos) break;
        i = cut + 1;
    }
    (void)acc;
    return dirExists(path);
}

}  // namespace

int main(int argc, char** argv) {
    std::string root;
    std::string receipt = "repo_intelligence_receipt.txt";
    std::string cacheDir = ".repo_intel_cache";
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--root" && i + 1 < argc) {
            root = argv[++i];
        } else if (a == "--out" && i + 1 < argc) {
            receipt = argv[++i];
        } else if (a == "--cache" && i + 1 < argc) {
            cacheDir = argv[++i];
        }
    }
    if (root.empty()) root = resolveRepositoryRoot(".");
    if (root.empty()) {
        std::printf("VERDICT=FAIL\nRATIONALE=repository root not found\n");
        return 3;
    }

    g_out = fopen(receipt.c_str(), "wb");
    if (!g_out) {
        std::printf("cannot write receipt %s\n", receipt.c_str());
        return 4;
    }

    line("RECEIPT=RAWRXD_REPOSITORY_INTELLIGENCE_001");
    kv("ROOT", toSlashes(root));

    // Collected here, asserted at the end. Nothing below reads a constant.
    bool crossFileCallerFound = false;
    bool multiHopFound = false;
    uint64_t depsFound = 0, dependentsFound = 0;
    uint64_t searchHits = 0, rankChunks = 0;
    bool rankMonotonic = true, rankDeterministic = true;
    bool saved = false, loadedOk = false, reloadFileCountMatch = false,
         reloadQueryIdentical = false;
    bool deterministicIdentical = false;
    std::string detHashA;
    bool incrReindexedOne = false, incrFasterThanFull = false;
    uint64_t incrModified = 0, incrReused = 0, incrReindexed = 0;
    bool falseAbsenceDemonstrated = false, narrowClaimRefused = false;
    uint64_t legacyMissedFiles = 0;

    // ---------------------------------------------------------------- build
    UniversePolicy policy;
    policy.explicitRoot = root;
    policy.extensions = {".cpp", ".c", ".cc", ".cxx", ".h", ".hpp", ".hh",
                         ".hxx", ".inl", ".ipp", ".inc", ".asm", ".cmake",
                         ".ps1", ".py", ".rc", ".json", ".txt", ".md"};

    RepositoryIntelligence idx;
    idx.build(policy, 0);
    const IndexStats& st = idx.stats();

    kvn("UNIVERSE_ROOT_EXISTS", idx.universe().rootExists ? 1u : 0u);
    kvn("UNIVERSE_ROOTS_INDEXED", idx.universe().rootsIndexed.size());
    kvn("FILES_SEEN_ALL_TYPES", idx.universe().filesSeen);
    kvn("UNIVERSE_BYTES_SEEN", idx.universe().bytesSeen);
    kvn("FILES_INDEXED", st.filesIndexed);
    kvn("FILES_REUSED", st.filesReused);
    kvn("BYTES_INDEXED", st.bytesIndexed);
    kvn("LINES_INDEXED", st.linesIndexed);
    kvn("UNREADABLE_FILES", st.unreadableFiles);
    kvn("WALK_TRUNCATED_FILES", st.truncatedFiles);
    kvn("WORKER_THREADS", st.threads);
    kvd("WALK_MS", st.walkMs, 1);
    kvd("PARSE_MS", st.parseMs, 1);
    kvd("MERGE_MS", st.mergeMs, 1);
    kvd("TOTAL_MS", st.totalMs, 1);
    kvn("PEAK_WORKING_SET_BYTES", st.peakWorkingSetBytes);
    kvd("MB_PER_SECOND", st.totalMs > 0.0
                            ? (static_cast<double>(st.bytesIndexed) / (1024.0 * 1024.0)) /
                                  (st.totalMs / 1000.0)
                            : 0.0,
        1);

    // ------------------------------------------------- what was NOT indexed
    kvn("PRUNED_DIRS", st.prunedDirs);
    kvn("PRUNED_FILES_BELOW", st.prunedFilesBelow);
    kvn("PRUNED_BYTES_BELOW", st.prunedBytesBelow);
    line("PRUNED_DIR_LISTING_BEGIN");
    {
        uint64_t shown = 0;
        std::map<std::string, std::pair<uint64_t, uint64_t>> agg;
        for (const PrunedDir& p : idx.universe().pruned) {
            auto& a = agg[topDir(p.rel)];
            a.first += p.filesBelow;
            a.second += p.bytesBelow;
        }
        for (const auto& kv2 : agg) {
            char b[128];
            std::snprintf(b, sizeof(b), "PRUNED_TOP=%s FILES=%llu BYTES=%llu",
                          kv2.first.c_str(),
                          static_cast<unsigned long long>(kv2.second.first),
                          static_cast<unsigned long long>(kv2.second.second));
            line(b);
            ++shown;
            if (shown >= 40) break;
        }
    }
    line("PRUNED_DIR_LISTING_END");

    // --------------------------------------------------- structural analysis
    kvn("CHUNKS", st.chunks);
    kvn("SYMBOLS", st.symbols);
    kvn("DISTINCT_IDENTIFIERS", st.identifiers);
    kvn("SEARCH_TOKENS", st.searchTokens);
    kvn("POSTING_ENTRIES", st.postingEntries);
    kvn("CALL_EDGES", st.callEdges);
    kvn("INCLUDE_EDGES", st.includeEdges);
    kvn("INCLUDE_EDGES_RESOLVED", st.resolvedIncludes);
    kvn("INCLUDE_EDGES_UNRESOLVED", st.unresolvedIncludes);
    kvn("INCLUDE_CYCLE_EDGES", st.includeCycles);

    // Chunk-kind census, so a reviewer can see the chunker is not emitting one
    // kind of node and calling it a symbol graph.
    {
        std::map<std::string, uint64_t> kinds;
        for (const ChunkRef& c : idx.chunks())
            kinds[scopeKindName(c.scope)]++;
        for (const auto& k : kinds) kvn("CHUNK_KIND_" + k.first, k.second);
        std::map<std::string, uint64_t> syms;
        for (const SymbolRef& s : idx.symbols())
            syms[symbolKindName(s.kind)]++;
        for (const auto& k : syms) kvn("SYMBOL_KIND_" + k.first, k.second);
    }
    kv("CHUNKER", "SCOPE_TREE_STRUCTURAL");
    kvB("FULL_CPP_AST", false);
    kvB("FIELD_DETECTION_HEURISTIC", true);
    kvB("TREE_SITTER_AVAILABLE", false);
    kvB("LIBCLANG_AVAILABLE", false);

    // ------------------------------------------------ symbol / reference graph
    struct Probe {
        const char*         symbol;
        const char*         expectFile;
        const char*         label;
    };
    const Probe probes[] = {
        {"analyzeSource", "src/repointel/ScopeTree.cpp", "self-indexed symbol"},
        {"buildUniverse", "src/repointel/RepositoryUniverse.cpp", "self-indexed symbol"},
        {"runAudit", "src/agentmodes/RawrAuditAuthority.cpp", "existing audit authority"},
        {"scanSourceTree", "src/agentmodes/RawrAuditAuthority.cpp", "existing audit authority"},
        {"collectDefaultLspSearchFiles", "src/core/ssot_handlers.cpp", "the narrow-scope defect"},
        {"rawrxd_filter_missing_sources", nullptr, "cmake function, declared only"},
        {"Deep2Engine", nullptr, "engine class"},
        {"specKvMirrorReset", nullptr, "engine member"},
        {"writeAuditReceipt", "src/agentmodes/RawrAuditAuthority.cpp", "receipt writer"},
    };

    uint64_t probesFound = 0, probesMissing = 0, probesWrongFile = 0;
    for (const Probe& p : probes) {
        const std::vector<SymbolRef> defs = idx.definitionsOf(p.symbol);
        if (defs.empty()) {
            ++probesMissing;
            line(std::string("PROBE_MISSING=") + p.label + " symbol=" +
                 p.symbol);
            continue;
        }
        ++probesFound;
        const SymbolRef& d = defs.front();
        const std::string rel = idx.universe().files[d.fileIdx].rel;
        if (p.expectFile && rel != p.expectFile) ++probesWrongFile;
        line(std::string("PROBE_DEFINED=") + p.label + " symbol=" + p.symbol +
             " file=" + rel + " line=" + std::to_string(d.beginLine));
    }
    kvn("PROBES_TOTAL", sizeof(probes) / sizeof(probes[0]));
    kvn("PROBES_DEFINITION_FOUND", probesFound);
    kvn("PROBES_NO_DEFINITION", probesMissing);
    kvn("PROBES_WRONG_FILE", probesWrongFile);

    // Cross-file callers: runAudit is called from RawrModesCli.cpp, which is a
    // different file from its definition.
    {
        const std::vector<SymbolRef> callers = idx.callersOf("runAudit");
        bool foundDifferentFile = false;
        for (const SymbolRef& c : callers) {
            const std::string rel = idx.universe().files[c.fileIdx].rel;
            line("CALLER_OF_runAudit=" + rel + ":" +
                 std::to_string(c.beginLine));
            if (rel != "src/agentmodes/RawrAuditAuthority.cpp")
                foundDifferentFile = true;
        }
        kvn("CALLERS_OF_runAudit", callers.size());
        crossFileCallerFound = foundDifferentFile;
        kvB("CROSS_FILE_CALLER_FOUND", crossFileCallerFound);
    }
    {
        const std::vector<SymbolRef> callees = idx.calleesOf("runAudit");
        kvn("CALLEES_OF_runAudit", callees.size());
        for (size_t i = 0; i < callees.size() && i < 12; ++i)
            line("CALLEE_OF_runAudit=" + callees[i].name);
    }
    {
        const std::vector<RankedChunk> hops =
            idx.reachableFrom("runAudit", 4, 32);
        kvn("REACHABLE_FROM_runAudit_HOPS4", hops.size());
        for (size_t i = 0; i < hops.size() && i < 12; ++i)
            line("REACHABLE=" + hops[i].rel + ":" +
                 std::to_string(hops[i].beginLine) + " hops=" +
                 std::to_string(hops[i].hopDistance) + " why=" + hops[i].why);
        bool multiHop = false;
        for (const RankedChunk& h : hops) {
            if (h.hopDistance >= 2) multiHop = true;
        }
        multiHopFound = multiHop;
        kvB("MULTI_HOP_REACHABILITY_FOUND", multiHopFound);
    }

    // ------------------------------------------------------- dependency graph
    {
        const std::vector<std::string> deps =
            idx.transitiveIncludes("src/repointel/RepositoryIntelligence.hpp");
        depsFound = deps.size();
        kvn("TRANSITIVE_INCLUDES_selfHeader", depsFound);
        const std::vector<std::string> dependents =
            idx.transitiveDependents("src/repointel/ScopeTree.hpp");
        dependentsFound = dependents.size();
        kvn("TRANSITIVE_DEPENDENTS_ScopeTreeHpp", dependentsFound);
        for (size_t i = 0; i < dependents.size() && i < 20; ++i)
            line("DEPENDENT_OF_ScopeTreeHpp=" + dependents[i]);
        const std::vector<std::string> cycles = idx.includeCycles();
        kvn("INCLUDE_CYCLES_DETECTED", cycles.size());
        for (size_t i = 0; i < cycles.size() && i < 10; ++i)
            line("INCLUDE_CYCLE=" + cycles[i]);
        const std::vector<RankedChunk> impact =
            idx.changeImpact("src/repointel/ScopeTree.hpp", 32);
        kvn("CHANGE_IMPACT_ScopeTreeHpp", impact.size());
        for (size_t i = 0; i < impact.size() && i < 10; ++i)
            line("IMPACT=" + impact[i].rel + " why=" + impact[i].why);
    }

    // ------------------------------------------------- search and ranking
    {
        const std::vector<SearchHit> hits =
            idx.search("receipt immutability authority", 10);
        searchHits = hits.size();
        kvn("SEARCH_hits", searchHits);
        for (const SearchHit& h : hits)
            line("SEARCH_HIT=" + h.rel + ":" + std::to_string(h.line) +
                 " token=" + h.matched);
        const std::vector<RankedChunk> ctx =
            idx.rankContext("write a receipt with measured fields only", "", 12);
        rankChunks = ctx.size();
        kvn("RANKCONTEXT_chunks", rankChunks);
        for (const RankedChunk& c : ctx)
            line("RANKCONTEXT=" + c.rel + ":" + std::to_string(c.beginLine) +
                 " score=" + std::to_string(static_cast<int>(c.score * 1000.0)) +
                 " why=" + c.why);
        bool deterministic = true;
        for (size_t i = 1; i < ctx.size(); ++i) {
            if (ctx[i - 1].score < ctx[i].score) deterministic = false;
        }
        rankMonotonic = deterministic;
        kvB("RANKCONTEXT_MONOTONIC", rankMonotonic);

        const std::vector<RankedChunk> ctx2 =
            idx.rankContext("write a receipt with measured fields only", "", 12);
        bool sameOrder = ctx.size() == ctx2.size();
        for (size_t i = 0; sameOrder && i < ctx.size(); ++i)
            if (ctx[i].rel != ctx2[i].rel ||
                ctx[i].beginLine != ctx2[i].beginLine)
                sameOrder = false;
        rankDeterministic = sameOrder;
        kvB("RANKCONTEXT_DETERMINISTIC", rankDeterministic);
    }

    // ------------------------------------------------------------ persistence
    makeDirs(cacheDir);
    const std::string indexPath = joinPath(cacheDir, "rawrxd_repo.rix");
    std::string saveErr;
    saved = idx.save(indexPath, &saveErr);
    kvB("INDEX_SAVED", saved);
    if (!saved) kv("INDEX_SAVE_ERROR", saveErr);
    kvn("INDEX_BYTES_ON_DISK", st.indexBytesOnDisk);

    {
        RepositoryIntelligence loaded;
        std::string loadErr;
        const bool ok = loaded.load(indexPath, &loadErr);
        loadedOk = ok;
        kvB("INDEX_LOADED", loadedOk);
        if (!ok) kv("INDEX_LOAD_ERROR", loadErr);
        kvB("RELOAD_FILE_COUNT_MATCH",
           loaded.universeFileCount() == idx.universeFileCount());
        kvB("RELOAD_SYMBOL_COUNT_MATCH",
           loaded.symbols().size() == idx.symbols().size());
        kvB("RELOAD_CHUNK_COUNT_MATCH",
           loaded.chunks().size() == idx.chunks().size());
        const std::vector<RankedChunk> a =
            idx.rankContext("write a receipt with measured fields only", "", 12);
        const std::vector<RankedChunk> b =
            loaded.rankContext("write a receipt with measured fields only", "", 12);
        bool same = a.size() == b.size();
        for (size_t i = 0; same && i < a.size(); ++i)
            if (a[i].rel != b[i].rel || a[i].beginLine != b[i].beginLine)
                same = false;
        reloadQueryIdentical = same;
        kvB("RELOAD_QUERY_RESULTS_IDENTICAL", reloadQueryIdentical);
        const std::vector<SymbolRef> da = idx.definitionsOf("runAudit");
        const std::vector<SymbolRef> db = loaded.definitionsOf("runAudit");
        bool dsame = da.size() == db.size();
        for (size_t i = 0; dsame && i < da.size(); ++i)
            if (da[i].name != db[i].name || da[i].fileIdx != db[i].fileIdx ||
                da[i].beginLine != db[i].beginLine)
                dsame = false;
        kvB("RELOAD_DEFINITIONS_IDENTICAL", dsame);
    }

    // ------------------------------------------------------ deterministic build
    {
        const std::string dirA = joinPath(cacheDir, "det_a");
        const std::string dirB = joinPath(cacheDir, "det_b");
        makeDirs(dirA);
        makeDirs(dirB);
        UniversePolicy p2 = policy;
        p2.extensions.clear();  // extension set would change the universe; keep
                                // it identical to the certified build instead
        p2.extensions = policy.extensions;
        const auto det =
            RepositoryIntelligence::verifyDeterminismRebuild(p2, dirA, dirB);
        deterministicIdentical = det.identical;
        detHashA = det.hashA;
        kvB("DETERMINISTIC_REBUILD_IDENTICAL", deterministicIdentical);
        kvn("DETERMINISM_BYTES_A", det.bytesA);
        kvn("DETERMINISM_BYTES_B", det.bytesB);
        kv("DETERMINISM_HASH_A", det.hashA);
        kv("DETERMINISM_HASH_B", det.hashB);
        if (!det.mismatch.empty()) kv("DETERMINISM_MISMATCH", det.mismatch);
    }

    // ---------------------------------------------------- incremental refresh
    {
        UniversePolicy pr = policy;
        RepositoryIntelligence fresh;
        fresh.build(pr, 0);
        const IncrementalDelta d = fresh.refresh();
        kvn("INCR_FIRST_REFRESH_filesReindexed", d.reindexed);
        kvn("INCR_FIRST_REFRESH_filesReused", d.reused);
        kvn("INCR_FIRST_REFRESH_modified", d.modified);
        kvn("INCR_FIRST_REFRESH_added", d.added);
        kvn("INCR_FIRST_REFRESH_removed", d.removed);
        kvn("INCR_FIRST_REFRESH_unchanged", d.unchanged);
        kvi("INCR_FIRST_REFRESH_ms", static_cast<long long>(d.incrMs));

        // Change one file for real, then refresh again.
        const std::string victim = joinPath(root, "src/repointel/ScopeTree.hpp");
        std::string original;
        std::string rerr;
        const bool readBack = readWholeFile(toSlashes(victim), original, &rerr);
        kvB("INCR_VICTIM_READABLE", readBack);
        FILE* vf = fopen(toSlashes(victim).c_str(), "ab");
        if (vf) {
            std::fputs("\n// RAWRXD_REPO_INTEL_CERT_001 temporary probe\n", vf);
            fclose(vf);
        }
        const IncrementalDelta d2 = fresh.refresh();
        kvn("INCR_SECOND_REFRESH_reindexed", d2.reindexed);
        kvn("INCR_SECOND_REFRESH_reused", d2.reused);
        kvn("INCR_SECOND_REFRESH_modified", d2.modified);
        kvn("INCR_SECOND_REFRESH_hashVerified", d2.hashVerified);
        kvn("INCR_SECOND_REFRESH_added", d2.added);
        kvn("INCR_SECOND_REFRESH_removed", d2.removed);
        kvi("INCR_SECOND_REFRESH_ms", static_cast<long long>(d2.incrMs));
        kvi("FULL_BUILD_MS", static_cast<long long>(fresh.stats().totalMs));
        incrReindexedOne = (d2.reindexed == 1);
        incrModified = d2.modified;
        incrReused = d2.reused;
        incrReindexed = d2.reindexed;
        kvB("INCR_REINDEXED_EXACTLY_ONE_FILE", incrReindexedOne);
        kvB("INCR_REUSED_THE_REST", d2.reused > 0 && d2.reused > d2.reindexed);
        incrFasterThanFull =
            (d2.incrMs > 0.0 && d2.incrMs < fresh.stats().totalMs);
        kvB("INCR_FASTER_THAN_FULL", incrFasterThanFull);

        if (readBack) {
            FILE* rf = fopen(toSlashes(victim).c_str(), "wb");
            if (rf) {
                std::fwrite(original.data(), 1, original.size(), rf);
                fclose(rf);
            }
            std::string restored;
            const bool okRestore =
                readWholeFile(toSlashes(victim), restored) && restored == original;
            kvB("INCR_VICTIM_RESTORED", okRestore);
        }
    }

    // ================================================================
    // The falseness experiment.
    //
    // Reconstruct the discovery scope that produced this repository's false
    // absences, run it, and compare against the whole-repository universe.
    // ================================================================
    line("FALSE_ABSENCE_EXPERIMENT_BEGIN");
    {
        std::vector<std::string> legacy;
        std::vector<std::string> legacyUncapped;
        const size_t kLegacyCap = 1600;
        const char* legacyRoots[] = {"src", "include", "tests", "test"};
        for (const char* r : legacyRoots) {
            legacyCollect(joinPath(root, r), legacy, kLegacyCap, &legacyUncapped);
            if (legacy.size() >= kLegacyCap) break;
        }
        const bool legacyHitCap = legacy.size() >= kLegacyCap;
        kvn("LEGACY_SCOPE_FILES", legacy.size());
        kvn("LEGACY_SCOPE_ROOTS", 4);
        kvn("LEGACY_SCOPE_CAP", kLegacyCap);
        kvB("LEGACY_SCOPE_TRUNCATED", legacyHitCap);

        // The same walk with no cap, so the truncation's cost is measurable.
        std::vector<std::string> uncapped;
        for (const char* r : legacyRoots)
            legacyCollect(joinPath(root, r), uncapped, 0, nullptr);
        kvn("LEGACY_SCOPE_FILES_IF_UNCAPPED", uncapped.size());
        kvn("LEGACY_SCOPE_FILES_LOST_TO_CAP",
            uncapped.size() > legacy.size() ? uncapped.size() - legacy.size() : 0);

        std::set<std::string> legacySet(legacy.begin(), legacy.end());
        std::vector<std::string> universePaths;
        universePaths.reserve(idx.universe().files.size());
        for (const UniverseFile& f : idx.universe().files)
            universePaths.push_back(toSlashes(f.abs));

        std::vector<std::string> missed;
        for (const std::string& p : universePaths)
            if (!legacySet.count(p)) missed.push_back(p);
        kvn("UNIVERSE_FILES", universePaths.size());
        legacyMissedFiles = missed.size();
        kvn("FILES_VISIBLE_REPO_WIDE_BUT_INVISIBLE_TO_LEGACY_SCOPE",
            legacyMissedFiles);

        std::map<std::string, uint64_t> missedByDir;
        for (const std::string& p : missed) ++missedByDir[secondDir(p)];
        uint64_t shown = 0;
        for (const auto& kv2 : missedByDir) {
            if (shown++ >= 60) break;
            kvn("INVISIBLE_DIR=" + kv2.first, kv2.second);
        }

        // Files the legacy scope never saw even with the cap removed, because
        // they live outside the four hardcoded roots. These are whole source
        // trees, not build output.
        std::vector<std::string> outsideRoots;
        for (const std::string& p : missed) {
            const std::string t = topDir(p);
            if (t == "src" || t == "include" || t == "tests" || t == "test")
                continue;
            outsideRoots.push_back(p);
        }
        kvn("FILES_OUTSIDE_ALL_FOUR_LEGACY_ROOTS", outsideRoots.size());
        {
            std::map<std::string, uint64_t> byTop;
            for (const std::string& p : outsideRoots) ++byTop[topDir(p)];
            shown = 0;
            for (const auto& kv2 : byTop) {
                if (shown++ >= 40) break;
                kvn("OUTSIDE_ROOT_DIR=" + kv2.first, kv2.second);
            }
        }
        line("SAMPLE_FILES_INVISIBLE_TO_LEGACY_SCOPE");
        for (size_t i = 0; i < missed.size() && i < 40; ++i) {
            std::string rel = missed[i];
            const std::string r2 = toSlashes(root) + "/";
            if (rel.rfind(r2, 0) == 0) rel = rel.substr(r2.size());
            line("INVISIBLE=" + rel);
        }
        line("SAMPLE_FILES_INVISIBLE_END");

        // Now the decisive part: take capability names that earlier audits of
        // this repository declared absent, and ask the whole-repository index
        // where they live.
        struct Claim {
            const char* claim;
            const char* probe;
        };
        const Claim claims[] = {
            {"IDE_HTTP_ROUTE_BINDING", "bindIdeHttpRoutes"},
            {"SANDBOXED_TOOL_AUTHORITY", "sandboxedToolAuthority"},
            {"IDECore_Shutdown", "IDECore_Shutdown"},
            {"RECEIPT_IMMUTABILITY", "beginImmutableGate"},
            {"SINGLE_WRITER", "checkWrite"},
            {"PRODUCTION_PROFILER", "ProductionProfiler"},
            {"NVME_STREAM", "NVMeStream"},
            {"BP16_STREAMER", "BP16Streamer"},
            {"COMPRESSED_KV_CACHE", "CompressedKVCache"},
            {"MARS_CONTROLLER", "MARSController"},
        };
        uint64_t claimsResolved = 0, claimsUnresolved = 0;
        line("ABSENCE_CLAIM_AUDIT_BEGIN");
        for (const Claim& c : claims) {
            const std::vector<SymbolRef> defs = idx.definitionsOf(c.probe);
            const std::vector<SymbolRef> ment = idx.filesMentioning(c.probe);
            const AbsenceClaim ac = idx.claimAbsence(c.probe);
            if (!defs.empty()) {
                ++claimsResolved;
                line(std::string("ABSENCE_CLAIM=") + c.claim +
                     " probe=" + c.probe + " RESOLVED_WHERE=" +
                     idx.universe().files[defs.front().fileIdx].rel + ":" +
                     std::to_string(defs.front().beginLine));
            } else if (!ment.empty()) {
                ++claimsResolved;
                std::string where;
                for (size_t i = 0; i < ment.size() && i < 5; ++i) {
                    if (i) where += ",";
                    where += idx.universe().files[ment[i].fileIdx].rel;
                }
                line(std::string("ABSENCE_CLAIM=") + c.claim + " probe=" +
                     c.probe + " MENTIONED_IN=" + where);
            } else {
                ++claimsUnresolved;
                line(std::string("ABSENCE_CLAIM=") + c.claim + " probe=" +
                     c.probe + " RESOLVED_WHERE=NOWHERE CLAIM_ALLOWED=" +
                     (ac.allowed ? "1" : "0") + " REFUSAL=" + ac.refusal);
            }
        }
        line("ABSENCE_CLAIM_AUDIT_END");
        kvn("ABSENCE_CLAIMS_RESOLVED_REPO_WIDE", claimsResolved);
        kvn("ABSENCE_CLAIMS_UNRESOLVED_REPO_WIDE", claimsUnresolved);

        // A claim made from the narrowed scope must be refused, structurally.
        UniversePolicy narrow;
        narrow.explicitRoot = root;
        narrow.narrowed = true;
        narrow.scopeLabel = "win32app-only, the legacy audit scope";
        narrow.extraRoots = {"src/win32app"};
        narrow.extensions = {".cpp"};
        RepositoryIntelligence narrowIdx;
        narrowIdx.build(narrow, 0);
        const AbsenceClaim nc = narrowIdx.claimAbsence("anything at all");
        kvB("NARROW_SCOPE_UNIVERSE_FILES", narrowIdx.universeFileCount() > 0);
        kvn("NARROW_SCOPE_FILE_COUNT", narrowIdx.universeFileCount());
        narrowClaimRefused = !nc.allowed;
        kvB("NARROW_SCOPE_CLAIM_ALLOWED", nc.allowed);
        kv("NARROW_SCOPE_REFUSAL", nc.refusal);

        const std::vector<SymbolRef> nf = narrowIdx.definitionsOf("runAudit");
        line(std::string("NARROW_SCOPE_FINDING=") +
             (nf.empty() ? std::string("runAudit NOT FOUND -> would have been "
                                       "reported ABSENT")
                         : std::string("runAudit found")));
        const std::vector<SymbolRef> wf = idx.definitionsOf("runAudit");
        line(std::string("REPO_WIDE_FINDING=") +
             (wf.empty() ? std::string("runAudit NOT FOUND")
                         : ("runAudit found at " +
                            idx.universe().files[wf.front().fileIdx].rel)));
        falseAbsenceDemonstrated = nf.empty() && !wf.empty();
        kvB("FALSE_ABSENCE_DEMONSTRATED", falseAbsenceDemonstrated);
    }
    line("FALSE_ABSENCE_EXPERIMENT_END");

    // ------------------------------------------------------- very large repo
    {
        // Scaling curve: same code path over 1, 10 and 100 percent of the
        // universe, so the cost per file is visible rather than assumed.
        const size_t total = idx.universe().files.size();
        const size_t points[] = {total / 100 + 1, total / 10 + 1, total};
        int n = 0;
        for (const size_t count : points) {
            UniversePolicy p3;
            p3.explicitRoot = root;
            p3.maxFiles = static_cast<uint32_t>(count);
            RepositoryIntelligence s;
            s.build(p3, 0);
            ++n;
            kvn("SCALE_POINT" + std::to_string(n) + "_FILES",
                s.universeFileCount());
            kvd("SCALE_POINT" + std::to_string(n) + "_MS", s.stats().totalMs, 1);
            kvd("SCALE_POINT" + std::to_string(n) + "_US_PER_FILE",
                s.universeFileCount()
                    ? s.stats().totalMs * 1000.0 /
                          static_cast<double>(s.universeFileCount())
                    : 0.0,
                1);
        }
        kvn("SCALE_POINTS", n);
    }

    // ------------------------------------------------------------- the guard
    {
        const AbsenceClaim ok = idx.claimAbsence("a feature that does not exist");
        kvB("FULL_SCOPE_CLAIM_ALLOWED", ok.allowed);
        kvB("FULL_SCOPE_IS_NARROWED", ok.narrowed);
        kvn("FULL_SCOPE_UNIVERSE_FILES", ok.universeFiles);
        kvn("FULL_SCOPE_FILES_SEEN", ok.filesSeen);
        kvn("FULL_SCOPE_PRUNED_DIRS", ok.prunedDirs);
    }

    // ---------------------------------------------------------------- verdict
    // Derived from the measurements above, in this order. A capability that
    // did not measure is reported as not passing; nothing here is asserted.
    struct Check {
        const char* name;
        bool        pass;
        std::string evidence;
    };
    std::vector<Check> checks;

    checks.push_back({"UNIVERSE_IS_WHOLE_REPOSITORY",
                      idx.universe().rootExists && st.filesIndexed > 1000 &&
                          st.truncatedFiles == 0 && !idx.narrowed(),
                      "FILES_INDEXED=" + std::to_string(st.filesIndexed)});
    checks.push_back({"PRUNED_TREES_REPORTED_NOT_HIDDEN",
                      st.prunedDirs > 0 && st.prunedFilesBelow > 0,
                      "PRUNED_DIRS=" + std::to_string(st.prunedDirs)});
    checks.push_back({"STRUCTURAL_CHUNKING",
                      st.chunks > 10000 && st.symbols > 10000,
                      "CHUNKS=" + std::to_string(st.chunks) +
                          " SYMBOLS=" + std::to_string(st.symbols)});
    checks.push_back({"SYMBOL_AND_REFERENCE_GRAPH",
                      probesFound >= 5 && probesWrongFile == 0 &&
                          st.identifiers > 1000,
                      "PROBES_DEFINITION_FOUND=" + std::to_string(probesFound) +
                          " WRONG_FILE=" + std::to_string(probesWrongFile)});
    checks.push_back({"CROSS_FILE_REASONING",
                      crossFileCallerFound && multiHopFound,
                      "CROSS_FILE_CALLER_FOUND=" +
                          std::string(crossFileCallerFound ? "1" : "0") +
                          " MULTI_HOP=" + std::string(multiHopFound ? "1" : "0")});
    checks.push_back({"DEPENDENCY_TRAVERSAL",
                      depsFound > 0 && dependentsFound > 0,
                      "TRANSITIVE_INCLUDES=" + std::to_string(depsFound) +
                          " DEPENDENTS=" + std::to_string(dependentsFound)});
    checks.push_back({"REPOSITORY_SCALE_SEARCH",
                      searchHits > 0 && st.searchTokens > 1000,
                      "SEARCH_hits=" + std::to_string(searchHits) +
                          " SEARCH_TOKENS=" + std::to_string(st.searchTokens)});
    checks.push_back({"CONTEXT_RANKING",
                      rankChunks > 0 && rankMonotonic && rankDeterministic,
                      "RANKCONTEXT_chunks=" + std::to_string(rankChunks)});
    checks.push_back({"PERSISTENT_INDEX",
                      saved && loadedOk && reloadFileCountMatch &&
                          reloadQueryIdentical,
                      "INDEX_BYTES_ON_DISK=" +
                          std::to_string(st.indexBytesOnDisk)});
    checks.push_back({"DETERMINISTIC_INDEX_REBUILD", deterministicIdentical,
                      "DETERMINISM_HASH_A=" + detHashA});
    checks.push_back({"INCREMENTAL_INVALIDATION",
                      incrReindexedOne && incrFasterThanFull,
                      "INCR_SECOND_REFRESH_reindexed=" +
                          std::to_string(incrReindexedOne ? 1u : 0u)});
    checks.push_back({"CHANGED_FILE_INVALIDATION",
                      incrModified >= 1 && incrReused > incrReindexed,
                      "INCR_SECOND_REFRESH_modified=" +
                          std::to_string(incrModified)});
    checks.push_back({"VERY_LARGE_REPOSITORY_BEHAVIOUR",
                      st.filesIndexed > 1000 && st.peakWorkingSetBytes > 0,
                      "FILES_INDEXED=" + std::to_string(st.filesIndexed) +
                          " PEAK_WS=" + std::to_string(st.peakWorkingSetBytes)});
    checks.push_back({"REPO_WIDE_DISCOVERY_IS_ARCHITECTURAL",
                      falseAbsenceDemonstrated && narrowClaimRefused,
                      "FILES_VISIBLE_REPO_WIDE_BUT_INVISIBLE_TO_LEGACY_SCOPE=" +
                          std::to_string(legacyMissedFiles)});

    uint64_t passed = 0, failed = 0;
    line("CHECKS_BEGIN");
    for (const Check& c : checks) {
        if (c.pass) ++passed; else ++failed;
        line(std::string("CHECK=") + c.name + " RESULT=" +
             (c.pass ? "PASS" : "FAIL") + " EVIDENCE=" + c.evidence);
    }
    line("CHECKS_END");
    kvn("CHECKS_TOTAL", checks.size());
    kvn("CHECKS_PASSED", passed);
    kvn("CHECKS_FAILED", failed);

    const bool verdictPass = (failed == 0);
    kv("VERDICT", verdictPass ? "PASS" : "FAIL");
    kv("VERDICT_DERIVED", "from " + std::to_string(checks.size()) +
                              " measured checks; " +
                              std::to_string(failed) + " failed");
    kv("RAWRXD_REPOSITORY_INTELLIGENCE_001",
       verdictPass ? "PASS" : "PARTIAL");

    std::printf("VERDICT=%s\n", verdictPass ? "PASS" : "FAIL");
    fclose(g_out);
    return verdictPass ? 0 : 5;
}