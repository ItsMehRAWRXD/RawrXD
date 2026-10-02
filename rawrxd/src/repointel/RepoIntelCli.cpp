// ============================================================================
// RepoIntelCli.cpp — RAWRXD_REPOSITORY_INTELLIGENCE_001
//
// The scope guard is enforced here rather than documented. `absence()` prints
// the refusal when the universe was narrowed; `rawr repo scope` prints the
// universe and every excluded tree with its size, so a reader can always tell
// "nothing there" from "never looked".
// ============================================================================
#include "repointel/RepoIntelCli.hpp"

#include <algorithm>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "repointel/RepositoryIntelligence.hpp"

namespace rawrxd {
namespace repointel {
namespace {

void out(const std::string& s) { std::printf("%s\n", s.c_str()); }

struct Args {
    std::string              sub;
    std::vector<std::string> positional;
    std::string              root;
    std::string              cache = ".repo_intel_cache";
    std::string              out;
    std::string              file;
    uint32_t                 limit = 20;
    bool                     narrowed = false;
    std::string              scopeLabel;
    std::string              roots;   // comma separated, restricts the walk
};

Args parse(const std::vector<std::string>& a) {
    Args r;
    size_t i = 0;
    if (!a.empty()) {
        r.sub = a[0];
        i = 1;
    }
    for (; i < a.size(); ++i) {
        const std::string& s = a[i];
        if (s == "--root" && i + 1 < a.size()) {
            r.root = a[++i];
        } else if (s == "--cache" && i + 1 < a.size()) {
            r.cache = a[++i];
        } else if (s == "--out" && i + 1 < a.size()) {
            r.out = a[++i];
        } else if (s == "--file" && i + 1 < a.size()) {
            r.file = a[++i];
        } else if (s == "--limit" && i + 1 < a.size()) {
            r.limit = static_cast<uint32_t>(std::strtoul(a[++i].c_str(), nullptr, 10));
        } else if (s == "--scope" && i + 1 < a.size()) {
            r.roots = a[++i];
            r.narrowed = true;
            r.scopeLabel = "--scope " + r.roots;
        } else if (s.rfind("--", 0) == 0) {
            r.positional.push_back(s);
        } else {
            r.positional.push_back(s);
        }
    }
    return r;
}

UniversePolicy policyFrom(const Args& a, const std::string& defaultRoot) {
    UniversePolicy p;
    p.explicitRoot = a.root.empty() ? defaultRoot : a.root;
    if (p.explicitRoot.empty()) p.explicitRoot = resolveRepositoryRoot(".");
    p.extensions = {".cpp", ".c",   ".cc",  ".cxx", ".h",   ".hpp", ".hh",
                     ".hxx", ".inl", ".ipp", ".inc", ".asm", ".cmake",
                     ".ps1", ".py",  ".rc",  ".json", ".txt", ".md"};
    p.narrowed = a.narrowed;
    p.scopeLabel = a.scopeLabel;
    if (!a.roots.empty()) {
        std::string cur;
        for (char c : a.roots) {
            if (c == ',' || c == ';') {
                if (!cur.empty()) p.restrictToRoots.push_back(cur);
                cur.clear();
            } else {
                cur.push_back(c);
            }
        }
        if (!cur.empty()) p.restrictToRoots.push_back(cur);
        p.narrowed = true;
    }
    return p;
}

std::string idx(const std::string& label, size_t i) {
    return "  [" + std::to_string(i) + "] " + label;
}

void printUniverse(const RepositoryIntelligence& in) {
    const IndexStats& s = in.stats();
    out("SCOPE_ROOTS=" + [&] {
        std::string j;
        for (const std::string& r : in.universe().rootsIndexed) {
            if (!j.empty()) j += ",";
            j += r;
        }
        return j;
    }());
    out("SCOPE_NARROWED=" + std::string(in.narrowed() ? "1" : "0"));
    if (in.narrowed()) out("SCOPE_LABEL=" + in.scopeLabel());
    out("UNIVERSE_FILES=" + std::to_string(in.universeFileCount()));
    out("UNIVERSE_BYTES_SEEN=" + std::to_string(in.universe().bytesSeen));
    out("FILES_INDEXED=" + std::to_string(s.filesIndexed));
    out("CHUNKS=" + std::to_string(s.chunks));
    out("SYMBOLS=" + std::to_string(s.symbols));
    out("IDENTIFIERS=" + std::to_string(s.identifiers));
    out("CALL_EDGES=" + std::to_string(s.callEdges));
    out("INCLUDE_EDGES=" + std::to_string(s.includeEdges));
    out("INCLUDE_EDGES_RESOLVED=" + std::to_string(s.resolvedIncludes));
    out("SEARCH_TOKENS=" + std::to_string(s.searchTokens));
    out("WALK_MS=" + std::to_string(static_cast<long long>(s.walkMs)));
    out("TOTAL_MS=" + std::to_string(static_cast<long long>(s.totalMs)));
    out("EXCLUDED_DIRS=" + std::to_string(s.prunedDirs));
    out("EXCLUDED_FILES_BELOW=" + std::to_string(s.prunedFilesBelow));
    out("EXCLUDED_BYTES_BELOW=" + std::to_string(s.prunedBytesBelow));
    out("WALK_TRUNCATED_FILES=" + std::to_string(s.truncatedFiles));
    if (s.prunedDirs) {
        std::map<std::string, std::pair<uint64_t, uint64_t>> agg;
        for (const PrunedDir& p : in.universe().pruned) {
            size_t cut = p.rel.find('/');
            const std::string top = cut == std::string::npos ? p.rel
                                                             : p.rel.substr(0, cut);
            agg[top].first += p.filesBelow;
            agg[top].second += p.bytesBelow;
        }
        for (const auto& kv : agg)
            out("EXCLUDED_TREE=" + kv.first +
                " files=" + std::to_string(kv.second.first) +
                " bytes=" + std::to_string(kv.second.second));
    }
}

int cmdAbsence(const RepositoryIntelligence& in, const std::string& subject) {
    const AbsenceClaim c = in.claimAbsence(subject);
    out("ABSENCE_SUBJECT=" + c.subject);
    out("ABSENCE_CLAIM_ALLOWED=" + std::string(c.allowed ? "1" : "0"));
    out("ABSENCE_UNIVERSE_FILES=" + std::to_string(c.universeFiles));
    out("ABSENCE_FILES_SEEN=" + std::to_string(c.filesSeen));
    out("ABSENCE_PRUNED_DIRS=" + std::to_string(c.prunedDirs));
    if (!c.allowed) {
        out("ABSENCE_REFUSED=" + c.refusal);
        return 3;
    }
    const std::vector<SymbolRef> defs = in.definitionsOf(subject);
    if (!defs.empty()) {
        out("ABSENCE_RESULT=PRESENT");
        for (const SymbolRef& d : defs)
            out(idx(in.universe().files[d.fileIdx].rel + ":" +
                        std::to_string(d.beginLine) + " " +
                        symbolKindName(d.kind),
                    0));
        return 0;
    }
    const std::vector<SymbolRef> ment = in.filesMentioning(subject);
    if (!ment.empty()) {
        out("ABSENCE_RESULT=NO_DEFINITION_BUT_MENTIONED_IN_" +
            std::to_string(ment.size()) + "_FILES");
        for (size_t i = 0; i < ment.size() && i < 20; ++i)
            out(idx(in.universe().files[ment[i].fileIdx].rel, i));
        return 0;
    }
    // Only reachable when allowed, i.e. the universe covered the repository.
    out("ABSENCE_RESULT=ABSENT_IN_WHOLE_REPOSITORY");
    return 0;
}

void usage() {
    out("rawr repo <subcommand> [options]");
    out("  scope                       print the universe and every exclusion");
    out("  index                       build and persist the index");
    out("  refresh                     re-index only what changed");
    out("  search <query>              repository-scale search");
    out("  context <query>             ranked context chunks");
    out("  symbol <name>               definitions and file-level references");
    out("  callers|callees|reachable <name>");
    out("  includes|dependents|impact <rel>");
    out("  absence <name>              presence/absence claim, scope-guarded");
    out("options: --root <dir> --cache <dir> --out <file> --file <rel>");
    out("         --limit N --scope <root>[,<root>]   (narrows; claims refused)");
}

}  // namespace

RepoCliResult runRepoIntelCli(const std::vector<std::string>& argv,
                              const std::string& defaultRoot) {
    RepoCliResult res;
    if (argv.empty()) {
        usage();
        res.exitCode = 64;
        return res;
    }
    const Args a = parse(argv);
    const UniversePolicy p = policyFrom(a, defaultRoot);

    RepositoryIntelligence in;

    if (a.sub == "help" || a.sub == "--help") {
        usage();
        return res;
    }

    const bool needsIndex =
        a.sub != "scope" && a.sub != "index" && a.sub != "help";
    if (a.sub == "index" || a.sub == "refresh") {
        if (a.sub == "refresh") {
            std::string err;
            if (!in.load(a.cache + "/rawrxd_repo.rix", &err)) {
                out("REFRESH_RESULT=FAIL NO_INDEX (" + err +
                    ") -- run `rawr repo index` first");
                res.exitCode = 4;
                return res;
            }
        } else {
            in.build(p, 0);
        }
    } else if (needsIndex) {
        in.build(p, 0);
    } else {
        in.build(p, 0);
    }

    printUniverse(in);

    if (a.sub == "scope" || a.sub == "index") {
        if (a.sub == "index") {
            std::string err;
            if (!in.save(a.cache + "/rawrxd_repo.rix", &err)) {
                out("INDEX_SAVE=FAIL " + err);
                res.exitCode = 4;
                return res;
            }
            out("INDEX_SAVE=OK path=" + a.cache + "/rawrxd_repo.rix");
            out("INDEX_BYTES=" + std::to_string(in.stats().indexBytesOnDisk));
        }
        out("RESULT=OK");
        return res;
    }

    if (a.sub == "refresh") {
        const IncrementalDelta d = in.refresh();
        out("REFRESH_ADDED=" + std::to_string(d.added));
        out("REFRESH_REMOVED=" + std::to_string(d.removed));
        out("REFRESH_MODIFIED=" + std::to_string(d.modified));
        out("REFRESH_UNCHANGED=" + std::to_string(d.unchanged));
        out("REFRESH_REINDEXED=" + std::to_string(d.reindexed));
        out("REFRESH_REUSED=" + std::to_string(d.reused));
        out("REFRESH_MS=" + std::to_string(static_cast<long long>(d.incrMs)));
        for (const std::string& r : d.reindexedPaths) out("REFRESH_REINDEXED_FILE=" + r);
        for (const std::string& r : d.removedPaths) out("REFRESH_REMOVED_FILE=" + r);
        std::string err;
        in.save(a.cache + "/rawrxd_repo.rix", &err);
        out("RESULT=OK");
        return res;
    }

    if (a.positional.empty()) {
        usage();
        res.exitCode = 64;
        return res;
    }
    const std::string subject = a.positional[0];

    if (a.sub == "search") {
        const std::vector<SearchHit> hits = in.search(subject, a.limit);
        out("SEARCH_HITS=" + std::to_string(hits.size()));
        for (size_t i = 0; i < hits.size(); ++i)
            out(idx(hits[i].rel + ":" + std::to_string(hits[i].line) +
                        " token=" + hits[i].matched, i));
        out("RESULT=OK");
        return res;
    }
    if (a.sub == "context") {
        const std::vector<RankedChunk> c =
            in.rankContext(subject, a.file, a.limit);
        out("CONTEXT_CHUNKS=" + std::to_string(c.size()));
        for (size_t i = 0; i < c.size(); ++i)
            out(idx(c[i].rel + ":" + std::to_string(c[i].beginLine) + "-" +
                        std::to_string(c[i].endLine) + " " + c[i].qualified +
                        " why=" + c[i].why, i));
        out("RESULT=OK");
        return res;
    }
    if (a.sub == "symbol") {
        const std::vector<SymbolRef> defs = in.definitionsOf(subject);
        out("DEFINITIONS=" + std::to_string(defs.size()));
        for (size_t i = 0; i < defs.size() && i < a.limit; ++i)
            out(idx(in.universe().files[defs[i].fileIdx].rel + ":" +
                        std::to_string(defs[i].beginLine) + " " +
                        symbolKindName(defs[i].kind) + " " + defs[i].qualified,
                    i));
        const std::vector<Location> refs = in.referencesTo(subject, a.limit);
        out("REFERENCING_FILES=" + std::to_string(refs.size()));
        for (size_t i = 0; i < refs.size() && i < a.limit; ++i)
            out(idx(refs[i].rel + ":" + std::to_string(refs[i].line), i));
        out("RESULT=OK");
        return res;
    }
    if (a.sub == "callers") {
        const std::vector<SymbolRef> v = in.callersOf(subject);
        out("CALLERS=" + std::to_string(v.size()));
        for (size_t i = 0; i < v.size() && i < a.limit; ++i)
            out(idx(in.universe().files[v[i].fileIdx].rel + ":" +
                        std::to_string(v[i].beginLine) + " " + v[i].qualified, i));
        out("RESULT=OK");
        return res;
    }
    if (a.sub == "callees") {
        const std::vector<SymbolRef> v = in.calleesOf(subject);
        out("CALLEES=" + std::to_string(v.size()));
        for (size_t i = 0; i < v.size() && i < a.limit; ++i) out(idx(v[i].name, i));
        out("RESULT=OK");
        return res;
    }
    if (a.sub == "reachable") {
        const std::vector<RankedChunk> v = in.reachableFrom(subject, 5, a.limit);
        out("REACHABLE=" + std::to_string(v.size()));
        for (size_t i = 0; i < v.size(); ++i)
            out(idx(v[i].rel + ":" + std::to_string(v[i].beginLine) + " hops=" +
                        std::to_string(v[i].hopDistance) + " " + v[i].why, i));
        out("RESULT=OK");
        return res;
    }
    if (a.sub == "includes") {
        const std::vector<IncludeEdge> v = in.includesOf(subject);
        out("INCLUDES=" + std::to_string(v.size()));
        for (size_t i = 0; i < v.size(); ++i)
            out(idx(v[i].spelling + (v[i].angled ? " <>" : " \"\"") + " line=" +
                        std::to_string(v[i].line),
                    i));
        const std::vector<std::string> t = in.transitiveIncludes(subject);
        out("TRANSITIVE_INCLUDES=" + std::to_string(t.size()));
        for (size_t i = 0; i < t.size() && i < a.limit; ++i) out(idx(t[i], i));
        out("RESULT=OK");
        return res;
    }
    if (a.sub == "dependents") {
        const std::vector<std::string> t = in.transitiveDependents(subject);
        out("TRANSITIVE_DEPENDENTS=" + std::to_string(t.size()));
        for (size_t i = 0; i < t.size() && i < a.limit; ++i) out(idx(t[i], i));
        out("RESULT=OK");
        return res;
    }
    if (a.sub == "impact") {
        const std::vector<RankedChunk> v = in.changeImpact(subject, a.limit);
        out("IMPACT=" + std::to_string(v.size()));
        for (size_t i = 0; i < v.size(); ++i)
            out(idx(v[i].rel + " why=" + v[i].why, i));
        out("RESULT=OK");
        return res;
    }
    if (a.sub == "absence") {
        res.exitCode = cmdAbsence(in, subject);
        return res;
    }

    out("unknown `rawr repo` subcommand: " + a.sub);
    usage();
    res.exitCode = 64;
    return res;
}

}  // namespace repointel
}  // namespace rawrxd