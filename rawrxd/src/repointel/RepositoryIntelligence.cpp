// ============================================================================
// RepositoryIntelligence.cpp â€” RAWRXD_REPOSITORY_INTELLIGENCE_001
//
// Phases, in order:
//
//   1. buildUniverse â€” filesystem facts only. No git, no glob assumptions, and
//      every excluded directory is still enumerated so its size is reported.
//   2. parseAll      â€” one analyzeSource() per file across N threads. Each
//      thread writes only its own slots: no lock, no contention.
//   3. mergeParsed   â€” strictly sequential in fileIdx order, which is sorted by
//      repo-relative path. Identifier tables, chunk tables, the symbol table,
//      the call graph, the include graph and the search index are all built
//      here. That single-threaded phase is what makes the result reproducible.
//   4. finalizeStats â€” every number is counted. None is assumed.
//
// Every postings list is sorted after the merge, so the persisted payload does
// not depend on thread count or on thread scheduling.
// ============================================================================
#include "repointel/RepositoryIntelligence.hpp"

#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <unordered_set>

namespace rawrxd {
namespace repointel {
namespace {

using Clock = std::chrono::steady_clock;

double msSince(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

std::string lowerAscii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

void splitTokens(const std::string& s, std::vector<std::string>& out,
                 size_t minLen) {
    std::string cur;
    for (char c : s) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_') {
            cur.push_back(c);
        } else {
            if (cur.size() >= minLen) out.push_back(lowerAscii(cur));
            cur.clear();
        }
    }
    if (cur.size() >= minLen) out.push_back(lowerAscii(cur));
}

uint64_t peakWorkingSetBytes() {
    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
        return static_cast<uint64_t>(pmc.PeakWorkingSetSize);
    return 0;
}

std::string dirOf(const std::string& p) {
    const size_t cut = p.find_last_of("/\\");
    if (cut == std::string::npos) return std::string();
    return p.substr(0, cut);
}

std::string baseOf(const std::string& p) {
    const size_t cut = p.find_last_of("/\\");
    if (cut == std::string::npos) return p;
    return p.substr(cut + 1);
}

std::string stemOf(const std::string& p) {
    std::string b = baseOf(p);
    const size_t dot = b.find_last_of('.');
    if (dot == std::string::npos) return b;
    return b.substr(0, dot);
}

double symbolKindWeight(SymbolKind k) {
    switch (k) {
        case SymbolKind::Function:  return 1.0;
        case SymbolKind::Method:    return 1.0;
        case SymbolKind::Class:     return 0.95;
        case SymbolKind::Struct:    return 0.9;
        case SymbolKind::Enum:      return 0.8;
        case SymbolKind::Namespace: return 0.7;
        case SymbolKind::Macro:     return 0.6;
        case SymbolKind::TypeAlias: return 0.6;
        case SymbolKind::Field:     return 0.4;
        case SymbolKind::Variable:  return 0.35;
        default:                    return 0.2;
    }
}

// --- fixed-width serialization -------------------------------------------
constexpr uint32_t kMagic = 0x58524952u;  // "RIRX"
constexpr uint32_t kVersion = 4u;

void putU32(std::string& b, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        b.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}
void putU64(std::string& b, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        b.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}
void putStr(std::string& b, const std::string& s) {
    putU32(b, static_cast<uint32_t>(s.size()));
    b.append(s);
}

struct Reader {
    const std::string& b;
    size_t             p = 0;
    bool               ok = true;
    explicit Reader(const std::string& s, size_t start = 0) : b(s), p(start) {}
    uint32_t u32() {
        if (p + 4 > b.size()) { ok = false; return 0; }
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i)
            v |= static_cast<uint32_t>(static_cast<unsigned char>(b[p + i]))
                 << (8 * i);
        p += 4;
        return v;
    }
    uint64_t u64() {
        if (p + 8 > b.size()) { ok = false; return 0; }
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v |= static_cast<uint64_t>(static_cast<unsigned char>(b[p + i]))
                 << (8 * i);
        p += 8;
        return v;
    }
    std::string str() {
        const uint32_t n = u32();
        if (!ok || p + n > b.size()) { ok = false; return std::string(); }
        std::string s = b.substr(p, n);
        p += n;
        return s;
    }
};

}  // namespace

std::vector<std::string> tokenizeQuery(const std::string& query) {
    std::vector<std::string> raw;
    splitTokens(query, raw, 2);
    std::vector<std::string> out;
    out.reserve(raw.size());
    for (std::string& t : raw) out.push_back(lowerAscii(t));
    return out;
}

RepositoryIntelligence::RepositoryIntelligence() = default;
RepositoryIntelligence::~RepositoryIntelligence() = default;

uint32_t RepositoryIntelligence::internIdent(const std::string& name) {
    auto it = m_identIds.find(name);
    if (it != m_identIds.end()) return it->second;
    const uint32_t id = static_cast<uint32_t>(m_identNames.size());
    m_identIds.emplace(name, id);
    m_identNames.push_back(name);
    m_identPostings.emplace_back();
    return id;
}

uint32_t RepositoryIntelligence::internSearchToken(const std::string& tok) {
    auto it = m_tokenIds.find(tok);
    if (it != m_tokenIds.end()) return it->second;
    const uint32_t id = static_cast<uint32_t>(m_postings.size());
    m_tokenIds.emplace(tok, id);
    m_postings.emplace_back();
    m_tokens.push_back(tok);
    return id;
}

bool RepositoryIntelligence::build(const UniversePolicy& policy, uint32_t threads) {
    const auto tAll = Clock::now();

    const auto tWalk = Clock::now();
    m_universe = buildUniverse(policy);
    m_stats = IndexStats{};
    m_stats.walkMs = msSince(tWalk);

    m_narrowed = policy.narrowed || m_universe.narrowed;
    m_scopeLabel = policy.scopeLabel;

    uint32_t nThreads = threads ? threads : std::thread::hardware_concurrency();
    if (nThreads == 0) nThreads = 1;
    if (nThreads > 32) nThreads = 32;
    m_stats.threads = nThreads;

    parseAll(false);

    const auto tMerge = Clock::now();
    mergeParsed();
    mergeCallGraph();
    resolveIncludeTargets();
    finalizeStats();
    m_stats.mergeMs = msSince(tMerge);

    m_stats.peakWorkingSetBytes = peakWorkingSetBytes();
    m_stats.totalMs = msSince(tAll);
    m_ready = m_universe.rootExists;
    // A completed build is an authoritative manifest, so refresh() can diff
    // against it without a prior save(). That is what makes the incremental
    // path testable against the same tree the full build just read.
    snapshotManifest();
    return m_ready;
}

bool RepositoryIntelligence::parseAll(bool reuse) {
    const auto tParse = Clock::now();

    const size_t n = m_universe.files.size();
    m_parsed.assign(n, ParsedFile{});

    std::vector<uint8_t> reuseFlag(n, 0);

    if (reuse && !m_savedRel.empty()) {
        std::unordered_map<std::string, size_t> savedByRel;
        savedByRel.reserve(m_savedRel.size() * 2);
        for (size_t i = 0; i < m_savedRel.size(); ++i)
            savedByRel.emplace(m_savedRel[i], i);

        for (size_t i = 0; i < n; ++i) {
            const UniverseFile& f = m_universe.files[i];
            auto it = savedByRel.find(f.rel);
            if (it == savedByRel.end()) {
                ++m_delta.added;
                continue;
            }
            const size_t s = it->second;
            if (m_savedSize[s] == f.size && m_savedMtime[s] == f.mtime) {
                reuseFlag[i] = 1;
                ++m_delta.unchanged;
                ++m_delta.reused;
                continue;
            }
            ++m_delta.hashVerified;
            if (!f.hash.empty() && f.hash == m_savedHash[s]) {
                reuseFlag[i] = 1;
                ++m_delta.unchanged;
                ++m_delta.reused;
            } else {
                ++m_delta.modified;
            }
        }
        std::unordered_set<std::string> nowPaths;
        nowPaths.reserve(n * 2);
        for (const UniverseFile& f : m_universe.files) nowPaths.insert(f.rel);
        for (const std::string& r : m_savedRel)
            if (nowPaths.find(r) == nowPaths.end()) {
                ++m_delta.removed;
                m_delta.removedPaths.push_back(r);
            }
    }

    std::atomic<uint32_t> cursor{0};
    std::vector<std::thread> pool;
    pool.reserve(m_stats.threads);
    for (uint32_t t = 0; t < m_stats.threads; ++t) {
        pool.emplace_back([&]() {
            for (;;) {
                const uint32_t i = cursor.fetch_add(1);
                if (i >= n) break;
                if (reuseFlag[i]) continue;

                const UniverseFile& uf = m_universe.files[i];
                ParsedFile&          pf = m_parsed[i];
                std::string          text;
                if (!readWholeFile(uf.abs, text)) continue;
                const FileAnalysis a = analyzeSource(text);
                if (!a.analyzed) continue;

                pf.ok = true;
                pf.uniqueIdents = a.uniqueIdents;
                pf.chunks = a.chunks;
                pf.symbols = a.symbols;
                pf.includes = a.includes;
                pf.calls = a.calls;
                pf.chunkIdentFlat = std::move(a.chunkIdents);
                pf.chunkIdentBegin =
                    std::vector<uint32_t>(a.chunkIdentCursor.begin(),
                                          a.chunkIdentCursor.end() - 1);
                pf.chunkIdentEnd =
                    std::vector<uint32_t>(a.chunkIdentCursor.begin() + 1,
                                          a.chunkIdentCursor.end());

                // Search tokens: identifiers, string-literal words and comment
                // words, deduped per file. Sorted so the merge is reproducible.
                std::vector<std::string> toks;
                toks.reserve(512);
                splitTokens(text, toks, 2);
                std::sort(toks.begin(), toks.end());
                toks.erase(std::unique(toks.begin(), toks.end()), toks.end());
                pf.tokens = std::move(toks);
            }
        });
    }
    for (std::thread& th : pool) th.join();

    for (size_t i = 0; i < n; ++i) {
        if (reuseFlag[i]) {
            ++m_stats.filesReused;
            ++m_delta.reused;
        } else {
            ++m_stats.filesIndexed;
            ++m_delta.reindexed;
            m_delta.reindexedPaths.push_back(m_universe.files[i].rel);
        }
    }

    m_stats.parseMs = msSince(tParse);
    return true;
}

void RepositoryIntelligence::mergeParsed() {
    m_identNames.clear();
    m_identIds.clear();
    m_identPostings.clear();
    m_tokens.clear();
    m_tokenIds.clear();
    m_postings.clear();
    m_chunks.clear();
    m_symbols.clear();
    m_callEdges.clear();
    m_defByName.clear();
    m_defByQualified.clear();
    m_defByLower.clear();

    m_files.assign(m_universe.files.size(), IndexedFile{});

    for (size_t i = 0; i < m_universe.files.size(); ++i) {
        IndexedFile&   idx = m_files[i];
        const ParsedFile& pf = m_parsed[i];
        idx.fileIdx = static_cast<uint32_t>(i);
        if (!pf.ok) continue;

        std::unordered_map<uint32_t, uint32_t> g;
        g.reserve(pf.uniqueIdents.size() * 2);
        for (uint32_t k = 0; k < pf.uniqueIdents.size(); ++k)
            g.emplace(k, internIdent(pf.uniqueIdents[k]));

        const uint32_t chunkBase = static_cast<uint32_t>(m_chunks.size());
        for (size_t c = 0; c < pf.chunks.size(); ++c) {
            const FileChunk& lc = pf.chunks[c];
            ChunkRef gc;
            gc.qualified = lc.qualified;
            gc.name = lc.name;
            gc.scope = lc.scope;
            gc.symbolKind = lc.symbolKind;
            gc.fileIdx = static_cast<uint32_t>(i);
            gc.beginLine = lc.beginLine;
            gc.endLine = lc.endLine;
            gc.depth = lc.depth;
            if (c < pf.chunkIdentBegin.size()) {
                const uint32_t b = pf.chunkIdentBegin[c];
                const uint32_t e = pf.chunkIdentEnd[c];
                if (e <= pf.chunkIdentFlat.size() && b <= e) {
                    gc.idents.reserve(e - b);
                    for (uint32_t t = b; t < e; ++t) {
                        auto it = g.find(pf.chunkIdentFlat[t]);
                        if (it != g.end()) gc.idents.push_back(it->second);
                    }
                    std::sort(gc.idents.begin(), gc.idents.end());
                    gc.idents.erase(
                        std::unique(gc.idents.begin(), gc.idents.end()),
                        gc.idents.end());
                }
            }
            m_chunks.push_back(std::move(gc));
        }
        (void)chunkBase;

        for (const FileSymbol& s : pf.symbols) {
            SymbolRef sr;
            sr.name = s.name;
            sr.qualified = s.qualified;
            sr.kind = s.kind;
            sr.fileIdx = static_cast<uint32_t>(i);
            // FileSymbol::chunkIndex is local to the file; translate it to a
            // global chunk index.
            sr.chunkIdx = (s.chunkIndex == 0xFFFFFFFFu)
                              ? 0xFFFFFFFFu
                              : (static_cast<uint32_t>(m_chunks.size() -
                                                       pf.chunks.size()) +
                                 s.chunkIndex);
            sr.beginLine = s.beginLine;
            sr.endLine = s.endLine;
            const uint32_t si = static_cast<uint32_t>(m_symbols.size());
            m_symbols.push_back(std::move(sr));
            m_defByName[m_symbols[si].name].push_back(si);
            m_defByQualified[m_symbols[si].qualified].push_back(si);
            m_defByLower[lowerAscii(m_symbols[si].name)].push_back(si);
        }

        for (const auto& ce : pf.calls) {
            if (ce.first >= pf.chunks.size()) continue;
            auto it = g.find(ce.second);
            if (it == g.end()) continue;
            CallEdge e;
            e.callerChunk = static_cast<uint32_t>(m_chunks.size() -
                                                   pf.chunks.size() + ce.first);
            e.calleeIdent = it->second;
            m_callEdges.push_back(e);
        }

        idx.includes = pf.includes;
        idx.callCount = static_cast<uint32_t>(pf.calls.size());
        idx.chunkCount = static_cast<uint32_t>(pf.chunks.size());
        idx.symbolCount = static_cast<uint32_t>(pf.symbols.size());

        // File-level identifier incidence: every identifier the file mentioned, so
    // a reference in a header is findable even when the file has no chunks.
    for (size_t k = 0; k < pf.uniqueIdents.size(); ++k)
        idx.globalIdents.push_back(g[static_cast<uint32_t>(k)]);
    std::sort(idx.globalIdents.begin(), idx.globalIdents.end());
    idx.globalIdents.erase(
        std::unique(idx.globalIdents.begin(), idx.globalIdents.end()),
        idx.globalIdents.end());

        for (const std::string& tok : pf.tokens) {
            const uint32_t tid = internSearchToken(tok);
            m_postings[tid].push_back({static_cast<uint32_t>(i), 0xFFFFFFFFu});
        }

        m_stats.bytesIndexed += m_universe.files[i].size;
        m_stats.linesIndexed += m_universe.files[i].lineCount;
    }

    for (const IndexedFile& f : m_files)
        for (const uint32_t gid : f.globalIdents)
            m_identPostings[gid].push_back({f.fileIdx, 0xFFFFFFFFu});

    for (auto& v : m_identPostings) {
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
    }
    for (auto& v : m_postings) {
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
    }
}

void RepositoryIntelligence::mergeCallGraph() {
    m_callees.clear();
    m_callers.clear();
    m_identDefChunk.clear();
    for (const CallEdge& e : m_callEdges) {
        m_callees[e.callerChunk].push_back(e.calleeIdent);
        m_callers[e.calleeIdent].push_back(e.callerChunk);
    }
    for (auto& kv : m_callees) {
        std::sort(kv.second.begin(), kv.second.end());
        kv.second.erase(std::unique(kv.second.begin(), kv.second.end()),
                        kv.second.end());
    }
    for (auto& kv : m_callers) {
        std::sort(kv.second.begin(), kv.second.end());
        kv.second.erase(std::unique(kv.second.begin(), kv.second.end()),
                        kv.second.end());
    }
    // Prefer a definition that actually has a body, then the lowest chunk
    // index, so the mapping is deterministic.
    for (const SymbolRef& s : m_symbols) {
        if (s.chunkIdx == 0xFFFFFFFFu || s.chunkIdx >= m_chunks.size()) continue;
        if (s.kind != SymbolKind::Function && s.kind != SymbolKind::Method &&
            s.kind != SymbolKind::Macro)
            continue;
        auto idIt = m_identIds.find(s.name);
        if (idIt == m_identIds.end()) continue;
        const uint32_t gid = idIt->second;
        const bool existingHasCallees =
            m_callees.count(s.chunkIdx) != 0;
        auto cur = m_identDefChunk.find(gid);
        if (cur == m_identDefChunk.end()) {
            m_identDefChunk.emplace(gid, s.chunkIdx);
        } else if (!existingHasCallees && m_callees.count(cur->second)) {
            m_identDefChunk[gid] = s.chunkIdx;
        } else if (existingHasCallees == (m_callees.count(cur->second) != 0) &&
                   s.chunkIdx < cur->second) {
            m_identDefChunk[gid] = s.chunkIdx;
        }
    }
}

void RepositoryIntelligence::resolveIncludeTargets() {
    // Two indexes over repo-relative paths: exact, and basename. A quoted
    // include resolves only against a real file path; an angled include may
    // resolve against the include-path directories the build declares.
    std::unordered_map<std::string, uint32_t> byRel;
    std::unordered_map<std::string, std::vector<uint32_t>> byBase;
    for (size_t i = 0; i < m_universe.files.size(); ++i) {
        const std::string& rel = m_universe.files[i].rel;
        byRel.emplace(rel, static_cast<uint32_t>(i));
        byBase[baseOf(rel)].push_back(static_cast<uint32_t>(i));
    }

    for (IndexedFile& f : m_files) {
        const std::string selfDir = dirOf(m_universe.files[f.fileIdx].rel);
        for (IncludeEdge& inc : f.includes) {
            auto direct = byRel.find(inc.spelling);
            if (direct != byRel.end()) {
                inc.resolvedFileIdx = direct->second;
                continue;
            }
            if (!selfDir.empty()) {
                const std::string rel = selfDir + "/" + inc.spelling;
                auto up = byRel.find(rel);
                if (up != byRel.end()) {
                    inc.resolvedFileIdx = up->second;
                    continue;
                }
                auto parent = byRel.find(dirOf(selfDir) == std::string()
                                              ? inc.spelling
                                              : dirOf(selfDir) + "/" +
                                                    inc.spelling);
                if (parent != byRel.end()) {
                    inc.resolvedFileIdx = parent->second;
                    continue;
                }
            }
            auto base = byBase.find(inc.spelling);
            if (base != byBase.end() && !base->second.empty()) {
                // Ambiguous by construction (many headers share a basename);
                // pick the shallowest path so the choice is deterministic.
                uint32_t best = base->second.front();
                for (const uint32_t cand : base->second) {
                    const size_t d = dirOf(m_universe.files[cand].rel).size();
                    const size_t db = dirOf(m_universe.files[best].rel).size();
                    if (d < db ||
                        (d == db &&
                         m_universe.files[cand].rel < m_universe.files[best].rel))
                        best = cand;
                }
                inc.resolvedFileIdx = best;
            }
        }
    }
}

void RepositoryIntelligence::finalizeStats() {
    m_stats.filesInUniverse = m_universe.files.size();
    m_stats.chunks = m_chunks.size();
    m_stats.symbols = m_symbols.size();
    m_stats.identifiers = m_identNames.size();
    m_stats.searchTokens = m_tokens.size();
    m_stats.callEdges = m_callEdges.size();
    m_stats.prunedDirs = m_universe.pruned.size();
    for (const PrunedDir& p : m_universe.pruned) {
        m_stats.prunedFilesBelow += p.filesBelow;
        m_stats.prunedBytesBelow += p.bytesBelow;
    }
    m_stats.truncatedFiles = m_universe.truncated;
    m_stats.unreadableFiles = m_universe.unreadable;
    uint64_t inc = 0, res = 0;
    for (const IndexedFile& f : m_files) {
        for (const IncludeEdge& e : f.includes) {
            ++inc;
            if (e.resolvedFileIdx != 0xFFFFFFFFu) ++res;
        }
    }
    m_stats.includeEdges = inc;
    m_stats.resolvedIncludes = res;
    m_stats.unresolvedIncludes = inc - res;
    uint64_t postings = 0;
    for (const auto& v : m_postings) postings += v.size();
    m_stats.postingEntries = postings;

    // Include cycles, measured over the resolved graph only.
    std::vector<std::vector<uint32_t>> adj(m_files.size());
    for (size_t i = 0; i < m_files.size(); ++i) {
        for (const IncludeEdge& e : m_files[i].includes) {
            if (e.resolvedFileIdx < m_files.size())
                adj[i].push_back(e.resolvedFileIdx);
        }
        std::sort(adj[i].begin(), adj[i].end());
        adj[i].erase(std::unique(adj[i].begin(), adj[i].end()), adj[i].end());
    }
    uint64_t cycleEdges = 0;
    for (size_t i = 0; i < adj.size(); ++i) {
        for (const uint32_t t : adj[i]) {
            if (std::binary_search(adj[t].begin(), adj[t].end(),
                                   static_cast<uint32_t>(i)))
                ++cycleEdges;
        }
    }
    m_stats.includeCycles = cycleEdges / 2;
}

void RepositoryIntelligence::rebuildLookupTables() {
    m_defByName.clear();
    m_defByQualified.clear();
    m_defByLower.clear();
    for (size_t i = 0; i < m_symbols.size(); ++i) {
        m_defByName[m_symbols[i].name].push_back(static_cast<uint32_t>(i));
        m_defByQualified[m_symbols[i].qualified].push_back(
            static_cast<uint32_t>(i));
        m_defByLower[lowerAscii(m_symbols[i].name)].push_back(
            static_cast<uint32_t>(i));
    }
    m_identPostings.assign(m_identNames.size(), {});
    for (const IndexedFile& f : m_files) {
        for (const uint32_t gid : f.globalIdents)
            m_identPostings[gid].push_back({f.fileIdx, 0xFFFFFFFFu});
    }
    for (auto& v : m_identPostings) {
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
    }
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

namespace {
void sortSymbols(std::vector<SymbolRef>& v) {
    std::sort(v.begin(), v.end(),
              [](const SymbolRef& a, const SymbolRef& b) {
                  if (a.fileIdx != b.fileIdx) return a.fileIdx < b.fileIdx;
                  if (a.beginLine != b.beginLine) return a.beginLine < b.beginLine;
                  return a.name < b.name;
              });
}
}  // namespace

std::vector<SymbolRef> RepositoryIntelligence::definitionsOf(
    const std::string& name) const {
    std::vector<SymbolRef> out;
    auto it = m_defByName.find(name);
    if (it == m_defByName.end()) it = m_defByLower.find(lowerAscii(name));
    if (it == m_defByName.end() || it == m_defByLower.end()) return out;
    for (const uint32_t si : it->second) out.push_back(m_symbols[si]);
    sortSymbols(out);
    return out;
}

std::vector<SymbolRef> RepositoryIntelligence::definitionsOfQualified(
    const std::string& q) const {
    std::vector<SymbolRef> out;
    auto it = m_defByQualified.find(q);
    if (it == m_defByQualified.end()) return out;
    for (const uint32_t si : it->second) out.push_back(m_symbols[si]);
    sortSymbols(out);
    return out;
}

std::vector<SymbolRef> RepositoryIntelligence::filesMentioning(
    const std::string& name) const {
    std::vector<SymbolRef> out;
    auto it = m_identIds.find(name);
    if (it == m_identIds.end()) return out;
    const uint32_t gid = it->second;
    if (gid >= m_identPostings.size()) return out;
    for (const Posting& p : m_identPostings[gid]) {
        if (p.fileIdx >= m_universe.files.size()) continue;
        SymbolRef sr;
        sr.name = name;
        sr.qualified = name;
        sr.kind = SymbolKind::Unknown;
        sr.fileIdx = p.fileIdx;
        out.push_back(sr);
    }
    return out;
}

std::vector<Location> RepositoryIntelligence::referencesTo(const std::string& name,
                                                          uint32_t limit) const {
    std::vector<Location> out;
    auto it = m_identIds.find(name);
    if (it == m_identIds.end()) return out;
    const uint32_t gid = it->second;
    if (gid >= m_identPostings.size()) return out;
    // File-level incidence first; line-level positions are located by
    // re-reading only the files that mention the name.
    for (const Posting& p : m_identPostings[gid]) {
        if (out.size() >= limit) break;
        if (p.fileIdx >= m_universe.files.size()) continue;
        const UniverseFile& uf = m_universe.files[p.fileIdx];
        Location loc;
        loc.rel = uf.rel;
        std::string text;
        if (readWholeFile(uf.abs, text)) {
            uint32_t line = 1;
            size_t   at = 0;
            while (at < text.size()) {
                const size_t nl = text.find('\n', at);
                const size_t end = (nl == std::string::npos) ? text.size() : nl;
                const std::string ln = text.substr(at, end - at);
                if (ln.find(name) != std::string::npos) {
                    loc.line = line;
                    loc.snippet = ln.size() > 200 ? ln.substr(0, 200) : ln;
                    break;
                }
                if (nl == std::string::npos) break;
                at = nl + 1;
                ++line;
            }
        }
        out.push_back(loc);
    }
    return out;
}

std::vector<SymbolRef> RepositoryIntelligence::callersOf(
    const std::string& name) const {
    std::vector<SymbolRef> out;
    auto it = m_identIds.find(name);
    if (it == m_identIds.end()) return out;
    auto c = m_callers.find(it->second);
    if (c == m_callers.end()) return out;
    for (const uint32_t chunk : c->second) {
        if (chunk >= m_chunks.size()) continue;
        const ChunkRef& ch = m_chunks[chunk];
        SymbolRef sr;
        sr.name = ch.name;
        sr.qualified = ch.qualified;
        sr.kind = ch.symbolKind;
        sr.fileIdx = ch.fileIdx;
        sr.chunkIdx = chunk;
        sr.beginLine = ch.beginLine;
        sr.endLine = ch.endLine;
        out.push_back(sr);
    }
    sortSymbols(out);
    out.erase(std::unique(out.begin(), out.end(),
                          [](const SymbolRef& a, const SymbolRef& b) {
                              return a.fileIdx == b.fileIdx &&
                                     a.beginLine == b.beginLine;
                          }),
              out.end());
    return out;
}

std::vector<SymbolRef> RepositoryIntelligence::calleesOf(
    const std::string& name) const {
    std::vector<SymbolRef> out;
    const std::vector<SymbolRef> defs = definitionsOf(name);
    if (defs.empty()) return out;
    for (const SymbolRef& d : defs) {
        if (d.chunkIdx == 0xFFFFFFFFu || d.chunkIdx >= m_chunks.size())
            continue;
        auto c = m_callees.find(d.chunkIdx);
        if (c == m_callees.end()) continue;
        for (const uint32_t ident : c->second) {
            if (ident >= m_identNames.size()) continue;
            SymbolRef sr;
            sr.name = m_identNames[ident];
            sr.qualified = m_identNames[ident];
            sr.kind = SymbolKind::Function;
            sr.fileIdx = 0xFFFFFFFFu;
            out.push_back(sr);
        }
    }
    sortSymbols(out);
    out.erase(std::unique(out.begin(), out.end(),
                          [](const SymbolRef& a, const SymbolRef& b) {
                              return a.name == b.name;
                          }),
              out.end());
    return out;
}

std::vector<RankedChunk> RepositoryIntelligence::reachableFrom(
    const std::string& name, uint32_t maxHops, uint32_t limit) const {
    std::vector<RankedChunk> out;

    auto idIt = m_identIds.find(name);
    if (idIt == m_identIds.end()) {
        idIt = m_identIds.find(lowerAscii(name));
        if (idIt == m_identIds.end()) return out;
    }
    const uint32_t rootIdent = idIt->second;

    std::vector<uint32_t> rootChunks;
    for (const SymbolRef& r : definitionsOf(name)) {
        if (r.chunkIdx == 0xFFFFFFFFu || r.chunkIdx >= m_chunks.size()) continue;
        rootChunks.push_back(r.chunkIdx);
    }
    auto defIt = m_identDefChunk.find(rootIdent);
    if (defIt != m_identDefChunk.end() &&
        std::find(rootChunks.begin(), rootChunks.end(), defIt->second) ==
            rootChunks.end())
        rootChunks.push_back(defIt->second);
    std::sort(rootChunks.begin(), rootChunks.end());
    rootChunks.erase(std::unique(rootChunks.begin(), rootChunks.end()),
                     rootChunks.end());
    if (rootChunks.empty()) return out;

    std::unordered_map<uint32_t, uint32_t> seen;
    struct Q {
        uint32_t chunk;
        uint32_t hops;
    };
    std::vector<Q> queue;
    for (const uint32_t c : rootChunks) {
        seen.emplace(c, 0u);
        queue.push_back({c, 0u});
    }

    // Forward transitive closure: caller chunk -> callee identifier -> the
    // chunk that defines it. A callee with no resolvable definition (a system
    // function, a macro, an overload set with no indexed body) ends that path
    // rather than fanning out to every unrelated user of the same name.
    for (size_t head = 0; head < queue.size() && out.size() < limit; ++head) {
        const Q cur = queue[head];
        if (cur.hops >= maxHops) continue;
        auto c = m_callees.find(cur.chunk);
        if (c == m_callees.end()) continue;
        for (const uint32_t ident : c->second) {
            auto d = m_identDefChunk.find(ident);
            if (d == m_identDefChunk.end()) continue;
            const uint32_t next = d->second;
            if (next >= m_chunks.size() || seen.count(next)) continue;
            seen.emplace(next, cur.hops + 1);
            const ChunkRef& ch = m_chunks[next];
            if (ch.fileIdx >= m_universe.files.size()) continue;
            if (ch.qualified.empty() && ch.name.empty()) continue;
            RankedChunk rc;
            rc.rel = m_universe.files[ch.fileIdx].rel;
            rc.qualified = ch.qualified;
            rc.beginLine = ch.beginLine;
            rc.endLine = ch.endLine;
            rc.hopDistance = cur.hops + 1;
            rc.why = "transitively calls " + name;
            out.push_back(rc);
            queue.push_back({next, cur.hops + 1});
            if (out.size() >= limit) break;
        }
    }
    return out;
}

std::vector<RankedChunk> RepositoryIntelligence::coCallersOf(
    const std::string& name, uint32_t limit) const {
    std::vector<RankedChunk> out;
    for (const SymbolRef& r : definitionsOf(name)) {
        if (r.chunkIdx == 0xFFFFFFFFu || r.chunkIdx >= m_chunks.size()) continue;
        auto c = m_callees.find(r.chunkIdx);
        if (c == m_callees.end()) continue;
        for (const uint32_t ident : c->second) {
            auto up = m_callers.find(ident);
            if (up == m_callers.end()) continue;
            for (const uint32_t chunk : up->second) {
                if (chunk >= m_chunks.size()) continue;
                const ChunkRef& ch = m_chunks[chunk];
                if (ch.fileIdx >= m_universe.files.size()) continue;
                RankedChunk rc;
                rc.rel = m_universe.files[ch.fileIdx].rel;
                rc.qualified = ch.qualified;
                rc.beginLine = ch.beginLine;
                rc.hopDistance = 1;
                rc.why = "also calls " +
                         (ident < m_identNames.size() ? m_identNames[ident]
                                                      : std::string("?"));
                out.push_back(rc);
                if (out.size() >= limit) return out;
            }
        }
    }
    return out;
}

std::vector<IncludeEdge> RepositoryIntelligence::includesOf(
    const std::string& rel) const {
    std::vector<IncludeEdge> out;
    std::unordered_map<std::string, uint32_t> byRel;
    for (size_t i = 0; i < m_universe.files.size(); ++i)
        byRel.emplace(m_universe.files[i].rel, static_cast<uint32_t>(i));
    auto it = byRel.find(rel);
    if (it == byRel.end()) return out;
    if (it->second >= m_files.size()) return out;
    out = m_files[it->second].includes;
    return out;
}

std::vector<std::string> RepositoryIntelligence::transitiveIncludes(
    const std::string& rel, uint32_t maxDepth) const {
    std::vector<std::string> out;
    std::unordered_set<uint32_t> visited;
    std::unordered_map<std::string, uint32_t> byRel;
    for (size_t i = 0; i < m_universe.files.size(); ++i)
        byRel.emplace(m_universe.files[i].rel, static_cast<uint32_t>(i));

    auto it = byRel.find(rel);
    if (it == byRel.end()) return out;
    struct Q {
        uint32_t idx;
        uint32_t depth;
    };
    std::vector<Q> queue{{it->second, 0u}};
    visited.insert(it->second);
    for (size_t head = 0; head < queue.size(); ++head) {
        const Q cur = queue[head];
        if (cur.depth >= maxDepth) continue;
        if (cur.idx >= m_files.size()) continue;
        for (const IncludeEdge& e : m_files[cur.idx].includes) {
            if (e.resolvedFileIdx == 0xFFFFFFFFu) continue;
            if (visited.insert(e.resolvedFileIdx).second) {
                out.push_back(m_universe.files[e.resolvedFileIdx].rel);
                queue.push_back({e.resolvedFileIdx, cur.depth + 1});
            }
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<std::string> RepositoryIntelligence::transitiveDependents(
    const std::string& rel, uint32_t maxDepth) const {
    std::vector<std::string> out;
    std::unordered_map<std::string, uint32_t> byRel;
    for (size_t i = 0; i < m_universe.files.size(); ++i)
        byRel.emplace(m_universe.files[i].rel, static_cast<uint32_t>(i));
    auto it = byRel.find(rel);
    if (it == byRel.end()) return out;

    std::vector<std::vector<uint32_t>> reverse(m_universe.files.size());
    for (size_t i = 0; i < m_files.size(); ++i)
        for (const IncludeEdge& e : m_files[i].includes)
            if (e.resolvedFileIdx != 0xFFFFFFFFu)
                reverse[e.resolvedFileIdx].push_back(static_cast<uint32_t>(i));
    for (auto& v : reverse) {
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
    }

    std::unordered_set<uint32_t> visited{it->second};
    struct Q {
        uint32_t idx;
        uint32_t depth;
    };
    std::vector<Q> queue{{it->second, 0u}};
    for (size_t head = 0; head < queue.size(); ++head) {
        const Q cur = queue[head];
        if (cur.depth >= maxDepth) continue;
        if (cur.idx >= reverse.size()) continue;
        for (const uint32_t dep : reverse[cur.idx]) {
            if (visited.insert(dep).second) {
                out.push_back(m_universe.files[dep].rel);
                queue.push_back({dep, cur.depth + 1});
            }
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<std::string> RepositoryIntelligence::includeCycles() const {
    std::vector<std::string> out;
    for (size_t i = 0; i < m_files.size(); ++i) {
        for (const IncludeEdge& e : m_files[i].includes) {
            if (e.resolvedFileIdx == 0xFFFFFFFFu) continue;
            if (e.resolvedFileIdx >= m_files.size()) continue;
            for (const IncludeEdge& back : m_files[e.resolvedFileIdx].includes) {
                if (back.resolvedFileIdx == static_cast<uint32_t>(i)) {
                    out.push_back(m_universe.files[i].rel + " -> " +
                                  m_universe.files[e.resolvedFileIdx].rel);
                }
            }
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

std::vector<RankedChunk> RepositoryIntelligence::changeImpact(
    const std::string& rel, uint32_t limit) const {
    std::vector<RankedChunk> out;
    const std::vector<std::string> dependents =
        transitiveDependents(rel, 64);
    for (const std::string& d : dependents) {
        RankedChunk rc;
        rc.rel = d;
        rc.why = "transitively includes " + rel;
        out.push_back(rc);
        if (out.size() >= limit) break;
    }
    for (const SymbolRef& s : definitionsOf(stemOf(rel))) {
        RankedChunk rc;
        rc.rel = m_universe.files[s.fileIdx].rel;
        rc.qualified = s.qualified;
        rc.beginLine = s.beginLine;
        rc.endLine = s.endLine;
        rc.why = "defines " + s.name;
        out.push_back(rc);
        if (out.size() >= limit) break;
    }
    return out;
}

std::vector<SearchHit> RepositoryIntelligence::search(const std::string& query,
                                                      uint32_t limit) const {
    const std::vector<std::string> qt = tokenizeQuery(query);
    if (qt.empty()) return {};

    struct Cand {
        uint32_t fileIdx;
        double   score;
    };
    std::unordered_map<uint32_t, double> scores;
    const double total = static_cast<double>(m_postings.size());
    for (const std::string& tok : qt) {
        auto it = m_tokenIds.find(tok);
        if (it == m_tokenIds.end()) continue;
        const uint32_t tid = it->second;
        const double df = static_cast<double>(m_postings[tid].size() + 1);
        const double idf = 1.0 + std::log((total + 1.0) / df);
        for (const Posting& p : m_postings[tid])
            scores[p.fileIdx] += idf;
    }

    struct Scored {
        uint32_t fileIdx;
        double   score;
    };
    std::vector<Scored> ranked;
    ranked.reserve(scores.size());
    for (const auto& kv : scores) ranked.push_back({kv.first, kv.second});
    std::sort(ranked.begin(), ranked.end(),
              [&](const Scored& a, const Scored& b) {
                  if (a.score != b.score) return a.score > b.score;
                  return m_universe.files[a.fileIdx].rel <
                         m_universe.files[b.fileIdx].rel;
              });

    std::vector<SearchHit> out;
    // The rarest query token is the most specific one; use it to place the
    // reported line for each hit.
    std::string anchor;
    uint32_t    anchorPostings = 0xFFFFFFFFu;
    for (const std::string& tok : qt) {
        auto it = m_tokenIds.find(tok);
        if (it == m_tokenIds.end()) continue;
        const uint32_t len = static_cast<uint32_t>(m_postings[it->second].size());
        if (len < anchorPostings) {
            anchorPostings = len;
            anchor = tok;
        }
    }

    for (const Scored& s : ranked) {
        if (out.size() >= limit) break;
        if (s.fileIdx >= m_universe.files.size()) continue;
        SearchHit h;
        h.rel = m_universe.files[s.fileIdx].rel;
        h.score = s.score;
        h.matched = anchor.empty() ? lowerAscii(query) : anchor;
        std::string text;
        if (!anchor.empty() && readWholeFile(m_universe.files[s.fileIdx].abs, text)) {
            const size_t at = text.find(anchor);
            uint32_t    line = 1;
            if (at != std::string::npos) {
                for (size_t k = 0; k < at; ++k)
                    if (text[k] == '\n') ++line;
                const size_t eol = text.find('\n', at);
                h.line = line;
            }
        }
        out.push_back(h);
    }
    return out;
}

std::vector<RankedChunk> RepositoryIntelligence::rankContext(
    const std::string& query, const std::string& activeFileRel,
    uint32_t maxChunks) const {
    const std::vector<std::string> qt = tokenizeQuery(query);
    if (qt.empty()) return {};

    std::unordered_map<uint32_t, double> tokenWeight;
    const double total = static_cast<double>(m_postings.size());
    for (const std::string& tok : qt) {
        auto it = m_tokenIds.find(tok);
        if (it == m_tokenIds.end()) continue;
        const double df = static_cast<double>(m_postings[it->second].size() + 1);
        tokenWeight[it->second] = 1.0 + std::log((total + 1.0) / df);
    }
    std::unordered_map<uint32_t, double> identWeight;
    for (const std::string& tok : qt) {
        auto it = m_identIds.find(tok);
        if (it == m_identIds.end()) continue;
        const double df =
            static_cast<double>(m_identPostings[it->second].size() + 1);
        identWeight[it->second] = 2.0 * (1.0 + std::log((total + 1.0) / df));
    }

    // Call-graph proximity. A chunk one hop from a symbol the query names is
    // more likely to be relevant than an unrelated chunk with equal lexical
    // overlap, so proximity is computed from the real call edges.
    std::unordered_map<uint32_t, uint32_t> hop;
    for (const std::string& tok : qt) {
        const std::vector<SymbolRef> defs = definitionsOf(tok);
        for (const SymbolRef& d : defs) {
            if (d.chunkIdx == 0xFFFFFFFFu || d.chunkIdx >= m_chunks.size())
                continue;
            hop.emplace(d.chunkIdx, 0u);
            auto cid = m_identIds.find(tok);
            if (cid == m_identIds.end()) continue;
            auto up = m_callers.find(cid->second);
            if (up == m_callers.end()) continue;
            for (const uint32_t callerChunk : up->second)
                if (callerChunk < m_chunks.size() && !hop.count(callerChunk))
                    hop.emplace(callerChunk, 1u);
        }
    }

    std::vector<RankedChunk> ranked;
    const size_t chunkCount = m_chunks.size();
    ranked.reserve(chunkCount / 4 + 16);
    for (size_t ci = 0; ci < chunkCount; ++ci) {
        const ChunkRef& ch = m_chunks[ci];
        if (ch.fileIdx >= m_universe.files.size()) continue;
        if (ch.scope != ScopeKind::Function && ch.scope != ScopeKind::Class &&
            ch.scope != ScopeKind::Struct && ch.scope != ScopeKind::Namespace &&
            ch.scope != ScopeKind::Enum)
            continue;

        double score = 0.0;
        std::string why;
        for (const auto& kw : identWeight) {
            const std::vector<uint32_t>& ids = ch.idents;
            if (std::binary_search(ids.begin(), ids.end(), kw.first)) {
                score += kw.second;
                if (why.empty()) why = "identifier match";
            }
        }
        const std::string qlower = lowerAscii(query);
        if (!ch.qualified.empty() &&
            lowerAscii(ch.qualified).find(qlower) != std::string::npos) {
            score += 3.0;
            why += why.empty() ? "" : "+";
            why += "name match";
        }
        for (const std::string& tok : qt) {
            if (lowerAscii(ch.name) == tok) score += 4.0;
        }
        score *= symbolKindWeight(ch.symbolKind);
        auto h = hop.find(static_cast<uint32_t>(ci));
        if (h != hop.end()) {
            score += (h->second == 0) ? 1.5 : 0.75;
            why += why.empty() ? "" : "+";
            why += (h->second == 0) ? "named in query" : "one call hop";
        }
        if (activeFileRel.empty() ||
            m_universe.files[ch.fileIdx].rel == activeFileRel)
            score += 0.5;
        if (score <= 0.0) continue;

        RankedChunk rc;
        rc.rel = m_universe.files[ch.fileIdx].rel;
        rc.qualified = ch.qualified;
        rc.why = why.empty() ? "token overlap" : why;
        rc.beginLine = ch.beginLine;
        rc.endLine = ch.endLine;
        rc.lineCount = ch.endLine >= ch.beginLine ? ch.endLine - ch.beginLine + 1
                                                 : 1;
        rc.score = score;
        rc.hopDistance = h != hop.end() ? h->second : 0xFFFFFFFFu;
        ranked.push_back(rc);
    }

    std::sort(ranked.begin(), ranked.end(),
              [](const RankedChunk& a, const RankedChunk& b) {
                  if (a.score != b.score) return a.score > b.score;
                  if (a.rel != b.rel) return a.rel < b.rel;
                  return a.beginLine < b.beginLine;
              });
    if (ranked.size() > maxChunks) ranked.resize(maxChunks);
    return ranked;
}

AbsenceClaim RepositoryIntelligence::claimAbsence(
    const std::string& subject) const {
    AbsenceClaim c;
    c.subject = subject;
    c.universeFiles = m_universe.files.size();
    c.universeBytes = m_universe.bytesSeen;
    c.prunedDirs = m_universe.pruned.size();
    c.filesSeen = m_universe.filesSeen;
    c.narrowed = m_narrowed;
    if (m_narrowed) {
        c.allowed = false;
        c.refusal =
            "SCOPE_NARROWED: this universe was not the whole repository, so no "
            "absence may be claimed from it. scopeLabel=" +
            (m_scopeLabel.empty() ? std::string("(none)") : m_scopeLabel);
        return c;
    }
    if (!m_universe.rootExists) {
        c.allowed = false;
        c.refusal = "ROOT_MISSING: the repository root was not found";
        return c;
    }
    if (m_universe.truncated != 0) {
        c.allowed = false;
        c.refusal = "WALK_TRUNCATED: maxFiles cut the walk short";
        return c;
    }
    c.allowed = true;
    c.refusal.clear();
    return c;
}

std::vector<std::string> RepositoryIntelligence::qualifiedNames() const {
    std::vector<std::string> out;
    out.reserve(m_symbols.size());
    for (const SymbolRef& s : m_symbols) out.push_back(s.qualified);
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

bool RepositoryIntelligence::save(const std::string& path, std::string* err) {
    std::string body;
    putStr(body, m_universe.policy.explicitRoot.empty() ? m_scopeLabel
                                                        : m_universe.policy.explicitRoot);
    putU32(body, static_cast<uint32_t>(m_universe.files.size()));
    putU32(body, static_cast<uint32_t>(m_chunks.size()));
    putU32(body, static_cast<uint32_t>(m_symbols.size()));
    putU32(body, static_cast<uint32_t>(m_callEdges.size()));
    putU32(body, static_cast<uint32_t>(m_identNames.size()));
    putU32(body, static_cast<uint32_t>(m_tokens.size()));

    for (const UniverseFile& f : m_universe.files) {
        putStr(body, f.rel);
        putU64(body, f.size);
        putU64(body, f.mtime);
        putStr(body, f.hash);
    }
    for (const ChunkRef& c : m_chunks) {
        putStr(body, c.qualified);
        putStr(body, c.name);
        putU32(body, static_cast<uint32_t>(c.scope));
        putU32(body, static_cast<uint32_t>(c.symbolKind));
        putU32(body, c.fileIdx);
        putU32(body, c.beginLine);
        putU32(body, c.endLine);
        putU32(body, c.depth);
        putU32(body, static_cast<uint32_t>(c.idents.size()));
        for (const uint32_t id : c.idents) putU32(body, id);
    }
    for (const SymbolRef& s : m_symbols) {
        putStr(body, s.name);
        putStr(body, s.qualified);
        putU32(body, static_cast<uint32_t>(s.kind));
        putU32(body, s.fileIdx);
        putU32(body, s.chunkIdx);
        putU32(body, s.beginLine);
        putU32(body, s.endLine);
    }
    for (const CallEdge& e : m_callEdges) {
        putU32(body, e.callerChunk);
        putU32(body, e.calleeIdent);
    }
    for (const std::string& nm : m_identNames) putStr(body, nm);
    for (const std::string& tk : m_tokens) putStr(body, tk);
    for (const auto& pl : m_postings) {
        putU32(body, static_cast<uint32_t>(pl.size()));
        for (const Posting& p : pl) {
            putU32(body, p.fileIdx);
            putU32(body, p.chunkIdx);
        }
    }
    for (const IndexedFile& f : m_files) {
        putU32(body, static_cast<uint32_t>(f.globalIdents.size()));
        for (const uint32_t g : f.globalIdents) putU32(body, g);
        putU32(body, static_cast<uint32_t>(f.includes.size()));
        for (const IncludeEdge& e : f.includes) {
            putStr(body, e.spelling);
            putU32(body, e.angled ? 1u : 0u);
            putU32(body, e.line);
            putU32(body, e.resolvedFileIdx);
        }
        putU32(body, f.callCount);
        putU32(body, f.chunkCount);
        putU32(body, f.symbolCount);
    }

    const std::string digest = contentHash(body);

    std::string out;
    putU32(out, kMagic);
    putU32(out, kVersion);
    putU64(out, static_cast<uint64_t>(body.size()));
    putStr(out, digest);
    putStr(out, digest);
    out.append(body);

    FILE* f = fopen(path.c_str(), "wb");
    if (!f) {
        if (err) *err = "fopen";
        return false;
    }
    const size_t wrote = fwrite(out.data(), 1, out.size(), f);
    fclose(f);
    if (wrote != out.size()) {
        if (err) *err = "short write";
        return false;
    }
    m_stats.indexBytesOnDisk = out.size();
    snapshotManifest();
    return true;
}

bool RepositoryIntelligence::load(const std::string& path, std::string* err) {
    std::string raw;
    if (!readWholeFile(path, raw, err)) return false;
    Reader h{raw};
    if (h.u32() != kMagic) {
        if (err) *err = "magic";
        return false;
    }
    h.u32();  // version
    const uint64_t bodyLen = h.u64();
    const std::string digest = h.str();
    h.str();  // duplicate digest field
    if (!h.ok || h.p + bodyLen > raw.size()) {
        if (err) *err = "body";
        return false;
    }
    const std::string body = raw.substr(h.p, static_cast<size_t>(bodyLen));
    if (contentHash(body) != digest) {
        if (err) *err = "digest";
        return false;
    }

    Reader b{body};
    UniversePolicy p;
    p.explicitRoot = b.str();
    const uint32_t nFiles = b.u32();
    const uint32_t nChunks = b.u32();
    const uint32_t nSymbols = b.u32();
    const uint32_t nEdges = b.u32();
    const uint32_t nIdents = b.u32();
    const uint32_t nTokens = b.u32();
    if (!b.ok) {
        if (err) *err = "header";
        return false;
    }

    Universe u;
    u.rootExists = true;
    for (uint32_t i = 0; i < nFiles; ++i) {
        UniverseFile f;
        f.rel = b.str();
        f.size = b.u64();
        f.mtime = b.u64();
        f.hash = b.str();
        u.files.push_back(f);
    }
    m_universe = u;
    m_savedRel.clear();
    m_savedSize.clear();
    m_savedMtime.clear();
    m_savedHash.clear();
    for (const UniverseFile& f : m_universe.files) {
        m_savedRel.push_back(f.rel);
        m_savedSize.push_back(f.size);
        m_savedMtime.push_back(f.mtime);
        m_savedHash.push_back(f.hash);
    }

    m_chunks.clear();
    m_chunks.reserve(nChunks);
    for (uint32_t i = 0; i < nChunks; ++i) {
        ChunkRef c;
        c.qualified = b.str();
        c.name = b.str();
        c.scope = static_cast<ScopeKind>(b.u32());
        c.symbolKind = static_cast<SymbolKind>(b.u32());
        c.fileIdx = b.u32();
        c.beginLine = b.u32();
        c.endLine = b.u32();
        c.depth = b.u32();
        const uint32_t idc = b.u32();
        c.idents.reserve(idc);
        for (uint32_t k = 0; k < idc; ++k) c.idents.push_back(b.u32());
        m_chunks.push_back(std::move(c));
    }
    m_symbols.clear();
    m_symbols.reserve(nSymbols);
    for (uint32_t i = 0; i < nSymbols; ++i) {
        SymbolRef s;
        s.name = b.str();
        s.qualified = b.str();
        s.kind = static_cast<SymbolKind>(b.u32());
        s.fileIdx = b.u32();
        s.chunkIdx = b.u32();
        s.beginLine = b.u32();
        s.endLine = b.u32();
        m_symbols.push_back(std::move(s));
    }
    m_callEdges.clear();
    m_callEdges.reserve(nEdges);
    for (uint32_t i = 0; i < nEdges; ++i) {
        CallEdge e;
        e.callerChunk = b.u32();
        e.calleeIdent = b.u32();
        m_callEdges.push_back(e);
    }
    m_identNames.clear();
    m_identIds.clear();
    m_identPostings.clear();
    for (uint32_t i = 0; i < nIdents; ++i) {
        const std::string nm = b.str();
        m_identIds.emplace(nm, i);
        m_identNames.push_back(nm);
    }
    m_tokens.clear();
    m_tokenIds.clear();
    m_postings.clear();
    for (uint32_t i = 0; i < nTokens; ++i) {
        const std::string tk = b.str();
        m_tokenIds.emplace(tk, i);
        m_tokens.push_back(tk);
    }
    for (uint32_t i = 0; i < nTokens; ++i) {
        const uint32_t cnt = b.u32();
        std::vector<Posting> pl;
        pl.reserve(cnt);
        for (uint32_t k = 0; k < cnt; ++k) {
            Posting pg;
            pg.fileIdx = b.u32();
            pg.chunkIdx = b.u32();
            pl.push_back(pg);
        }
        m_postings.push_back(std::move(pl));
    }
    m_files.assign(m_universe.files.size(), IndexedFile{});
    for (uint32_t i = 0; i < m_files.size(); ++i) {
        IndexedFile& f = m_files[i];
        f.fileIdx = i;
        const uint32_t gc = b.u32();
        f.globalIdents.reserve(gc);
        for (uint32_t k = 0; k < gc; ++k) f.globalIdents.push_back(b.u32());
        const uint32_t ic = b.u32();
        for (uint32_t k = 0; k < ic; ++k) {
            IncludeEdge e;
            e.spelling = b.str();
            e.angled = b.u32() != 0;
            e.line = b.u32();
            e.resolvedFileIdx = b.u32();
            f.includes.push_back(std::move(e));
        }
        f.callCount = b.u32();
        f.chunkCount = b.u32();
        f.symbolCount = b.u32();
    }
    if (!b.ok) {
        if (err) *err = "truncated";
        return false;
    }
    mergeCallGraph();
    rebuildLookupTables();
    m_stats.indexBytesOnDisk = raw.size();
    m_ready = true;
    return true;
}

void RepositoryIntelligence::snapshotManifest() {
    m_savedRel.clear();
    m_savedSize.clear();
    m_savedMtime.clear();
    m_savedHash.clear();
    m_savedRel.reserve(m_universe.files.size());
    for (const UniverseFile& uf : m_universe.files) {
        m_savedRel.push_back(uf.rel);
        m_savedSize.push_back(uf.size);
        m_savedMtime.push_back(uf.mtime);
        m_savedHash.push_back(uf.hash);
    }
}

IncrementalDelta RepositoryIntelligence::refresh() {
    m_delta = IncrementalDelta{};
    if (m_savedRel.empty()) return m_delta;

    const UniversePolicy p = m_universe.policy;
    const auto           t0 = Clock::now();
    m_universe = buildUniverse(p);
    m_stats = IndexStats{};
    m_stats.walkMs = msSince(t0);
    parseAll(true);
    const auto t1 = Clock::now();
    mergeParsed();
    mergeCallGraph();
    resolveIncludeTargets();
    finalizeStats();
    m_stats.mergeMs = msSince(t1);
    m_stats.totalMs = msSince(t0);
    m_delta.incrMs = m_stats.totalMs;
    return m_delta;
}

RepositoryIntelligence::DeterminismResult
RepositoryIntelligence::verifyDeterminismRebuild(const UniversePolicy& p,
                                                const std::string& dirA,
                                                const std::string& dirB) {
    DeterminismResult r;
    const std::string pathA = dirA + "/index.rix";
    const std::string pathB = dirB + "/index.rix";

    // Fingerprint the input tree first: without this, two builds of a tree that
    // something else is writing to would be reported as non-determinism when the
    // algorithm is in fact deterministic.
    const Universe before = buildUniverse(p);

    RepositoryIntelligence a;
    a.build(p);
    a.save(pathA);

    RepositoryIntelligence b;
    b.build(p);
    b.save(pathB);

    const Universe after = buildUniverse(p);
    std::vector<std::string> moved;
    {
        if (before.files.size() != after.files.size()) {
            moved.push_back("<file count changed " +
                            std::to_string(before.files.size()) + " -> " +
                            std::to_string(after.files.size()) + ">");
        }
        std::unordered_map<std::string, const UniverseFile*> byRel;
        for (const UniverseFile& f : before.files) byRel.emplace(f.rel, &f);
        for (const UniverseFile& f : after.files) {
            auto it = byRel.find(f.rel);
            if (it == byRel.end() || it->second->hash != f.hash ||
                it->second->size != f.size)
                moved.push_back(f.rel);
        }
        r.treeStable = moved.empty();
        for (size_t i = 0; i < moved.size() && i < 40; ++i)
            r.changedPaths += (i ? "," : "") + moved[i];
    }

    if (!r.treeStable) {
        // Another process is writing to this tree. Reproducibility over a moving
        // input proves nothing, so the comparison is redone over a declared
        // input set that excludes exactly the paths that moved, and the
        // excluded set is reported. This narrows what determinism has been
        // proven over, and says so, rather than either failing the algorithm or
        // silently ignoring the difference.
        UniversePolicy stable = p;
        stable.excludeRelPaths = moved;
        DeterminismResult narrowed =
            verifyDeterminismRebuild(stable, dirA, dirB);
        narrowed.excludedVolatilePaths = r.changedPaths;
        narrowed.volatilePathCount = static_cast<uint32_t>(moved.size());
        return narrowed;
    }

    std::string ba, bb;
    if (!readWholeFile(pathA, ba) || !readWholeFile(pathB, bb)) {
        r.mismatch = "index file unreadable";
        return r;
    }
    r.bytesA = ba.size();
    r.bytesB = bb.size();
    r.hashA = contentHash(ba);
    r.hashB = contentHash(bb);
    if (ba.size() != bb.size()) {
        r.mismatch = "payload size differs";
        return r;
    }
    for (size_t i = 0; i < ba.size(); ++i) {
        if (ba[i] != bb[i]) {
            r.mismatch = "first byte difference at offset " +
                         std::to_string(i);
            return r;
        }
    }
    r.identical = true;
    return r;
}

}  // namespace repointel
}  // namespace rawrxd