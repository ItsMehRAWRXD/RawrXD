// ============================================================================
// RepositoryIntelligence.hpp — RAWRXD_REPOSITORY_INTELLIGENCE_001
//
// One index over one Universe. Everything a coding agent needs to answer
// "where is this, who calls it, what does it depend on, and what should I
// read" comes from a single lexical pass per file, is persisted between runs,
// and is refreshed by re-parsing only files that actually changed.
//
// The scope guard is the point. A query issued against a narrowed universe
// carries SCOPE_NARROWED=1 and claimAbsence() refuses, so "not found" can
// never be reported from a universe that did not cover the repository. That is
// the property an audit convention cannot supply: src/core/ssot_handlers.cpp
// used to enumerate four hardcoded directories under a 1600-file cap and treat
// the truncated result as the whole repository.
// ============================================================================
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "repointel/RepositoryUniverse.hpp"
#include "repointel/ScopeTree.hpp"

namespace rawrxd {
namespace repointel {

struct Location {
    std::string rel;
    uint32_t    line = 0;  // 1-based
    std::string snippet;
};

struct SymbolRef {
    std::string name;
    std::string qualified;
    SymbolKind  kind = SymbolKind::Unknown;
    uint32_t    fileIdx = 0;
    uint32_t    chunkIdx = 0xFFFFFFFFu;
    uint32_t    beginLine = 0;
    uint32_t    endLine = 0;
};

struct ChunkRef {
    std::string qualified;
    std::string name;
    ScopeKind   scope = ScopeKind::Unknown;
    SymbolKind  symbolKind = SymbolKind::Unknown;
    uint32_t    fileIdx = 0;
    uint32_t    beginLine = 0;
    uint32_t    endLine = 0;
    uint32_t    depth = 0;
    // Global identifier ids this chunk mentions, sorted and deduped.
    std::vector<uint32_t> idents;
};

struct Posting {
    uint32_t fileIdx = 0;
    uint32_t chunkIdx = 0xFFFFFFFFu;

    bool operator==(const Posting& o) const {
        return fileIdx == o.fileIdx && chunkIdx == o.chunkIdx;
    }
    bool operator<(const Posting& o) const {
        if (fileIdx != o.fileIdx) return fileIdx < o.fileIdx;
        return chunkIdx < o.chunkIdx;
    }
};

struct IndexedFile {
    uint32_t               fileIdx = 0;
    std::vector<uint32_t>  globalIdents;  // sorted, deduped
    std::vector<IncludeEdge> includes;
    uint32_t               callCount = 0;
    uint32_t               chunkCount = 0;
    uint32_t               symbolCount = 0;
};

struct IndexStats {
    uint64_t filesInUniverse = 0;
    uint64_t filesIndexed = 0;
    uint64_t filesReused = 0;
    uint64_t bytesIndexed = 0;
    uint64_t linesIndexed = 0;
    uint64_t chunks = 0;
    uint64_t symbols = 0;
    uint64_t identifiers = 0;
    uint64_t searchTokens = 0;
    uint64_t includeEdges = 0;
    uint64_t resolvedIncludes = 0;
    uint64_t unresolvedIncludes = 0;
    uint64_t callEdges = 0;
    uint64_t postingEntries = 0;
    uint64_t prunedDirs = 0;
    uint64_t prunedFilesBelow = 0;
    uint64_t prunedBytesBelow = 0;
    uint64_t truncatedFiles = 0;
    uint64_t unreadableFiles = 0;
    uint64_t includeCycles = 0;
    uint32_t threads = 1;
    double   walkMs = 0.0;
    double   parseMs = 0.0;
    double   mergeMs = 0.0;
    double   totalMs = 0.0;
    uint64_t peakWorkingSetBytes = 0;
    uint64_t indexBytesOnDisk = 0;
};

struct IncrementalDelta {
    uint32_t added = 0;
    uint32_t removed = 0;
    uint32_t modified = 0;
    uint32_t unchanged = 0;
    uint32_t reindexed = 0;
    uint32_t reused = 0;
    uint32_t hashVerified = 0;
    double   fullMs = 0.0;
    double   incrMs = 0.0;
    // Exactly which files were re-parsed, and which disappeared. A count alone
    // cannot distinguish "re-parsed the file I changed" from "re-parsed the
    // file I changed plus something else that moved under the walk".
    std::vector<std::string> reindexedPaths;
    std::vector<std::string> removedPaths;
};

struct RankedChunk {
    std::string rel;
    std::string qualified;
    std::string why;
    uint32_t    beginLine = 0;
    uint32_t    endLine = 0;
    uint32_t    lineCount = 0;
    double      score = 0.0;
    uint32_t    hopDistance = 0xFFFFFFFFu;
};

struct SearchHit {
    std::string rel;
    uint32_t    line = 0;
    std::string matched;
    double      score = 0.0;
};

// A claim that something is absent. Obtainable only from a universe that
// covers the whole repository; refused otherwise, on purpose.
struct AbsenceClaim {
    bool        allowed = false;
    std::string subject;
    std::string refusal;
    uint64_t    universeFiles = 0;
    uint64_t    universeBytes = 0;
    uint64_t    prunedDirs = 0;
    uint64_t    filesSeen = 0;
    bool        narrowed = false;
};

class RepositoryIntelligence {
public:
    RepositoryIntelligence();
    ~RepositoryIntelligence();

    RepositoryIntelligence(const RepositoryIntelligence&) = delete;
    RepositoryIntelligence& operator=(const RepositoryIntelligence&) = delete;

    // Whole-repository index. threads == 0 means hardware_concurrency().
    bool build(const UniversePolicy& policy, uint32_t threads = 0);

    // Changed-file invalidation against a loaded index: files whose path, size
    // and mtime are unchanged are reused; the rest are re-hashed, and only
    // hash-changed files are re-parsed.
    IncrementalDelta refresh();

    // Persist / restore. The payload is byte-identical for a byte-identical
    // input tree; verifyDeterminismRebuild compares two payloads byte for byte.
    bool save(const std::string& path, std::string* err = nullptr);
    bool load(const std::string& path, std::string* err = nullptr);

    // Build the same policy twice and report whether the two payloads match.
    // A determinism claim is only meaningful over a stable input tree, so the
    // universe facts are captured before the first build and re-read after the
    // second; if they differ, `treeStable` is false and the caller must report
    // INDETERMINATE rather than either a pass or a failure of the algorithm.
    struct DeterminismResult {
        bool        identical = false;
        bool        treeStable = false;
        uint32_t    volatilePathCount = 0;
        std::string excludedVolatilePaths;
        uint64_t    bytesA = 0;
        uint64_t    bytesB = 0;
        std::string hashA;
        std::string hashB;
        std::string mismatch;
        std::string changedPaths;  // paths that moved during the two builds
    };
    static DeterminismResult verifyDeterminismRebuild(const UniversePolicy& p,
                                                      const std::string& dirA,
                                                      const std::string& dirB);

    bool ready() const { return m_ready; }
    bool narrowed() const { return m_narrowed; }
    const std::string& scopeLabel() const { return m_scopeLabel; }
    const Universe& universe() const { return m_universe; }
    const IndexStats& stats() const { return m_stats; }
    const IncrementalDelta& lastDelta() const { return m_delta; }
    uint64_t universeFileCount() const { return m_universe.files.size(); }

    // --- symbol and reference graph ----------------------------------------
    std::vector<SymbolRef> definitionsOf(const std::string& name) const;
    std::vector<SymbolRef> definitionsOfQualified(const std::string& q) const;
    std::vector<SymbolRef> filesMentioning(const std::string& name) const;
    std::vector<Location>  referencesTo(const std::string& name,
                                        uint32_t limit = 200) const;
    std::vector<SymbolRef> callersOf(const std::string& name) const;
    std::vector<SymbolRef> calleesOf(const std::string& name) const;
    // Multi-hop cross-file traversal of the call graph: forward transitive
    // closure from every definition of `name`, following real call edges to the
    // definition chunk of each callee. Bounded by maxHops.
    std::vector<RankedChunk> reachableFrom(const std::string& name,
                                           uint32_t maxHops = 4,
                                           uint32_t limit = 64) const;
    // Every chunk that calls the same functions `name` calls, one hop. Useful
    // for co-change candidates; deliberately not called transitive reachability.
    std::vector<RankedChunk> coCallersOf(const std::string& name,
                                         uint32_t limit = 32) const;

    // --- dependency traversal ----------------------------------------------
    std::vector<IncludeEdge> includesOf(const std::string& rel) const;
    std::vector<std::string> transitiveIncludes(const std::string& rel,
                                                uint32_t maxDepth = 64) const;
    std::vector<std::string> transitiveDependents(const std::string& rel,
                                                  uint32_t maxDepth = 64) const;
    std::vector<std::string> includeCycles() const;
    std::vector<RankedChunk> changeImpact(const std::string& rel,
                                          uint32_t limit = 64) const;

    // --- repository-scale search and context ranking -----------------------
    std::vector<SearchHit> search(const std::string& query,
                                  uint32_t limit = 50) const;
    std::vector<RankedChunk> rankContext(const std::string& query,
                                         const std::string& activeFileRel,
                                         uint32_t maxChunks = 24) const;

    // --- the scope guard ---------------------------------------------------
    AbsenceClaim claimAbsence(const std::string& subject) const;

    const std::vector<ChunkRef>&  chunks() const { return m_chunks; }
    const std::vector<SymbolRef>& symbols() const { return m_symbols; }
    std::vector<std::string>      qualifiedNames() const;

private:
    struct CallEdge {
        uint32_t callerChunk = 0;
        uint32_t calleeIdent = 0;
    };

    // Parse output for one file. Tokens and comments are consumed inside
    // analyzeSource's caller and never retained here.
    struct ParsedFile {
        bool        ok = false;
        std::vector<std::string> uniqueIdents;
        std::vector<FileChunk>   chunks;
        std::vector<uint32_t>    chunkIdentBegin;
        std::vector<uint32_t>    chunkIdentEnd;
        std::vector<uint32_t>    chunkIdentFlat;
        std::vector<FileSymbol>  symbols;
        std::vector<IncludeEdge> includes;
        std::vector<std::pair<uint32_t, uint32_t>> calls;
        std::vector<std::string> tokens;   // per-file deduped search tokens
    };

    bool parseAll(bool reuse);
    void mergeParsed();
    void mergeSearchIndex();
    void mergeCallGraph();
    void mergeIncludes();
    void rebuildLookupTables();
    void snapshotManifest();
    void finalizeStats();
    uint32_t internIdent(const std::string& name);
    uint32_t internSearchToken(const std::string& tok);
    void     resolveIncludeTargets();

    Universe                 m_universe;
    std::vector<ParsedFile>  m_parsed;
    std::vector<IndexedFile> m_files;
    std::vector<ChunkRef>    m_chunks;
    std::vector<SymbolRef>   m_symbols;
    std::vector<CallEdge>    m_callEdges;

    std::vector<std::string> m_identNames;
    std::unordered_map<std::string, uint32_t> m_identIds;
    std::vector<std::vector<Posting>> m_identPostings;

    std::vector<std::string> m_tokens;
    std::unordered_map<std::string, uint32_t> m_tokenIds;
    std::vector<std::vector<Posting>> m_postings;

    std::unordered_map<uint32_t, std::vector<uint32_t>> m_callees;
    std::unordered_map<uint32_t, std::vector<uint32_t>> m_callers;
    // Callee identifier -> the chunk that defines it. This is what turns a set
    // of name-level call edges into a traversable call graph: without it, a
    // common identifier like `throw` would link unrelated functions.
    std::unordered_map<uint32_t, uint32_t> m_identDefChunk;
    std::unordered_map<std::string, std::vector<uint32_t>> m_defByName;
    std::unordered_map<std::string, std::vector<uint32_t>> m_defByQualified;
    std::unordered_map<std::string, std::vector<uint32_t>> m_defByLower;

    IndexStats       m_stats;
    IncrementalDelta m_delta;
    bool             m_ready = false;
    bool             m_narrowed = false;
    std::string      m_scopeLabel;

    // Snapshot of the last saved universe, used by refresh().
    std::vector<std::string> m_savedRel;
    std::vector<uint64_t>    m_savedSize;
    std::vector<uint64_t>    m_savedMtime;
    std::vector<std::string> m_savedHash;
};

// Split a query into lowercase alphanumeric tokens of at least 2 characters.
std::vector<std::string> tokenizeQuery(const std::string& query);

}  // namespace repointel
}  // namespace rawrxd