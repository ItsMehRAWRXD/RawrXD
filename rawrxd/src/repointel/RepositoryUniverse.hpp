// ============================================================================
// RepositoryUniverse.hpp — RAWRXD_REPOSITORY_INTELLIGENCE_001
//
// The whole-repository file universe. This is the architectural answer to
// "the audit only looked at win32app/*.cpp and declared a feature absent".
//
// Three properties are structural here, not conventions:
//
//  1. The root is resolved from the filesystem, never assumed to be a handful
//     of hardcoded directory names. Callers pass a start directory; the root
//     is found by walking up to the nearest ancestor that carries a build
//     manifest.
//  2. Every excluded directory is still enumerated, and its file count and
//     byte count are recorded in the result. A pruned tree is reported, never
//     silently dropped, so "the walk found nothing here" is distinguishable
//     from "the walk never looked here".
//  3. When the caller's scope has been narrowed, Universe::narrowed is true
//     and the caller is required to label its output SCOPE_NARROWED. Absence
//     claims are refused outright in that mode — see RepositoryIntelligence.
//
// Filesystem facts only. No git, because git ls-files in this repository
// reports untracked source trees as absent (see the receipt).
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd {
namespace repointel {

// Knobs for one universe build. Defaults describe the whole repository.
struct UniversePolicy {
    std::string              startDir;      // where to begin root discovery
    std::string              explicitRoot;  // non-empty bypasses discovery
    std::vector<std::string> pruneDirPatterns = {"build*", "build-*", ".git",
                                                 ".vs", ".vscode", "node_modules",
                                                 "__pycache__", ".rawrxd_cache"};
    std::vector<std::string> extensions;    // empty == every text file
    std::vector<std::string> extraRoots;    // additional in-root subtrees
    // Non-empty restricts the walk to exactly these repo-relative subtrees.
    // This is what a legacy narrow scope is, and setting it forces
    // `narrowed` so absence claims from the result are refused.
    std::vector<std::string> restrictToRoots;
    // Exact repo-relative paths to omit. Used by the determinism gate to
    // declare its input set: a file another process is writing cannot be part
    // of a reproducibility proof, and the excluded set is always reported
    // rather than silently dropped.
    std::vector<std::string> excludeRelPaths;
    uint32_t                 maxFiles = 0;  // 0 == unlimited
    bool                     includeBuildTrees = false;
    bool                     narrowed = false;   // caller restricted scope
    std::string              scopeLabel;        // why it was narrowed
};

// One file in the universe. rel is repo-relative with forward slashes so the
// manifest is identical on every platform.
struct UniverseFile {
    std::string rel;
    std::string abs;
    uint64_t    size = 0;
    uint64_t    mtime = 0;      // 100-ns units since the Windows epoch
    std::string hash;           // 16 hex chars, FNV-1a 64 over content
    uint32_t    lineCount = 0;
};

// A directory the walk deliberately did not index, with what is underneath it.
struct PrunedDir {
    std::string rel;
    uint64_t    filesBelow = 0;
    uint64_t    bytesBelow = 0;
};

struct Universe {
    UniversePolicy         policy;
    std::vector<UniverseFile> files;   // sorted by rel, deduplicated
    std::vector<PrunedDir>    pruned;
    std::vector<std::string>  rootsIndexed;   // repo-relative, sorted
    uint64_t    filesSeen = 0;     // every regular file encountered
    uint64_t    bytesSeen = 0;
    uint32_t    truncated = 0;     // files dropped by maxFiles
    uint32_t    unreadable = 0;    // files present but not openable
    bool        rootExists = false;
    bool        narrowed = false;

    uint64_t filesMatchingExtension() const { return files.size(); }
};

// Walk the filesystem. Never throws. A missing root yields rootExists=false
// and an empty file set rather than an exception.
Universe buildUniverse(const UniversePolicy& policy);

// Locate the repository root for `startDir`: the nearest ancestor containing a
// CMakeLists.txt. Returns empty when none is found.
std::string resolveRepositoryRoot(const std::string& startDir);

// FNV-1a 64 over a buffer, formatted as 16 lowercase hex chars.
std::string contentHash(const void* data, size_t bytes);
std::string contentHash(const std::string& text);

// Read a whole file. Returns false and sets `err` on failure.
bool readWholeFile(const std::string& path, std::string& out, std::string* err = nullptr);

// Count lines without materializing the file; 0 when unreadable.
uint32_t countLines(const std::string& path);

}  // namespace repointel
}  // namespace rawrxd