// ============================================================================
// RepositoryIndexer.hpp — Structured filesystem understanding for RawrXD
// ============================================================================
// Scans project directories, extracts symbols, dependencies, and build state.
// Produces a structured index that ContextEngine can compress for model inference.
//
// Phase: Context Generation Pipeline
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <filesystem>

namespace RawrXD {
namespace Context {

// ============================================================================
// FILE INFO — Per-file metadata and extracted symbols
// ============================================================================

struct FileInfo
{
    std::string path;                    // Relative path from repo root
    uint64_t size = 0;                   // File size in bytes
    std::string language;              // Detected language (cpp, header, build, etc.)
    std::vector<std::string> symbols;   // Extracted symbols (functions, classes, etc.)
    std::vector<std::string> includes;  // #include directives
    std::vector<std::string> dependencies; // Linked libraries / dependencies
};

// ============================================================================
// REPOSITORY INDEX — Complete scan result
// ============================================================================

struct RepositoryIndex
{
    std::string rootPath;
    std::chrono::system_clock::time_point timestamp;

    // File counts
    uint64_t totalFiles = 0;
    uint64_t totalBytes = 0;
    uint64_t cppFiles = 0;
    uint64_t headerFiles = 0;
    uint64_t buildFiles = 0;

    // Detailed file list
    std::vector<FileInfo> files;

    // Aggregated data
    std::vector<std::string> topSymbols;
    std::vector<std::string> includes;
    std::vector<std::string> dependencies;
    std::vector<std::string> issues;

    // Build state
    std::string buildState;
};

// ============================================================================
// INDEX OPTIONS — Control what gets scanned and extracted
// ============================================================================

struct IndexOptions
{
    bool includeCpp = true;
    bool includeHeaders = true;
    bool includeBuild = true;
    bool includeDocs = false;
    bool includeAll = false;
    bool extractSymbols = true;
    size_t maxSymbols = 100;
    size_t maxIncludes = 50;
    size_t maxDependencies = 50;
};

// ============================================================================
// REPOSITORY INDEXER — Main API
// ============================================================================

class RepositoryIndexer
{
public:
    // Scan a directory and produce a structured index
    static RepositoryIndex Index(const std::string& rootPath, IndexOptions opts = IndexOptions{});

    // Detect language from file extension
    static std::string DetectLanguage(const std::filesystem::path& path);

    // Detect build state from directory contents
    static std::string DetectBuildState(const std::string& rootPath);
};

} // namespace Context
} // namespace RawrXD
