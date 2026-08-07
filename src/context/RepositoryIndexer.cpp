// ============================================================================
// RepositoryIndexer.cpp — Structured filesystem understanding for RawrXD
// ============================================================================
// Scans project directories, extracts symbols, dependencies, and build state.
// Produces a structured index that ContextEngine can compress for model inference.
//
// Phase: Context Generation Pipeline
// ============================================================================

#include "RepositoryIndexer.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <thread>
#include <mutex>

namespace RawrXD {
namespace Context {

namespace fs = std::filesystem;

// ============================================================================
// INTERNAL — Symbol extraction helpers
// ============================================================================

static std::vector<std::string> ExtractCppSymbols(const std::string& content)
{
    std::vector<std::string> symbols;
    std::regex funcRe(R"((\w+)\s*\([^)]*\)\s*\{)");
    std::regex classRe(R"(class\s+(\w+))");
    std::regex structRe(R"(struct\s+(\w+))");
    std::regex enumRe(R"(enum\s+(?:class\s+)?(\w+))");
    std::regex typedefRe(R"(using\s+(\w+)\s*=)");

    std::sregex_iterator end;
    for (auto it = std::sregex_iterator(content.begin(), content.end(), funcRe); it != end; ++it)
        symbols.push_back((*it)[1].str() + "()");
    for (auto it = std::sregex_iterator(content.begin(), content.end(), classRe); it != end; ++it)
        symbols.push_back("class:" + (*it)[1].str());
    for (auto it = std::sregex_iterator(content.begin(), content.end(), structRe); it != end; ++it)
        symbols.push_back("struct:" + (*it)[1].str());
    for (auto it = std::sregex_iterator(content.begin(), content.end(), enumRe); it != end; ++it)
        symbols.push_back("enum:" + (*it)[1].str());
    for (auto it = std::sregex_iterator(content.begin(), content.end(), typedefRe); it != end; ++it)
        symbols.push_back("type:" + (*it)[1].str());

    // Deduplicate
    std::sort(symbols.begin(), symbols.end());
    symbols.erase(std::unique(symbols.begin(), symbols.end()), symbols.end());
    return symbols;
}

static std::vector<std::string> ExtractIncludes(const std::string& content)
{
    std::vector<std::string> includes;
    std::regex incRe(R"(#include\s*[<"]([^>"]+)[>"])");
    std::sregex_iterator end;
    for (auto it = std::sregex_iterator(content.begin(), content.end(), incRe); it != end; ++it)
        includes.push_back((*it)[1].str());
    std::sort(includes.begin(), includes.end());
    includes.erase(std::unique(includes.begin(), includes.end()), includes.end());
    return includes;
}

static std::vector<std::string> ExtractDependencies(const std::string& content)
{
    std::vector<std::string> deps;
    std::regex libRe(R"(#pragma\s+comment\s*\(\s*lib\s*,\s*"([^"]+)"\s*\))");
    std::regex linkRe(R"(target_link_libraries\s*\(\s*\w+\s+([^)]+)\))");
    std::sregex_iterator end;
    for (auto it = std::sregex_iterator(content.begin(), content.end(), libRe); it != end; ++it)
        deps.push_back((*it)[1].str());
    for (auto it = std::sregex_iterator(content.begin(), content.end(), linkRe); it != end; ++it)
        deps.push_back((*it)[1].str());
    std::sort(deps.begin(), deps.end());
    deps.erase(std::unique(deps.begin(), deps.end()), deps.end());
    return deps;
}

// ============================================================================
// REPOSITORY INDEXER
// ============================================================================

RepositoryIndex RepositoryIndexer::Index(const std::string& rootPath, IndexOptions opts)
{
    RepositoryIndex idx;
    idx.rootPath = rootPath;
    idx.timestamp = std::chrono::system_clock::now();

    if (!fs::exists(rootPath) || !fs::is_directory(rootPath))
    {
        idx.issues.push_back("Root path does not exist: " + rootPath);
        return idx;
    }

    std::mutex idxMutex;
    std::vector<std::thread> workers;
    std::vector<fs::path> fileQueue;

    // Phase 1: Collect files
    try
    {
        for (const auto& entry : fs::recursive_directory_iterator(rootPath,
            fs::directory_options::skip_permission_denied))
        {
            if (!fs::is_regular_file(entry))
                continue;

            auto ext = entry.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

            bool include = false;
            if (opts.includeCpp && (ext == ".cpp" || ext == ".cc" || ext == ".cxx"))
                include = true;
            if (opts.includeHeaders && (ext == ".h" || ext == ".hpp" || ext == ".hxx"))
                include = true;
            if (opts.includeBuild && (ext == ".cmake" || ext == ".ninja" || ext == ".json"))
                include = true;
            if (opts.includeDocs && (ext == ".md" || ext == ".txt" || ext == ".rst"))
                include = true;
            if (opts.includeAll)
                include = true;

            if (include)
                fileQueue.push_back(entry.path());
        }
    }
    catch (const std::exception& e)
    {
        idx.issues.push_back(std::string("Directory iteration error: ") + e.what());
    }

    idx.totalFiles = fileQueue.size();

    // Phase 2: Parallel symbol extraction
    auto workerFn = [&](size_t start, size_t end)
    {
        for (size_t i = start; i < end; ++i)
        {
            const auto& path = fileQueue[i];
            try
            {
                std::ifstream file(path, std::ios::binary);
                if (!file)
                    continue;

                std::string content((std::istreambuf_iterator<char>(file)),
                                      std::istreambuf_iterator<char>());
                file.close();

                FileInfo info;
                info.path = fs::relative(path, rootPath).string();
                info.size = fs::file_size(path);
                info.language = DetectLanguage(path);

                if (opts.extractSymbols && (info.language == "cpp" || info.language == "header"))
                {
                    info.symbols = ExtractCppSymbols(content);
                    info.includes = ExtractIncludes(content);
                    info.dependencies = ExtractDependencies(content);
                }

                std::lock_guard<std::mutex> lock(idxMutex);
                idx.files.push_back(std::move(info));
                idx.totalBytes += info.size;

                // Track language counts
                if (info.language == "cpp")
                    idx.cppFiles++;
                else if (info.language == "header")
                    idx.headerFiles++;
                else if (info.language == "build")
                    idx.buildFiles++;
            }
            catch (...)
            {
                // Skip files we can't read
            }
        }
    };

    size_t numThreads = std::max(1u, std::thread::hardware_concurrency());
    size_t chunkSize = fileQueue.size() / numThreads;
    if (chunkSize == 0)
        chunkSize = fileQueue.size();

    for (size_t t = 0; t < numThreads; ++t)
    {
        size_t start = t * chunkSize;
        size_t end = (t == numThreads - 1) ? fileQueue.size() : (t + 1) * chunkSize;
        if (start < fileQueue.size())
            workers.emplace_back(workerFn, start, end);
    }

    for (auto& t : workers)
        t.join();

    // Phase 3: Aggregate top-level symbols
    for (const auto& file : idx.files)
    {
        for (const auto& sym : file.symbols)
        {
            if (std::find(idx.topSymbols.begin(), idx.topSymbols.end(), sym) == idx.topSymbols.end())
                idx.topSymbols.push_back(sym);
        }
        for (const auto& inc : file.includes)
        {
            if (std::find(idx.includes.begin(), idx.includes.end(), inc) == idx.includes.end())
                idx.includes.push_back(inc);
        }
        for (const auto& dep : file.dependencies)
        {
            if (std::find(idx.dependencies.begin(), idx.dependencies.end(), dep) == idx.dependencies.end())
                idx.dependencies.push_back(dep);
        }
    }

    // Sort and limit
    std::sort(idx.topSymbols.begin(), idx.topSymbols.end());
    std::sort(idx.includes.begin(), idx.includes.end());
    std::sort(idx.dependencies.begin(), idx.dependencies.end());

    if (idx.topSymbols.size() > opts.maxSymbols)
        idx.topSymbols.resize(opts.maxSymbols);
    if (idx.includes.size() > opts.maxIncludes)
        idx.includes.resize(opts.maxIncludes);
    if (idx.dependencies.size() > opts.maxDependencies)
        idx.dependencies.resize(opts.maxDependencies);

    // Detect build state
    idx.buildState = DetectBuildState(rootPath);

    // Detect issues
    if (idx.cppFiles == 0 && idx.headerFiles == 0)
        idx.issues.push_back("no C++ source files found");
    if (!fs::exists(rootPath + "/CMakeLists.txt") && !fs::exists(rootPath + "/Makefile") && !fs::exists(rootPath + "/build.ninja"))
        idx.issues.push_back("no build system detected (CMakeLists.txt, Makefile, build.ninja)");

    return idx;
}

std::string RepositoryIndexer::DetectLanguage(const fs::path& path)
{
    auto ext = path.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    if (ext == ".cpp" || ext == ".cc" || ext == ".cxx" || ext == ".c++")
        return "cpp";
    if (ext == ".h" || ext == ".hpp" || ext == ".hxx" || ext == ".inl")
        return "header";
    if (ext == ".cmake" || ext == ".txt" || path.filename() == "CMakeLists.txt")
        return "build";
    if (ext == ".md" || ext == ".rst")
        return "doc";
    if (ext == ".py")
        return "python";
    if (ext == ".js" || ext == ".ts")
        return "javascript";
    if (ext == ".asm" || ext == ".s")
        return "asm";
    return "other";
}

std::string RepositoryIndexer::DetectBuildState(const std::string& rootPath)
{
    bool hasBuildDir = fs::exists(rootPath + "/build") || fs::exists(rootPath + "/build_win32ide") ||
                       fs::exists(rootPath + "/out") || fs::exists(rootPath + "/cmake-build");
    bool hasCache = fs::exists(rootPath + "/build/CMakeCache.txt") ||
                    fs::exists(rootPath + "/build_win32ide/CMakeCache.txt");
    bool hasNinja = fs::exists(rootPath + "/build/build.ninja") ||
                    fs::exists(rootPath + "/build_win32ide/build.ninja");

    if (hasBuildDir && hasCache && hasNinja)
        return "configured + built (ninja)";
    if (hasBuildDir && hasCache)
        return "configured (cmake cache present)";
    if (hasBuildDir)
        return "partial (build dir exists, no cache)";
    return "not built";
}

} // namespace Context
} // namespace RawrXD
