// Persistence Layer - Unit Tests
// Tests saving/loading RepositoryMemoryGraph to disk

#include <iostream>
#include <cassert>
#include <filesystem>
#include <chrono>

#include "../src/memory/RepositoryMemoryGraph.hpp"

using namespace RawrXD;
using namespace RawrXD::Memory;

// ============================================================================
// Test Utilities
// ============================================================================

static int testsPassed = 0;
static int testsFailed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) \
    std::cout << "  " #name "... "; \
    try { \
        test_##name(); \
        std::cout << "PASSED\n"; \
        testsPassed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAILED: " << e.what() << "\n"; \
        testsFailed++; \
    }

#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
        throw std::runtime_error("Assertion failed: " #expr); \
    }

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))
#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))
#define ASSERT_NE(a, b) ASSERT_TRUE((a) != (b))

// ============================================================================
// Tests
// ============================================================================

TEST(persistence_save_empty_graph) {
    // Initialize empty graph
    RepositoryGraph::Instance().Initialize("test_repo");
    
    // Save to disk
    std::string savePath = "test_graph_empty.rawr";
    ASSERT_TRUE(RepositoryGraph::Instance().SaveToDisk(savePath));
    
    // Verify file exists
    ASSERT_TRUE(std::filesystem::exists(savePath));
    
    // Cleanup
    RepositoryGraph::Instance().Shutdown();
    std::filesystem::remove(savePath);
}

TEST(persistence_save_and_load_files) {
    // Create temp directory with test files
    std::string tempDir = "test_repo_files";
    std::filesystem::create_directories(tempDir);
    std::filesystem::create_directories(tempDir + "/src");
    
    // Create test files
    {
        std::ofstream f(tempDir + "/src/main.cpp");
        f << "int main() { return 0; }";
    }
    {
        std::ofstream f(tempDir + "/src/utils.cpp");
        f << "void helper() {}";
    }
    {
        std::ofstream f(tempDir + "/README.md");
        f << "# Test Project";
    }
    
    // Initialize and scan
    RepositoryGraph::Instance().Initialize(tempDir);
    
    auto stats = RepositoryGraph::Instance().GetStats();
    ASSERT_TRUE(stats.fileCount >= 3); // At least our 3 files
    
    // Save
    std::string savePath = "test_graph_files.rawr";
    ASSERT_TRUE(RepositoryGraph::Instance().SaveToDisk(savePath));
    
    // Shutdown and reload
    RepositoryGraph::Instance().Shutdown();
    
    ASSERT_TRUE(RepositoryGraph::Instance().LoadFromDisk(savePath));
    
    auto loadedStats = RepositoryGraph::Instance().GetStats();
    ASSERT_EQ(loadedStats.fileCount, stats.fileCount);
    
    // Verify files loaded
    auto files = RepositoryGraph::Instance().GetAllFiles();
    ASSERT_EQ(files.size(), stats.fileCount);
    
    // Cleanup
    RepositoryGraph::Instance().Shutdown();
    std::filesystem::remove(savePath);
    std::filesystem::remove_all(tempDir);
}

TEST(persistence_save_and_load_symbols) {
    RepositoryGraph::Instance().Initialize("test_repo_symbols");
    
    // Add symbols
    auto sym1 = RepositoryGraph::Instance().AddSymbol("main", NodeType::FUNCTION);
    auto sym2 = RepositoryGraph::Instance().AddSymbol("helper", NodeType::FUNCTION);
    auto sym3 = RepositoryGraph::Instance().AddSymbol("MyClass", NodeType::CLASS);
    
    sym1->qualifiedName = "main";
    sym2->qualifiedName = "helper";
    sym3->qualifiedName = "MyClass";
    
    sym1->isDefined = true;
    sym2->isDefined = true;
    sym3->isDefined = true;
    
    auto stats = RepositoryGraph::Instance().GetStats();
    ASSERT_EQ(stats.symbolCount, 3);
    
    // Save
    std::string savePath = "test_graph_symbols.rawr";
    ASSERT_TRUE(RepositoryGraph::Instance().SaveToDisk(savePath));
    
    // Reload
    RepositoryGraph::Instance().Shutdown();
    ASSERT_TRUE(RepositoryGraph::Instance().LoadFromDisk(savePath));
    
    // Verify symbols
    auto loadedStats = RepositoryGraph::Instance().GetStats();
    ASSERT_EQ(loadedStats.symbolCount, 3);
    
    auto found1 = RepositoryGraph::Instance().FindSymbol("main");
    ASSERT_NE(found1, nullptr);
    ASSERT_EQ(found1->name, "main");
    ASSERT_EQ(found1->kind, NodeType::FUNCTION);
    ASSERT_TRUE(found1->isDefined);
    
    auto found2 = RepositoryGraph::Instance().FindSymbol("helper");
    ASSERT_NE(found2, nullptr);
    ASSERT_EQ(found2->name, "helper");
    
    auto found3 = RepositoryGraph::Instance().FindSymbol("MyClass");
    ASSERT_NE(found3, nullptr);
    ASSERT_EQ(found3->kind, NodeType::CLASS);
    
    // Cleanup
    RepositoryGraph::Instance().Shutdown();
    std::filesystem::remove(savePath);
}

TEST(persistence_save_and_load_edges) {
    RepositoryGraph::Instance().Initialize("test_repo_edges");
    
    // Add files
    auto file1 = RepositoryGraph::Instance().AddFile("test1.cpp");
    auto file2 = RepositoryGraph::Instance().AddFile("test2.cpp");
    auto file3 = RepositoryGraph::Instance().AddFile("test3.cpp");
    
    // Add dependencies (edges)
    auto edge1 = RepositoryGraph::Instance().AddDependency(file1, file2, EdgeType::DEPENDS_ON);
    auto edge2 = RepositoryGraph::Instance().AddDependency(file2, file3, EdgeType::DEPENDS_ON);
    auto edge3 = RepositoryGraph::Instance().AddDependency(file1, file3, EdgeType::DEPENDS_ON);
    
    edge1->strength = 5;
    edge2->strength = 3;
    edge3->strength = 1;
    
    auto stats = RepositoryGraph::Instance().GetStats();
    ASSERT_EQ(stats.edgeCount, 3);
    
    // Save
    std::string savePath = "test_graph_edges.rawr";
    ASSERT_TRUE(RepositoryGraph::Instance().SaveToDisk(savePath));
    
    // Reload
    RepositoryGraph::Instance().Shutdown();
    ASSERT_TRUE(RepositoryGraph::Instance().LoadFromDisk(savePath));
    
    // Verify edges
    auto loadedStats = RepositoryGraph::Instance().GetStats();
    ASSERT_EQ(loadedStats.edgeCount, 3);
    
    // Cleanup
    RepositoryGraph::Instance().Shutdown();
    std::filesystem::remove(savePath);
}

TEST(persistence_dirty_files_preserved) {
    RepositoryGraph::Instance().Initialize("test_repo_dirty");
    
    // Add files
    auto file1 = RepositoryGraph::Instance().AddFile("test1.cpp");
    auto file2 = RepositoryGraph::Instance().AddFile("test2.cpp");
    auto file3 = RepositoryGraph::Instance().AddFile("test3.cpp");
    
    // Mark some dirty
    RepositoryGraph::Instance().MarkFileDirty(file1->fileId);
    RepositoryGraph::Instance().MarkFileDirty(file3->fileId);
    
    auto dirtyBefore = RepositoryGraph::Instance().GetDirtyFiles();
    ASSERT_EQ(dirtyBefore.size(), 2);
    
    // Save
    std::string savePath = "test_graph_dirty.rawr";
    ASSERT_TRUE(RepositoryGraph::Instance().SaveToDisk(savePath));
    
    // Reload
    RepositoryGraph::Instance().Shutdown();
    ASSERT_TRUE(RepositoryGraph::Instance().LoadFromDisk(savePath));
    
    // Verify dirty files preserved
    auto dirtyAfter = RepositoryGraph::Instance().GetDirtyFiles();
    ASSERT_EQ(dirtyAfter.size(), 2);
    
    // Cleanup
    RepositoryGraph::Instance().Shutdown();
    std::filesystem::remove(savePath);
}

TEST(persistence_large_graph) {
    RepositoryGraph::Instance().Initialize("test_repo_large");
    
    // Add many symbols
    const int symbolCount = 1000;
    for (int i = 0; i < symbolCount; i++) {
        auto sym = RepositoryGraph::Instance().AddSymbol("symbol_" + std::to_string(i), NodeType::FUNCTION);
        sym->qualifiedName = "ns::symbol_" + std::to_string(i);
        sym->isDefined = (i % 2 == 0);
    }
    
    auto stats = RepositoryGraph::Instance().GetStats();
    ASSERT_EQ(stats.symbolCount, symbolCount);
    
    // Save
    std::string savePath = "test_graph_large.rawr";
    auto startSave = std::chrono::steady_clock::now();
    ASSERT_TRUE(RepositoryGraph::Instance().SaveToDisk(savePath));
    auto endSave = std::chrono::steady_clock::now();
    auto saveTime = std::chrono::duration_cast<std::chrono::milliseconds>(endSave - startSave).count();
    
    std::cout << "(save: " << saveTime << "ms) ";
    
    // Reload
    RepositoryGraph::Instance().Shutdown();
    auto startLoad = std::chrono::steady_clock::now();
    ASSERT_TRUE(RepositoryGraph::Instance().LoadFromDisk(savePath));
    auto endLoad = std::chrono::steady_clock::now();
    auto loadTime = std::chrono::duration_cast<std::chrono::milliseconds>(endLoad - startLoad).count();
    
    std::cout << "(load: " << loadTime << "ms) ";
    
    // Verify
    auto loadedStats = RepositoryGraph::Instance().GetStats();
    ASSERT_EQ(loadedStats.symbolCount, symbolCount);
    
    // Spot check
    auto sym500 = RepositoryGraph::Instance().FindSymbol("symbol_500");
    ASSERT_NE(sym500, nullptr);
    ASSERT_EQ(sym500->name, "symbol_500");
    
    // Cleanup
    RepositoryGraph::Instance().Shutdown();
    std::filesystem::remove(savePath);
}

TEST(persistence_invalid_file) {
    // Try to load non-existent file
    ASSERT_FALSE(RepositoryGraph::Instance().LoadFromDisk("nonexistent_file.rawr"));
    
    // Try to load invalid file
    {
        std::ofstream f("invalid_file.rawr", std::ios::binary);
        f << "NOT_A_VALID_GRAPH_FILE";
    }
    ASSERT_FALSE(RepositoryGraph::Instance().LoadFromDisk("invalid_file.rawr"));
    
    std::filesystem::remove("invalid_file.rawr");
}

TEST(persistence_id_generators_preserved) {
    RepositoryGraph::Instance().Initialize("test_repo_ids");
    
    // Add some items to advance IDs
    auto file1 = RepositoryGraph::Instance().AddFile("test1.cpp");
    auto file2 = RepositoryGraph::Instance().AddFile("test2.cpp");
    auto sym1 = RepositoryGraph::Instance().AddSymbol("sym1", NodeType::FUNCTION);
    auto sym2 = RepositoryGraph::Instance().AddSymbol("sym2", NodeType::FUNCTION);
    
    FileId lastFileId = file2->fileId;
    SymbolId lastSymbolId = sym2->symbolId;
    
    // Save
    std::string savePath = "test_graph_ids.rawr";
    ASSERT_TRUE(RepositoryGraph::Instance().SaveToDisk(savePath));
    
    // Reload
    RepositoryGraph::Instance().Shutdown();
    ASSERT_TRUE(RepositoryGraph::Instance().LoadFromDisk(savePath));
    
    // Add new items - IDs should continue from where they left off
    auto file3 = RepositoryGraph::Instance().AddFile("test3.cpp");
    auto sym3 = RepositoryGraph::Instance().AddSymbol("sym3", NodeType::FUNCTION);
    
    ASSERT_TRUE(file3->fileId > lastFileId);
    ASSERT_TRUE(sym3->symbolId > lastSymbolId);
    
    // Cleanup
    RepositoryGraph::Instance().Shutdown();
    std::filesystem::remove(savePath);
}

TEST(persistence_file_metadata) {
    RepositoryGraph::Instance().Initialize("test_repo_meta");
    
    // Create a test file with content
    std::string testFile = "test_meta.cpp";
    {
        std::ofstream f(testFile);
        f << "void test_function() { int x = 42; }";
    }
    
    auto file = RepositoryGraph::Instance().AddFile(testFile);
    ASSERT_NE(file, nullptr);
    
    // Verify metadata
    ASSERT_EQ(file->name, "test_meta.cpp");
    ASSERT_EQ(file->extension, ".cpp");
    ASSERT_TRUE(file->isSource);
    ASSERT_FALSE(file->isHeader);
    ASSERT_EQ(file->language, FileNode::Language::CPP);
    ASSERT_TRUE(file->fileSize > 0);
    ASSERT_TRUE(file->contentHash != 0);
    
    // Save
    std::string savePath = "test_graph_meta.rawr";
    ASSERT_TRUE(RepositoryGraph::Instance().SaveToDisk(savePath));
    
    // Reload
    RepositoryGraph::Instance().Shutdown();
    ASSERT_TRUE(RepositoryGraph::Instance().LoadFromDisk(savePath));
    
    // Verify metadata preserved
    auto loadedFile = RepositoryGraph::Instance().GetFileByPath(testFile);
    ASSERT_NE(loadedFile, nullptr);
    ASSERT_EQ(loadedFile->name, "test_meta.cpp");
    ASSERT_EQ(loadedFile->extension, ".cpp");
    ASSERT_TRUE(loadedFile->isSource);
    ASSERT_FALSE(loadedFile->isHeader);
    ASSERT_EQ(loadedFile->language, FileNode::Language::CPP);
    ASSERT_EQ(loadedFile->fileSize, file->fileSize);
    ASSERT_EQ(loadedFile->contentHash, file->contentHash);
    
    // Cleanup
    RepositoryGraph::Instance().Shutdown();
    std::filesystem::remove(savePath);
    std::filesystem::remove(testFile);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     PERSISTENCE LAYER - UNIT TESTS                                ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    // Basic Persistence Tests
    std::cout << "┌─ Basic Persistence Tests ─────────────────────────────────────────┐\n";
    RUN_TEST(persistence_save_empty_graph);
    RUN_TEST(persistence_save_and_load_files);
    RUN_TEST(persistence_save_and_load_symbols);
    RUN_TEST(persistence_save_and_load_edges);
    std::cout << "└───────────────────────────────────────────────────────────────────┘\n\n";
    
    // Advanced Persistence Tests
    std::cout << "┌─ Advanced Persistence Tests ──────────────────────────────────────┐\n";
    RUN_TEST(persistence_dirty_files_preserved);
    RUN_TEST(persistence_large_graph);
    RUN_TEST(persistence_invalid_file);
    RUN_TEST(persistence_id_generators_preserved);
    RUN_TEST(persistence_file_metadata);
    std::cout << "└───────────────────────────────────────────────────────────────────┘\n\n";
    
    // Summary
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  TEST RESULTS: " << testsPassed << " passed, " << testsFailed << " failed";
    std::cout << std::string(35 - std::to_string(testsPassed).length() - std::to_string(testsFailed).length(), ' ') << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    return testsFailed > 0 ? 1 : 0;
}
