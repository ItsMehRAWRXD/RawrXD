// Repository Memory Graph - Integration Tests
// Tests the persistent project understanding system

#include <iostream>
#include <cassert>
#include <filesystem>
#include <fstream>

#include "../src/memory/RepositoryMemoryGraph.hpp"

using namespace RawrXD::Memory;

// ============================================================================
// Test Utilities
// ============================================================================

static int testsPassed = 0;
static int testsFailed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) \
    std::cout << "Running " #name "... "; \
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
// Setup/Teardown
// ============================================================================

class TestSetup {
public:
    std::string tempDir;
    
    TestSetup() {
        // Create temporary test directory
        tempDir = std::filesystem::temp_directory_path().string() + "/rawrxd_test_repo";
        std::filesystem::create_directories(tempDir);
        
        // Create test files
        CreateTestFile("main.cpp", R"(
#include "utils.h"

int main() {
    auto result = calculate(42);
    return result;
}
)");
        
        CreateTestFile("utils.h", R"(
#pragma once

int calculate(int value);
class Calculator {
public:
    int add(int a, int b);
    int multiply(int a, int b);
};
)");
        
        CreateTestFile("utils.cpp", R"(
#include "utils.h"

int calculate(int value) {
    return value * 2;
}

int Calculator::add(int a, int b) {
    return a + b;
}

int Calculator::multiply(int a, int b) {
    return a * b;
}
)");
        
        CreateTestFile("CMakeLists.txt", R"(
cmake_minimum_required(VERSION 3.20)
project(TestProject)

add_executable(test_app main.cpp utils.cpp)
)");
    }
    
    ~TestSetup() {
        // Cleanup
        std::filesystem::remove_all(tempDir);
    }
    
    void CreateTestFile(const std::string& name, const std::string& content) {
        std::ofstream f(tempDir + "/" + name);
        f << content;
    }
};

// ============================================================================
// Tests
// ============================================================================

TEST(graph_initialization) {
    TestSetup setup;
    
    auto& graph = RepositoryGraph::Instance();
    ASSERT_TRUE(graph.Initialize(setup.tempDir));
    ASSERT_TRUE(graph.IsInitialized());
    
    auto stats = graph.GetStats();
    ASSERT_TRUE(stats.fileCount >= 4); // At least our 4 test files
    
    graph.Shutdown();
    ASSERT_FALSE(graph.IsInitialized());
}

TEST(file_detection) {
    TestSetup setup;
    
    auto& graph = RepositoryGraph::Instance();
    graph.Initialize(setup.tempDir);
    
    // Check that files were detected
    auto files = graph.GetAllFiles();
    ASSERT_TRUE(files.size() >= 4);
    
    // Find specific files
    bool foundMain = false;
    bool foundUtilsH = false;
    bool foundCMake = false;
    
    for (auto& file : files) {
        if (file->name == "main.cpp") {
            foundMain = true;
            ASSERT_EQ(file->language, FileNode::Language::CPP);
            ASSERT_TRUE(file->isSource);
        }
        if (file->name == "utils.h") {
            foundUtilsH = true;
            ASSERT_EQ(file->language, FileNode::Language::CPP);
            ASSERT_TRUE(file->isHeader);
        }
        if (file->name == "CMakeLists.txt") {
            foundCMake = true;
            ASSERT_EQ(file->language, FileNode::Language::CMAKE);
        }
    }
    
    ASSERT_TRUE(foundMain);
    ASSERT_TRUE(foundUtilsH);
    ASSERT_TRUE(foundCMake);
    
    graph.Shutdown();
}

TEST(file_lookup) {
    TestSetup setup;
    
    auto& graph = RepositoryGraph::Instance();
    graph.Initialize(setup.tempDir);
    
    // Test path lookup
    auto file = graph.GetFileByPath("main.cpp");
    ASSERT_TRUE(file != nullptr);
    ASSERT_EQ(file->name, "main.cpp");
    
    // Test absolute path lookup
    auto file2 = graph.GetFileByPath(setup.tempDir + "/utils.cpp");
    ASSERT_TRUE(file2 != nullptr);
    ASSERT_EQ(file2->name, "utils.cpp");
    
    graph.Shutdown();
}

TEST(symbol_management) {
    TestSetup setup;
    
    auto& graph = RepositoryGraph::Instance();
    graph.Initialize(setup.tempDir);
    
    // Add symbols
    auto calcFunc = graph.AddSymbol("calculate", NodeType::FUNCTION);
    calcFunc->returnType = "int";
    calcFunc->parameters = {{"value", "int"}};
    calcFunc->isDefined = true;
    
    auto calcClass = graph.AddSymbol("Calculator", NodeType::CLASS);
    calcClass->isDefined = true;
    
    // Find symbols
    auto found = graph.FindSymbol("calculate");
    ASSERT_TRUE(found != nullptr);
    ASSERT_EQ(found->kind, NodeType::FUNCTION);
    ASSERT_EQ(found->returnType, "int");
    
    // Query symbols
    SymbolQuery query;
    query.namePattern = "Calculator";
    query.type = NodeType::CLASS;
    auto results = graph.QuerySymbols(query);
    ASSERT_EQ(results.size(), 1);
    ASSERT_EQ(results[0]->name, "Calculator");
    
    graph.Shutdown();
}

TEST(dependency_edges) {
    TestSetup setup;
    
    auto& graph = RepositoryGraph::Instance();
    graph.Initialize(setup.tempDir);
    
    // Get files
    auto mainFile = graph.GetFileByPath("main.cpp");
    auto utilsFile = graph.GetFileByPath("utils.cpp");
    ASSERT_TRUE(mainFile != nullptr);
    ASSERT_TRUE(utilsFile != nullptr);
    
    // Add dependency
    auto edge = graph.AddDependency(mainFile, utilsFile, EdgeType::DEPENDS_ON);
    ASSERT_TRUE(edge != nullptr);
    ASSERT_EQ(edge->type, EdgeType::DEPENDS_ON);
    ASSERT_TRUE(edge->IsValid());
    
    // Get dependencies
    auto deps = graph.GetDependencies(mainFile, EdgeType::DEPENDS_ON);
    ASSERT_EQ(deps.size(), 1);
    
    // Get dependents
    auto dependents = graph.GetDependents(utilsFile, EdgeType::DEPENDS_ON);
    ASSERT_EQ(dependents.size(), 1);
    
    graph.Shutdown();
}

TEST(dirty_file_tracking) {
    TestSetup setup;
    
    auto& graph = RepositoryGraph::Instance();
    graph.Initialize(setup.tempDir);
    
    auto mainFile = graph.GetFileByPath("main.cpp");
    ASSERT_TRUE(mainFile != nullptr);
    
    // Initially not dirty
    ASSERT_FALSE(mainFile->isDirty);
    auto dirtyBefore = graph.GetDirtyFiles();
    ASSERT_EQ(dirtyBefore.size(), 0);
    
    // Mark as dirty
    graph.MarkFileDirty(mainFile->fileId);
    ASSERT_TRUE(mainFile->isDirty);
    
    auto dirtyAfter = graph.GetDirtyFiles();
    ASSERT_EQ(dirtyAfter.size(), 1);
    ASSERT_EQ(dirtyAfter[0]->fileId, mainFile->fileId);
    
    graph.Shutdown();
}

TEST(graph_walker) {
    TestSetup setup;
    
    auto& graph = RepositoryGraph::Instance();
    graph.Initialize(setup.tempDir);
    
    auto mainFile = graph.GetFileByPath("main.cpp");
    ASSERT_TRUE(mainFile != nullptr);
    
    // Walk the graph
    int visitedCount = 0;
    GraphWalker::Walk(mainFile, 
        [&visitedCount](std::shared_ptr<ASTNode> node, uint32_t depth) {
            visitedCount++;
            return true; // Continue walking
        },
        nullptr, // No filter
        10       // Max depth
    );
    
    // Should visit at least the starting node
    ASSERT_TRUE(visitedCount >= 1);
    
    graph.Shutdown();
}

TEST(context_assembler) {
    TestSetup setup;
    
    auto& graph = RepositoryGraph::Instance();
    graph.Initialize(setup.tempDir);
    
    auto& assembler = ContextAssembler::Instance();
    
    // Add a symbol
    auto symbol = graph.AddSymbol("test_function", NodeType::FUNCTION);
    symbol->returnType = "int";
    symbol->parameters = {{"x", "int"}, {"y", "int"}};
    
    // Assemble context
    auto context = assembler.AssembleContextForIntent(
        "MODIFY_FUNCTION",
        "test_function",
        1000
    );
    
    // Should contain the function signature
    ASSERT_FALSE(context.empty());
    ASSERT_TRUE(context.find("test_function") != std::string::npos);
    
    // Test token estimation
    std::string testText = "int main() { return 0; }";
    uint32_t tokens = assembler.EstimateTokens(testText);
    ASSERT_TRUE(tokens > 0);
    
    // Test truncation
    std::string longText(10000, 'x');
    std::string truncated = assembler.TruncateToTokens(longText, 100);
    ASSERT_TRUE(truncated.length() < longText.length());
    ASSERT_TRUE(truncated.find("[truncated]") != std::string::npos);
    
    graph.Shutdown();
}

TEST(ast_node_hierarchy) {
    // Test AST node parent-child relationships
    auto parent = std::make_shared<ASTNode>();
    parent->nodeId = 1;
    parent->type = NodeType::NAMESPACE;
    parent->name = "MyNamespace";
    
    auto child1 = std::make_shared<ASTNode>();
    child1->nodeId = 2;
    child1->type = NodeType::CLASS;
    child1->name = "MyClass";
    child1->parent = parent;
    
    auto child2 = std::make_shared<ASTNode>();
    child2->nodeId = 3;
    child2->type = NodeType::FUNCTION;
    child2->name = "myFunction";
    child2->parent = parent;
    
    parent->children.push_back(child1);
    parent->children.push_back(child2);
    
    // Test GetChildrenOfType
    auto classes = parent->GetChildrenOfType(NodeType::CLASS);
    ASSERT_EQ(classes.size(), 1);
    ASSERT_EQ(classes[0]->name, "MyClass");
    
    // Test FindChild
    auto found = parent->FindChild("myFunction");
    ASSERT_TRUE(found != nullptr);
    ASSERT_EQ(found->type, NodeType::FUNCTION);
    
    // Test GetAncestorOfType
    auto ancestor = child1->GetAncestorOfType(NodeType::NAMESPACE);
    ASSERT_TRUE(ancestor != nullptr);
    ASSERT_EQ(ancestor->name, "MyNamespace");
}

TEST(symbol_signature) {
    auto symbol = std::make_shared<Symbol>();
    symbol->name = "calculate";
    symbol->kind = NodeType::FUNCTION;
    symbol->returnType = "int";
    symbol->parameters = {{"a", "int"}, {"b", "const std::string&"}};
    symbol->isConstexpr = true;
    
    std::string sig = symbol->GetSignature();
    ASSERT_TRUE(sig.find("int") != std::string::npos);
    ASSERT_TRUE(sig.find("calculate") != std::string::npos);
    ASSERT_TRUE(sig.find("int") != std::string::npos);
    ASSERT_TRUE(sig.find("const std::string&") != std::string::npos);
    ASSERT_TRUE(sig.find("constexpr") != std::string::npos);
}

TEST(graph_statistics) {
    TestSetup setup;
    
    auto& graph = RepositoryGraph::Instance();
    graph.Initialize(setup.tempDir);
    
    // Add some symbols
    for (int i = 0; i < 10; i++) {
        auto sym = graph.AddSymbol("symbol_" + std::to_string(i), NodeType::FUNCTION);
        sym->isDefined = true;
    }
    
    auto stats = graph.GetStats();
    ASSERT_TRUE(stats.fileCount >= 4);
    ASSERT_EQ(stats.symbolCount, 10);
    ASSERT_TRUE(stats.memoryUsageMB >= 0);
    
    graph.Shutdown();
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "Repository Memory Graph Tests\n";
    std::cout << "========================================\n\n";
    
    // Graph Tests
    std::cout << "--- Graph Tests ---\n";
    RUN_TEST(graph_initialization);
    RUN_TEST(file_detection);
    RUN_TEST(file_lookup);
    RUN_TEST(symbol_management);
    RUN_TEST(dependency_edges);
    RUN_TEST(dirty_file_tracking);
    RUN_TEST(graph_walker);
    RUN_TEST(graph_statistics);
    std::cout << "\n";
    
    // Context Tests
    std::cout << "--- Context Tests ---\n";
    RUN_TEST(context_assembler);
    std::cout << "\n";
    
    // AST Tests
    std::cout << "--- AST Tests ---\n";
    RUN_TEST(ast_node_hierarchy);
    RUN_TEST(symbol_signature);
    std::cout << "\n";
    
    // Summary
    std::cout << "========================================\n";
    std::cout << "Test Results: " << testsPassed << " passed, " 
              << testsFailed << " failed\n";
    std::cout << "========================================\n";
    
    return testsFailed > 0 ? 1 : 0;
}
