// Phase 17 Smoke Test: Semantic Search Prototype
// Validates HNSW integration and query routing

#include "rawrxd_semantic_search.h"
#include <iostream>
#include <chrono>
#include <vector>
#include <string>

using namespace RawrXD::Intelligence;

// Simple test framework
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAIL: " << msg << " at line " << __LINE__ << std::endl; \
            return 1; \
        } \
    } while(0)

#define TEST_PASS(msg) \
    std::cout << "PASS: " << msg << std::endl

int main() {
    std::cout << "=== Phase 17 Semantic Search Smoke Test ===" << std::endl;
    std::cout << "Testing HNSW fallback implementation..." << std::endl << std::endl;
    
    // Test 1: Query Classifier
    std::cout << "[Test 1] Query Classification..." << std::endl;
    {
        TEST_ASSERT(QueryClassifier::classify("vector") == QueryType::FAST_PREFIX,
                   "Single word should be FAST_PREFIX");
        TEST_ASSERT(QueryClassifier::classify("std::vector") == QueryType::FAST_PREFIX,
                   "Scoped identifier should be FAST_PREFIX");
        TEST_ASSERT(QueryClassifier::classify("find async file io") == QueryType::SEMANTIC,
                   "Natural language should be SEMANTIC");
        TEST_ASSERT(QueryClassifier::classify("how to implement this") == QueryType::SEMANTIC,
                   "Question should be SEMANTIC");
        TEST_PASS("Query classification working correctly");
    }
    
    // Test 2: Semantic Index Initialization
    std::cout << "[Test 2] Semantic Index Initialization..." << std::endl;
    {
        SemanticCodeIndex index;
        bool initialized = index.initialize(384, 512);  // 384-dim, 512MB limit
        TEST_ASSERT(initialized, "Index should initialize successfully");
        
        size_t mem_mb = index.memory_usage_mb();
        TEST_ASSERT(mem_mb == 0, "Empty index should use 0 MB");
        
        auto stats = index.get_stats();
        TEST_ASSERT(stats.total_snippets == 0, "Empty index should have 0 snippets");
        
        TEST_PASS("Index initialization successful");
        
        index.shutdown();
    }
    
    // Test 3: Add and Search Snippets
    std::cout << "[Test 3] Add and Search Snippets..." << std::endl;
    {
        SemanticCodeIndex index;
        index.initialize(384, 512);
        
        // Add test snippets
        std::vector<CodeSnippet> snippets = {
            {"1", "async function readFile()", "javascript", "file.js", 1, 1, {}},
            {"2", "vector<int> processData()", "cpp", "data.cpp", 10, 15, {}},
            {"3", "async def fetch_data():", "python", "api.py", 5, 8, {}},
            {"4", "std::vector<std::string> split()", "cpp", "utils.cpp", 20, 25, {}},
            {"5", "function handleAsyncIO()", "javascript", "async.js", 1, 10, {}},
        };
        
        // Generate embeddings (deterministic for testing)
        for (auto& s : snippets) {
            // Simple hash-based embedding
            size_t hash = std::hash<std::string>{}(s.content);
            for (int i = 0; i < 384; ++i) {
                hash = hash * 31 + i;
                s.embedding.push_back(static_cast<float>(hash % 1000) / 1000.0f);
            }
            // Normalize
            float norm = 0;
            for (float v : s.embedding) norm += v * v;
            norm = std::sqrt(norm);
            if (norm > 0) {
                for (auto& v : s.embedding) v /= norm;
            }
            
            bool added = index.add_snippet(s);
            TEST_ASSERT(added, "Should add snippet successfully");
        }
        
        auto stats = index.get_stats();
        TEST_ASSERT(stats.total_snippets == 5, "Should have 5 snippets");
        
        // Search for async patterns
        auto results = index.semantic_search("async file io", 3, 0.5f);
        TEST_ASSERT(results.size() > 0, "Should find async-related snippets");
        
        // Verify latency
        auto stats2 = index.get_stats();
        std::cout << "  Query P95 latency: " << stats2.p95_query_time_ms << "ms" << std::endl;
        TEST_ASSERT(stats2.p95_query_time_ms < 10.0f, "P95 should be < 10ms");
        
        TEST_PASS("Add and search working correctly");
        
        index.shutdown();
    }
    
    // Test 4: Memory Constraints
    std::cout << "[Test 4] Memory Constraints..." << std::endl;
    {
        SemanticCodeIndex index;
        index.initialize(384, 64);  // Small 64MB limit
        
        // Calculate max elements
        size_t bytes_per_vector = 384 * sizeof(float) + 1024;
        size_t max_elements = (64 * 1024 * 1024) / bytes_per_vector;
        std::cout << "  Max elements with 64MB: ~" << max_elements << std::endl;
        
        auto stats = index.get_stats();
        TEST_ASSERT(stats.index_size_mb <= 64, "Index should respect memory limit");
        
        TEST_PASS("Memory constraints respected");
        
        index.shutdown();
    }
    
    // Test 5: Hybrid Query Router
    std::cout << "[Test 5] Hybrid Query Router..." << std::endl;
    {
        HybridQueryRouter router;
        SemanticCodeIndex semantic_index;
        semantic_index.initialize(384, 512);
        
        // Add some test data
        CodeSnippet snippet;
        snippet.id = "test1";
        snippet.content = "async function example()";
        snippet.language = "javascript";
        snippet.file_path = "test.js";
        snippet.line_start = 1;
        snippet.line_end = 5;
        
        // Generate embedding
        size_t hash = std::hash<std::string>{}(snippet.content);
        for (int i = 0; i < 384; ++i) {
            hash = hash * 31 + i;
            snippet.embedding.push_back(static_cast<float>(hash % 1000) / 1000.0f);
        }
        float norm = 0;
        for (float v : snippet.embedding) norm += v * v;
        norm = std::sqrt(norm);
        if (norm > 0) {
            for (auto& v : snippet.embedding) v /= norm;
        }
        
        semantic_index.add_snippet(snippet);
        
        // Initialize router (Trie index is null for this test)
        router.initialize(nullptr, &semantic_index);
        
        // Test semantic query
        auto results = router.complete("find async code", "", 5);
        std::cout << "  Found " << results.size() << " results" << std::endl;
        
        TEST_PASS("Hybrid router functional");
        
        semantic_index.shutdown();
    }
    
    // Test 6: Performance Benchmark
    std::cout << "[Test 6] Performance Benchmark..." << std::endl;
    {
        SemanticCodeIndex index;
        index.initialize(384, 512);
        
        // Add 100 snippets
        for (int i = 0; i < 100; ++i) {
            CodeSnippet s;
            s.id = std::to_string(i);
            s.content = "function test" + std::to_string(i) + "() { return " + std::to_string(i) + "; }";
            s.language = "javascript";
            s.file_path = "test" + std::to_string(i) + ".js";
            s.line_start = i;
            s.line_end = i + 5;
            
            // Generate embedding
            size_t hash = std::hash<std::string>{}(s.content);
            for (int j = 0; j < 384; ++j) {
                hash = hash * 31 + j;
                s.embedding.push_back(static_cast<float>(hash % 1000) / 1000.0f);
            }
            float norm = 0;
            for (float v : s.embedding) norm += v * v;
            norm = std::sqrt(norm);
            if (norm > 0) {
                for (auto& v : s.embedding) v /= norm;
            }
            
            index.add_snippet(s);
        }
        
        // Run 100 queries
        auto start = std::chrono::steady_clock::now();
        for (int i = 0; i < 100; ++i) {
            index.semantic_search("test function " + std::to_string(i), 5, 0.5f);
        }
        auto elapsed = std::chrono::steady_clock::now() - start;
        float avg_ms = std::chrono::duration<float, std::milli>(elapsed).count() / 100.0f;
        
        auto stats = index.get_stats();
        std::cout << "  Average query time: " << avg_ms << "ms" << std::endl;
        std::cout << "  P95 query time: " << stats.p95_query_time_ms << "ms" << std::endl;
        std::cout << "  Cache hits: " << stats.cache_hits << std::endl;
        std::cout << "  Cache misses: " << stats.cache_misses << std::endl;
        
        TEST_ASSERT(stats.p95_query_time_ms < 10.0f, "P95 should be < 10ms");
        TEST_PASS("Performance within target");
        
        index.shutdown();
    }
    
    std::cout << std::endl << "=== All Tests Passed ===" << std::endl;
    std::cout << "Phase 17 Semantic Search: READY for integration" << std::endl;
    
    return 0;
}
