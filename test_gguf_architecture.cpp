// Simple test to verify GGUF architecture detection
#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <cstdint>

// Minimal GGUF structures for testing
struct TestGGUFMetadata {
    std::map<std::string, std::string> kv_pairs;
    uint32_t layer_count = 0;
    uint32_t context_length = 0;
    uint32_t embedding_dim = 0;
    uint32_t vocab_size = 0;
    uint32_t architecture_type = 1;
};

// Test the architecture detection logic
void testArchitectureDetection() {
    std::cout << "=== Testing GGUF Architecture Detection ===" << std::endl;
    
    // Test Case 1: Qwen model
    {
        TestGGUFMetadata metadata;
        metadata.kv_pairs["general.architecture"] = "qwen2";
        metadata.kv_pairs["qwen2.block_count"] = "40";
        metadata.kv_pairs["qwen2.context_length"] = "32768";
        metadata.kv_pairs["qwen2.embedding_length"] = "5120";
        metadata.kv_pairs["qwen2.vocab_size"] = "32000";
        
        // Detect architecture
        std::string arch = "llama";
        auto archIt = metadata.kv_pairs.find("general.architecture");
        if (archIt != metadata.kv_pairs.end()) {
            arch = archIt->second;
            if (arch == "qwen" || arch == "qwen2" || arch == "qwen2_moe") arch = "qwen2";
            else if (arch == "phi" || arch == "phi3") arch = "phi3";
            else if (arch == "gemma" || arch == "gemma2") arch = "gemma";
            else if (arch != "llama") arch = "llama";
        }
        metadata.architecture_type = (arch == "llama") ? 1u : (arch == "qwen2") ? 2u : (arch == "phi3") ? 3u : 4u;
        
        // Lambda to find uint with fallback
        auto findUint = [&metadata](const std::string& key, const std::string& fallback = "") -> uint64_t {
            auto it = metadata.kv_pairs.find(key);
            if (it == metadata.kv_pairs.end() && !fallback.empty()) {
                it = metadata.kv_pairs.find(fallback);
            }
            if (it == metadata.kv_pairs.end()) {
                return 0;
            }
            try {
                return std::stoull(it->second);
            } catch (...) {
                return 0;
            }
        };
        
        metadata.layer_count = static_cast<uint32_t>(findUint(arch + ".block_count", "llama.block_count"));
        metadata.context_length = static_cast<uint32_t>(findUint(arch + ".context_length", "llama.context_length"));
        metadata.embedding_dim = static_cast<uint32_t>(findUint(arch + ".embedding_length", "llama.embedding_length"));
        metadata.vocab_size = static_cast<uint32_t>(findUint(arch + ".vocab_size", "llama.vocab_size"));
        
        std::cout << "\n[Test 1: Qwen Model]" << std::endl;
        std::cout << "  Architecture: " << arch << " (type=" << metadata.architecture_type << ")" << std::endl;
        std::cout << "  Layers: " << metadata.layer_count << std::endl;
        std::cout << "  Context: " << metadata.context_length << std::endl;
        std::cout << "  Embedding: " << metadata.embedding_dim << std::endl;
        std::cout << "  Vocab: " << metadata.vocab_size << std::endl;
        
        bool pass = (metadata.layer_count == 40 && metadata.context_length == 32768 && 
                     metadata.embedding_dim == 5120 && metadata.vocab_size == 32000);
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << std::endl;
    }
    
    // Test Case 2: Llama model (fallback test)
    {
        TestGGUFMetadata metadata;
        metadata.kv_pairs["general.architecture"] = "llama";
        metadata.kv_pairs["llama.block_count"] = "32";
        metadata.kv_pairs["llama.context_length"] = "4096";
        
        std::string arch = "llama";
        auto archIt = metadata.kv_pairs.find("general.architecture");
        if (archIt != metadata.kv_pairs.end()) {
            arch = archIt->second;
            if (arch == "qwen" || arch == "qwen2" || arch == "qwen2_moe") arch = "qwen2";
            else if (arch == "phi" || arch == "phi3") arch = "phi3";
            else if (arch == "gemma" || arch == "gemma2") arch = "gemma";
            else if (arch != "llama") arch = "llama";
        }
        
        auto findUint = [&metadata](const std::string& key, const std::string& fallback = "") -> uint64_t {
            auto it = metadata.kv_pairs.find(key);
            if (it == metadata.kv_pairs.end() && !fallback.empty()) {
                it = metadata.kv_pairs.find(fallback);
            }
            if (it == metadata.kv_pairs.end()) return 0;
            try { return std::stoull(it->second); } catch (...) { return 0; }
        };
        
        metadata.layer_count = static_cast<uint32_t>(findUint(arch + ".block_count", "llama.block_count"));
        
        std::cout << "\n[Test 2: Llama Model]" << std::endl;
        std::cout << "  Architecture: " << arch << std::endl;
        std::cout << "  Layers: " << metadata.layer_count << std::endl;
        
        bool pass = (metadata.layer_count == 32);
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << std::endl;
    }
    
    // Test Case 3: Unknown architecture (should fallback to llama)
    {
        TestGGUFMetadata metadata;
        metadata.kv_pairs["general.architecture"] = "unknown_arch";
        metadata.kv_pairs["llama.block_count"] = "24";
        
        std::string arch = "llama";
        auto archIt = metadata.kv_pairs.find("general.architecture");
        if (archIt != metadata.kv_pairs.end()) {
            arch = archIt->second;
            if (arch == "qwen" || arch == "qwen2" || arch == "qwen2_moe") arch = "qwen2";
            else if (arch == "phi" || arch == "phi3") arch = "phi3";
            else if (arch == "gemma" || arch == "gemma2") arch = "gemma";
            else if (arch != "llama") arch = "llama";
        }
        
        auto findUint = [&metadata](const std::string& key, const std::string& fallback = "") -> uint64_t {
            auto it = metadata.kv_pairs.find(key);
            if (it == metadata.kv_pairs.end() && !fallback.empty()) {
                it = metadata.kv_pairs.find(fallback);
            }
            if (it == metadata.kv_pairs.end()) return 0;
            try { return std::stoull(it->second); } catch (...) { return 0; }
        };
        
        metadata.layer_count = static_cast<uint32_t>(findUint(arch + ".block_count", "llama.block_count"));
        
        std::cout << "\n[Test 3: Unknown Architecture Fallback]" << std::endl;
        std::cout << "  Input: unknown_arch" << std::endl;
        std::cout << "  Normalized: " << arch << std::endl;
        std::cout << "  Layers: " << metadata.layer_count << std::endl;
        
        bool pass = (arch == "llama" && metadata.layer_count == 24);
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << std::endl;
    }
    
    std::cout << "\n=== All Tests Complete ===" << std::endl;
}

int main() {
    testArchitectureDetection();
    return 0;
}
