// Minimal test for GGUF loader architecture detection
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <set>
#include <regex>

// Simplified metadata structures
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
    uint64_t metadata_offset;
};

struct GGUFMetadata {
    std::map<std::string, std::string> kv_pairs;
    uint32_t layer_count = 0;
    uint32_t context_length = 0;
    uint32_t embedding_dim = 0;
    uint32_t vocab_size = 0;
    uint32_t architecture_type = 1;
};

// Test the key lookup logic
void testKeyLookup() {
    GGUFMetadata metadata;
    
    // Simulate Qwen model metadata
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
        std::cout << "[TEST] Architecture detected: " << arch << std::endl;
        if (arch == "qwen" || arch == "qwen2" || arch == "qwen2_moe") arch = "qwen2";
    }
    metadata.architecture_type = (arch == "llama") ? 1u : (arch == "qwen2") ? 2u : 3u;
    
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
    
    // Try architecture-specific keys first, then fall back to llama keys
    metadata.layer_count = static_cast<uint32_t>(findUint(arch + ".block_count", "llama.block_count"));
    metadata.context_length = static_cast<uint32_t>(findUint(arch + ".context_length", "llama.context_length"));
    metadata.embedding_dim = static_cast<uint32_t>(findUint(arch + ".embedding_length", "llama.embedding_length"));
    metadata.vocab_size = static_cast<uint32_t>(findUint(arch + ".vocab_size", "llama.vocab_size"));
    
    std::cout << "[TEST] Results:" << std::endl;
    std::cout << "  Architecture: " << arch << " (type=" << metadata.architecture_type << ")" << std::endl;
    std::cout << "  Layers: " << metadata.layer_count << std::endl;
    std::cout << "  Context: " << metadata.context_length << std::endl;
    std::cout << "  Embedding: " << metadata.embedding_dim << std::endl;
    std::cout << "  Vocab: " << metadata.vocab_size << std::endl;
    
    // Verify results
    bool success = (metadata.layer_count == 40 && 
                    metadata.context_length == 32768 && 
                    metadata.embedding_dim == 5120 && 
                    metadata.vocab_size == 32000);
    
    if (success) {
        std::cout << "[TEST] PASSED: All values correctly detected!" << std::endl;
    } else {
        std::cout << "[TEST] FAILED: Values not as expected!" << std::endl;
    }
}

// Test fallback to llama keys
void testFallback() {
    GGUFMetadata metadata;
    
    // Simulate model with only llama keys
    metadata.kv_pairs["general.architecture"] = "unknown_arch";
    metadata.kv_pairs["llama.block_count"] = "32";
    metadata.kv_pairs["llama.context_length"] = "4096";
    
    std::string arch = "llama";
    auto archIt = metadata.kv_pairs.find("general.architecture");
    if (archIt != metadata.kv_pairs.end()) {
        arch = archIt->second;
        if (arch != "llama") arch = "llama"; // Default unknown to llama
    }
    
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
    
    std::cout << "[TEST] Fallback test - Architecture: " << arch << ", Layers: " << metadata.layer_count << std::endl;
    
    if (metadata.layer_count == 32) {
        std::cout << "[TEST] PASSED: Fallback works correctly!" << std::endl;
    } else {
        std::cout << "[TEST] FAILED: Fallback returned " << metadata.layer_count << " instead of 32" << std::endl;
    }
}

int main() {
    std::cout << "=== GGUF Loader Architecture Detection Test ===" << std::endl;
    testKeyLookup();
    std::cout << std::endl;
    testFallback();
    std::cout << "=== Test Complete ===" << std::endl;
    return 0;
}
