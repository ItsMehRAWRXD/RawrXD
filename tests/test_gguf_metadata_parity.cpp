#include "gguf_loader.h"
#include <iostream>
#include <cassert>
#include <filesystem>
#include <map>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: test_gguf_metadata_parity <model.gguf>" << std::endl;
        return 1;
    }
    
    std::string model_path = argv[1];
    if (!std::filesystem::exists(model_path)) {
        std::cerr << "Model file not found: " << model_path << std::endl;
        return 1;
    }
    
    try {
        std::cout << "=== RawrXD GGUF Loader Metadata Parity Test ===" << std::endl;
        std::cout << "Model: " << model_path << std::endl;
        
        GGUFLoader loader;
        
        if (!loader.Open(model_path)) {
            std::cerr << "Failed to open GGUF file: " << loader.GetLastError() << std::endl;
            return 1;
        }
        std::cout << "✓ File opened successfully" << std::endl;
        
        GGUFHeader header = loader.GetHeader();
        std::cout << "  Magic: 0x" << std::hex << header.magic << std::dec << std::endl;
        std::cout << "  Version: " << header.version << std::endl;
        std::cout << "  Tensors: " << header.tensor_count << std::endl;
        std::cout << "  Metadata KV pairs: " << header.metadata_kv_count << std::endl;
        
        if (!loader.ParseMetadata()) {
            std::cerr << "Failed to parse metadata" << std::endl;
            return 1;
        }
        
        GGUFMetadata metadata = loader.GetMetadata();
        
        std::cout << "\n=== PARSED METADATA ===" << std::endl;
        std::cout << "Architecture type: " << metadata.architecture_type << std::endl;
        std::cout << "Layer count: " << metadata.layer_count << std::endl;
        std::cout << "Context length: " << metadata.context_length << std::endl;
        std::cout << "Embedding dim: " << metadata.embedding_dim << std::endl;
        std::cout << "Vocab size: " << metadata.vocab_size << std::endl;
        std::cout << "Tokens count: " << metadata.tokens.size() << std::endl;
        
        // Check for llama.* normalized keys
        std::cout << "\n=== NORMALIZED LLAMA.* KEYS ===" << std::endl;
        const std::vector<std::string> llama_keys = {
            "llama.block_count", "llama.context_length", "llama.embedding_length",
            "llama.vocab_size", "llama.feed_forward_length"
        };
        for (const auto& key : llama_keys) {
            auto it = metadata.kv_pairs.find(key);
            if (it != metadata.kv_pairs.end()) {
                std::cout << "  " << key << " = " << it->second << std::endl;
            } else {
                std::cout << "  " << key << " = (not found)" << std::endl;
            }
        }
        
        // Check original architecture-specific keys
        std::cout << "\n=== ARCHITECTURE-SPECIFIC KEYS ===" << std::endl;
        const std::vector<std::string> arch_keys = {
            "phi3.block_count", "phi3.context_length", "phi3.embedding_length",
            "phi3.feed_forward_length", "phi3.vocab_size", "phi3.attention.head_count",
            "phi3.rope.freq_base", "general.architecture", "general.architecture.embedding_length"
        };
        for (const auto& key : arch_keys) {
            auto it = metadata.kv_pairs.find(key);
            if (it != metadata.kv_pairs.end()) {
                std::cout << "  " << key << " = " << it->second << std::endl;
            }
        }
        
        // Verify parity with standalone Deep2Engine expected values
        std::cout << "\n=== PARITY CHECK vs STANDALONE DEEP2ENGINE ===" << std::endl;
        bool parity_ok = true;
        
        // Expected from standalone Deep2Engine run
        struct ExpectedValue { const char* key; uint32_t expected; };
        ExpectedValue expected[] = {
            {"layer_count", 32},
            {"context_length", 131072},  // maxSeqLen from phi3.context_length
            {"embedding_dim", 3072},
            {"intermediate_dim", 8192},  // Not directly in metadata, from feed_forward_length
            {"vocab_size", 32064},
            {"num_heads", 32}  // Not in metadata struct, would need attention.head_count
        };
        
        // Check layer_count
        if (metadata.layer_count != 32) {
            std::cerr << "  ✗ layer_count: got " << metadata.layer_count << ", expected 32" << std::endl;
            parity_ok = false;
        } else {
            std::cout << "  ✓ layer_count = 32" << std::endl;
        }
        
        // Check context_length
        if (metadata.context_length != 131072) {
            std::cerr << "  ✗ context_length: got " << metadata.context_length << ", expected 131072" << std::endl;
            parity_ok = false;
        } else {
            std::cout << "  ✓ context_length = 131072" << std::endl;
        }
        
        // Check embedding_dim
        if (metadata.embedding_dim != 3072) {
            std::cerr << "  ✗ embedding_dim: got " << metadata.embedding_dim << ", expected 3072" << std::endl;
            parity_ok = false;
        } else {
            std::cout << "  ✓ embedding_dim = 3072" << std::endl;
        }
        
        // Check vocab_size
        if (metadata.vocab_size != 32064) {
            std::cerr << "  ✗ vocab_size: got " << metadata.vocab_size << ", expected 32064" << std::endl;
            parity_ok = false;
        } else {
            std::cout << "  ✓ vocab_size = 32064" << std::endl;
        }
        
        // Check llama.* normalized keys exist
        auto check_normalized = [&](const std::string& key, const std::string& expected) {
            auto it = metadata.kv_pairs.find(key);
            if (it == metadata.kv_pairs.end()) {
                std::cerr << "  ✗ Normalized key " << key << " not found" << std::endl;
                parity_ok = false;
            } else if (it->second != expected) {
                std::cerr << "  ✗ Normalized key " << key << ": got " << it->second << ", expected " << expected << std::endl;
                parity_ok = false;
            } else {
                std::cout << "  ✓ " << key << " = " << it->second << std::endl;
            }
        };
        
        check_normalized("llama.block_count", "32");
        check_normalized("llama.context_length", "131072");
        check_normalized("llama.embedding_length", "3072");
        check_normalized("llama.vocab_size", "32064");
        
        std::cout << "\n=== RESULT ===" << std::endl;
        if (parity_ok) {
            std::cout << "✓ PARITY TEST PASSED - RawrXD loader matches standalone Deep2Engine" << std::endl;
            return 0;
        } else {
            std::cerr << "✗ PARITY TEST FAILED - Metadata mismatch detected" << std::endl;
            return 1;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}