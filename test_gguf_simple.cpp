// Simple GGUF loader test - standalone console application
// Build: cl /std:c++20 /EHsc /W3 /O2 /I. /Isrc /Iinclude test_gguf_simple.cpp src\streaming_gguf_loader.cpp src\gguf_loader.cpp /Fe:test_gguf_simple.exe /link

#include "streaming_gguf_loader.h"
#include "gguf_loader.h"
#include <iostream>
#include <fstream>
#include <cstring>

// Simple hex dump for debugging
void hexDump(const char* label, const void* data, size_t len) {
    const unsigned char* bytes = static_cast<const unsigned char*>(data);
    std::cerr << label << " (" << len << " bytes): ";
    for (size_t i = 0; i < std::min(len, (size_t)32); i++) {
        char buf[4];
        sprintf_s(buf, "%02x", bytes[i]);
        std::cerr << buf;
    }
    if (len > 32) std::cerr << "...";
    std::cerr << std::endl;
}

int main(int argc, char** argv) {
    std::cerr << "========================================" << std::endl;
    std::cerr << "GGUF Loader Simple Test" << std::endl;
    std::cerr << "========================================" << std::endl;
    
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf>" << std::endl;
        
        // Try to find a GGUF file automatically
        const char* testPaths[] = {
            "F:\\OllamaModels\\Qwen3.5-40B.Q4_K_M.gguf",
            "F:\\OllamaModels\\*.gguf",
            "gemma3-1b-Q2_K.gguf",
            "phi3-mini-Q2_K.gguf",
            "llama3.2-3b-Q2_K.gguf"
        };
        
        for (const char* path : testPaths) {
            std::ifstream test(path, std::ios::binary);
            if (test.is_open()) {
                std::cerr << "Found test file: " << path << std::endl;
                test.close();
                // Re-run with this path
                argv[1] = const_cast<char*>(path);
                argc = 2;
                break;
            }
        }
        
        if (argc < 2) {
            std::cerr << "No GGUF file found. Please specify one." << std::endl;
            return 1;
        }
    }

    const char* modelPath = argv[1];
    std::cerr << "\n[TEST] Loading: " << modelPath << std::endl;

    RawrXD::StreamingGGUFLoader loader;
    
    // Open the model
    if (!loader.Open(modelPath)) {
        std::cerr << "[FAIL] Could not open model file" << std::endl;
        return 1;
    }

    // Get the metadata
    auto metadata = loader.GetMetadata();
    auto header = loader.GetHeader();
    
    std::cerr << "\n========================================" << std::endl;
    std::cerr << "GGUF HEADER" << std::endl;
    std::cerr << "========================================" << std::endl;
    std::cerr << "Magic:          0x" << std::hex << header.magic << std::dec << std::endl;
    std::cerr << "Version:        " << header.version << std::endl;
    std::cerr << "Tensor count:   " << header.tensor_count << std::endl;
    std::cerr << "Metadata count: " << header.metadata_kv_count << std::endl;
    
    std::cerr << "\n========================================" << std::endl;
    std::cerr << "METADATA DETECTED" << std::endl;
    std::cerr << "========================================" << std::endl;
    std::cerr << "Architecture Type: " << metadata.architecture_type << " (1=llama, 2=qwen2, 3=phi3, 4=gemma)" << std::endl;
    std::cerr << "Layer Count:       " << metadata.layer_count << std::endl;
    std::cerr << "Context Length:    " << metadata.context_length << std::endl;
    std::cerr << "Embedding Dim:     " << metadata.embedding_dim << std::endl;
    std::cerr << "Vocab Size:        " << metadata.vocab_size << std::endl;
    std::cerr << "Head Count:        " << metadata.head_count << std::endl;
    std::cerr << "KV Pairs:          " << metadata.kv_pairs.size() << std::endl;
    
    // Print all kv_pairs that contain architecture info
    std::cerr << "\n========================================" << std::endl;
    std::cerr << "ARCHITECTURE-RELATED KEYS" << std::endl;
    std::cerr << "========================================" << std::endl;
    for (const auto& [key, value] : metadata.kv_pairs) {
        if (key.find("architecture") != std::string::npos ||
            key.find("block_count") != std::string::npos ||
            key.find("context_length") != std::string::npos ||
            key.find("embedding_length") != std::string::npos ||
            key.find("vocab_size") != std::string::npos ||
            key.find("general.") != std::string::npos) {
            std::cerr << key << " = " << value << std::endl;
        }
    }
    
    // Print first few tensor names to see naming pattern
    std::cerr << "\n========================================" << std::endl;
    std::cerr << "FIRST 10 TENSORS" << std::endl;
    std::cerr << "========================================" << std::endl;
    auto tensorInfo = loader.GetTensorInfo();
    for (size_t i = 0; i < std::min(tensorInfo.size(), (size_t)10); i++) {
        std::cerr << i << ": " << tensorInfo[i].name << std::endl;
    }
    
    // Validation
    std::cerr << "\n========================================" << std::endl;
    std::cerr << "VALIDATION" << std::endl;
    std::cerr << "========================================" << std::endl;
    
    bool hasArch = metadata.architecture_type != 0;
    bool hasLayers = metadata.layer_count > 0;
    bool hasContext = metadata.context_length > 0;
    bool hasEmbedding = metadata.embedding_dim > 0;
    
    std::cerr << "Has architecture:   " << (hasArch ? "PASS" : "FAIL") << std::endl;
    std::cerr << "Has layer count:    " << (hasLayers ? "PASS" : "FAIL") << std::endl;
    std::cerr << "Has context length: " << (hasContext ? "PASS" : "FAIL") << std::endl;
    std::cerr << "Has embedding dim:  " << (hasEmbedding ? "PASS" : "FAIL") << std::endl;
    
    bool allPassed = hasArch && hasLayers && hasContext && hasEmbedding;
    
    if (allPassed) {
        std::cerr << "\n✓ ALL TESTS PASSED" << std::endl;
        return 0;
    } else {
        std::cerr << "\n✗ SOME TESTS FAILED" << std::endl;
        return 1;
    }
}
