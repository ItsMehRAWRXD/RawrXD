// Console test harness for GGUF loader architecture detection
// Build: cl.exe /EHsc /W3 /O2 /I. /Isrc /Iinclude test_gguf_loader_console.cpp src\streaming_gguf_loader.cpp src\gguf_loader.cpp /Fe:test_gguf_loader.exe /link

#include "streaming_gguf_loader.h"
#include "gguf_loader.h"
#include <iostream>
#include <cstring>

int main(int argc, char** argv) {
    std::cerr << "========================================" << std::endl;
    std::cerr << "GGUF Loader Architecture Detection Test" << std::endl;
    std::cerr << "========================================" << std::endl;
    
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf>" << std::endl;
        std::cerr << "\nTests architecture detection for Qwen/Llama/Phi3/Gemma models" << std::endl;
        return 1;
    }

    const char* modelPath = argv[1];
    std::cerr << "\n[TEST] Loading: " << modelPath << std::endl;

    RawrXD::StreamingGGUFLoader loader;
    
    // Open the model - this triggers ParseMetadata with architecture detection
    if (!loader.Open(modelPath)) {
        std::cerr << "[FAIL] Could not open model file" << std::endl;
        return 1;
    }

    // Get the metadata that was parsed
    auto metadata = loader.GetMetadata();
    
    std::cerr << "\n========================================" << std::endl;
    std::cerr << "METADATA DETECTED" << std::endl;
    std::cerr << "========================================" << std::endl;
    std::cerr << "Architecture Type: " << metadata.architecture_type << " (1=llama, 2=qwen2, 3=phi3, 4=gemma)" << std::endl;
    std::cerr << "Layer Count:       " << metadata.layer_count << std::endl;
    std::cerr << "Context Length:    " << metadata.context_length << std::endl;
    std::cerr << "Embedding Dim:     " << metadata.embedding_dim << std::endl;
    std::cerr << "Vocab Size:        " << metadata.vocab_size << std::endl;
    std::cerr << "KV Pairs:          " << metadata.kv_pairs.size() << std::endl;
    
    // Validation for Qwen3.5-40B
    bool isQwen = (metadata.architecture_type == 2);
    bool hasLayers = (metadata.layer_count > 0);
    bool hasContext = (metadata.context_length > 1000);
    bool hasEmbedding = (metadata.embedding_dim > 0);
    
    std::cerr << "\n========================================" << std::endl;
    std::cerr << "VALIDATION" << std::endl;
    std::cerr << "========================================" << std::endl;
    std::cerr << "Is Qwen architecture: " << (isQwen ? "PASS" : "FAIL") << std::endl;
    std::cerr << "Has layer count:      " << (hasLayers ? "PASS" : "FAIL") << std::endl;
    std::cerr << "Has context length:   " << (hasContext ? "PASS" : "FAIL") << std::endl;
    std::cerr << "Has embedding dim:    " << (hasEmbedding ? "PASS" : "FAIL") << std::endl;
    
    // Overall result
    bool allPassed = isQwen && hasLayers && hasContext && hasEmbedding;
    
    if (allPassed) {
        std::cerr << "\n✓ ALL TESTS PASSED - Architecture detection is working!" << std::endl;
        return 0;
    } else {
        std::cerr << "\n✗ SOME TESTS FAILED - Architecture detection needs work" << std::endl;
        return 1;
    }
}
