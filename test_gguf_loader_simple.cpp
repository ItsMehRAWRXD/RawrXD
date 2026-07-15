// Simple test for GGUF loader architecture detection
#include "streaming_gguf_loader.h"
#include "gguf_loader.h"
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf>" << std::endl;
        return 1;
    }

    std::string modelPath = argv[1];
    std::cerr << "[Test] Loading model: " << modelPath << std::endl;

    RawrXD::StreamingGGUFLoader loader;
    
    if (!loader.Open(modelPath)) {
        std::cerr << "[Test] FAILED: Could not open model" << std::endl;
        return 1;
    }

    auto metadata = loader.GetMetadata();
    
    std::cerr << "\n[Test] === METADATA DETECTED ===" << std::endl;
    std::cerr << "[Test] Architecture Type: " << metadata.architecture_type << std::endl;
    std::cerr << "[Test] Layer Count: " << metadata.layer_count << std::endl;
    std::cerr << "[Test] Context Length: " << metadata.context_length << std::endl;
    std::cerr << "[Test] Embedding Dim: " << metadata.embedding_dim << std::endl;
    std::cerr << "[Test] Vocab Size: " << metadata.vocab_size << std::endl;
    std::cerr << "[Test] KV Pairs: " << metadata.kv_pairs.size() << std::endl;
    
    // Check if architecture was detected
    bool success = (metadata.layer_count > 0) && (metadata.architecture_type > 0);
    
    if (success) {
        std::cerr << "\n[Test] SUCCESS: Model loaded with architecture detection" << std::endl;
        return 0;
    } else {
        std::cerr << "\n[Test] FAILED: Architecture not properly detected" << std::endl;
        return 1;
    }
}
