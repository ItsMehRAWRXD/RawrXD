// ============================================================================
// test_streaming_backend.cpp - Test Streaming Multi-Layer Backend
// ============================================================================

#include "streaming_multi_layer_backend.hpp"
#include "streaming_gguf_loader.hpp"
#include "streaming_layer_registry.hpp"
#include <iostream>
#include <iomanip>
#include <vector>

using namespace RawrXD::Runtime;

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " <gguf_file> [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --prompt \"text\"    Prompt text (default: \"Hello\")" << std::endl;
    std::cout << "  --tokens N         Max tokens to generate (default: 10)" << std::endl;
    std::cout << "  --temp T           Temperature (default: 1.0)" << std::endl;
    std::cout << "  --list             List tensors and exit" << std::endl;
}

// Simple tokenizer stub (would use real tokenizer in production)
std::vector<uint32_t> SimpleTokenize(const std::string& text) {
    // Stub: just return token IDs for each character
    std::vector<uint32_t> tokens;
    for (char c : text) {
        tokens.push_back(static_cast<uint32_t>(c));
    }
    return tokens;
}

int main(int argc, char* argv[]) {
    std::cout << "=== Streaming Multi-Layer Backend Test ===" << std::endl;
    std::cout << std::endl;
    
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    std::string filePath = argv[1];
    std::string prompt = "Hello";
    size_t maxTokens = 10;
    float temperature = 1.0f;
    bool listTensors = false;
    
    // Parse arguments
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--prompt" && i + 1 < argc) {
            prompt = argv[++i];
        } else if (arg == "--tokens" && i + 1 < argc) {
            maxTokens = std::stoul(argv[++i]);
        } else if (arg == "--temp" && i + 1 < argc) {
            temperature = std::stof(argv[++i]);
        } else if (arg == "--list") {
            listTensors = true;
        }
    }
    
    // ------------------------------------------------------------------------
    // Step 1: Open GGUF file
    // ------------------------------------------------------------------------
    std::cout << "Opening: " << filePath << std::endl;
    
    StreamingGGUFLoader loader;
    if (!loader.Open(filePath)) {
        std::cout << "✗ Failed to open GGUF file" << std::endl;
        return 1;
    }
    
    std::cout << "✓ GGUF file opened" << std::endl;
    std::cout << "  File size: " << loader.GetFileSize() << " bytes" << std::endl;
    std::cout << "  Tensors: " << loader.GetTensorCount() << std::endl;
    
    // Build index for fast lookup
    if (!loader.BuildIndex()) {
        std::cout << "✗ Failed to build tensor index" << std::endl;
        return 1;
    }
    
    std::cout << "✓ Tensor index built" << std::endl;
    
    // List tensors if requested
    if (listTensors) {
        std::cout << "\nTensors:" << std::endl;
        TensorInfo info;
        while (loader.NextTensor(info)) {
            std::cout << "  " << info.name << " [";
            for (size_t i = 0; i < info.shape.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << info.shape[i];
            }
            std::cout << "]" << std::endl;
        }
        return 0;
    }
    
    // ------------------------------------------------------------------------
    // Step 2: Initialize streaming backend
    // ------------------------------------------------------------------------
    std::cout << std::endl << "--- Initializing Streaming Backend ---" << std::endl;
    
    StreamingMultiLayerBackend backend;
    if (!backend.Initialize(loader)) {
        std::cout << "✗ Failed to initialize backend" << std::endl;
        return 1;
    }
    
    std::cout << "✓ Backend initialized" << std::endl;
    std::cout << "  Vocab size: " << backend.GetVocabSize() << std::endl;
    std::cout << "  Hidden size: " << backend.GetHiddenSize() << std::endl;
    std::cout << "  Num layers: " << backend.GetNumLayers() << std::endl;
    std::cout << "  Max seq len: " << backend.GetMaxSeqLen() << std::endl;
    
    // ------------------------------------------------------------------------
    // Step 3: Tokenize prompt
    // ------------------------------------------------------------------------
    std::cout << std::endl << "--- Tokenizing Prompt ---" << std::endl;
    std::cout << "Prompt: \"" << prompt << "\"" << std::endl;
    
    std::vector<uint32_t> promptTokens = SimpleTokenize(prompt);
    std::cout << "Tokens: " << promptTokens.size() << std::endl;
    
    // ------------------------------------------------------------------------
    // Step 4: Generate
    // ------------------------------------------------------------------------
    std::cout << std::endl << "--- Generating ---" << std::endl;
    std::cout << "Max tokens: " << maxTokens << ", Temperature: " << temperature << std::endl;
    
    std::vector<uint32_t> outputTokens;
    bool success = backend.Generate(promptTokens, outputTokens, maxTokens, temperature, 40);
    
    if (!success) {
        std::cout << "✗ Generation failed" << std::endl;
        return 1;
    }
    
    std::cout << "✓ Generation complete" << std::endl;
    std::cout << "Generated " << outputTokens.size() << " tokens" << std::endl;
    
    // ------------------------------------------------------------------------
    // Step 5: Output results
    // ------------------------------------------------------------------------
    std::cout << std::endl << "--- Output ---" << std::endl;
    std::cout << "Tokens: ";
    for (auto t : outputTokens) {
        std::cout << t << " ";
    }
    std::cout << std::endl;
    
    // Convert back to text (stub)
    std::string outputText;
    for (auto t : outputTokens) {
        if (t < 256) outputText += static_cast<char>(t);
    }
    std::cout << "Text: \"" << outputText << "\"" << std::endl;
    
    std::cout << std::endl << "=== Test Complete ===" << std::endl;
    
    return 0;
}
