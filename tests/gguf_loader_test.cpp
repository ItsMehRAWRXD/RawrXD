/**
 * @file gguf_loader_test.cpp
 * @brief Real GGUF loader validation test
 * 
 * Tests loading actual GGUF files.
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <memory>
#include <chrono>
#include "../src/agentic/GGUFLoader.h"
#include "../src/agentic/Logger.h"

using namespace RawrXD::Agentic;

int main(int argc, char* argv[]) {
    std::cout << "🔬 GGUF Loader Real File Test\n";
    std::cout << "==============================\n\n";
    
    Logger::Instance().Initialize();
    Logger::Instance().SetLevel(LogLevel::Info);
    
    // Get model path from args or use default
    std::string modelPath = (argc > 1) ? argv[1] : "D:/phi3mini.gguf";
    
    std::cout << "Testing with: " << modelPath << "\n\n";
    
    // Check if file exists and is valid GGUF
    std::cout << "[1/4] Checking GGUF validity...\n";
    if (!GGUFLoader::IsValidGGUF(modelPath)) {
        std::cerr << "    ❌ File is not a valid GGUF\n";
        std::cerr << "    (File may not exist or has wrong magic number)\n";
        return 1;
    }
    std::cout << "    ✅ Valid GGUF file detected\n\n";
    
    // Load the model
    std::cout << "[2/4] Loading GGUF file...\n";
    auto start = std::chrono::high_resolution_clock::now();
    
    GGUFLoader loader;
    auto result = loader.Load(modelPath);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    if (result.IsErr()) {
        std::cerr << "    ❌ Load failed: " << result.Message() << "\n";
        return 1;
    }
    
    auto model = std::move(result.Value());
    std::cout << "    ✅ Loaded in " << duration << "ms\n\n";
    
    // Display model info
    std::cout << "[3/4] Model Information:\n";
    std::cout << "    Path: " << model->path << "\n";
    std::cout << "    Architecture: " << (model->architecture.empty() ? "unknown" : model->architecture) << "\n";
    std::cout << "    Vocab Size: " << model->vocabSize << "\n";
    std::cout << "    Hidden Size: " << model->hiddenSize << "\n";
    std::cout << "    Layers: " << model->numLayers << "\n";
    std::cout << "    Heads: " << model->numHeads << "\n";
    std::cout << "    Context Length: " << model->contextLength << "\n";
    std::cout << "    Tensors: " << model->tensors.size() << "\n";
    std::cout << "    GGML Context: " << (model->ctx ? "initialized" : "null") << "\n\n";
    
    // Display metadata
    std::cout << "[4/4] Metadata (" << model->metadata.size() << " entries):\n";
    int count = 0;
    for (const auto& [key, value] : model->metadata) {
        std::cout << "    " << key << " = " << value << "\n";
        if (++count >= 10) {
            std::cout << "    ... (" << (model->metadata.size() - 10) << " more)\n";
            break;
        }
    }
    
    // Display first few tensors
    std::cout << "\n    First 5 tensors:\n";
    for (size_t i = 0; i < std::min(size_t(5), model->tensors.size()); i++) {
        const auto& t = model->tensors[i];
        std::cout << "    - " << t.name << " [";
        for (int d = 0; d < t.n_dims; d++) {
            if (d > 0) std::cout << "x";
            std::cout << t.dims[d];
        }
        std::cout << "] type=" << t.type << "\n";
    }
    
    std::cout << "\n==============================\n";
    std::cout << "✅ GGUF loader test PASSED\n";
    std::cout << "Real GGUF file loaded successfully!\n";
    
    Logger::Instance().Shutdown();
    return 0;
}
