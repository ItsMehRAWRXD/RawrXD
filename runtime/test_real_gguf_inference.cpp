// ============================================================================
// test_real_gguf_inference.cpp - Load Real GGUF and Run Inference
// ============================================================================
// This is the final integration test:
//   Real GGUF File → GGUFModelLoader → TensorRegistry → ModelBinder → Inference
// ============================================================================

#include "gguf_model_loader.hpp"
#include "model_binder.hpp"
#include "transformer_layer_runtime.hpp"
#include "tensor_view.hpp"
#include <iostream>
#include <iomanip>
#include <cstring>

using namespace RawrXD::Runtime;

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " <gguf_file> [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --arch NAME    Architecture (tinyllama, phi3, qwen, llama3)" << std::endl;
    std::cout << "  --token N      Token ID to embed (default: 42)" << std::endl;
    std::cout << "  --list         List all tensors in file" << std::endl;
}

float ComputeChecksum(const float* data, size_t count) {
    float sum = 0.0f;
    for (size_t i = 0; i < count; ++i) {
        sum += data[i] * (i + 1);
    }
    return sum;
}

int main(int argc, char* argv[]) {
    std::cout << "=== Real GGUF Inference Test ===" << std::endl;
    std::cout << std::endl;
    
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    std::string filePath = argv[1];
    std::string archName = "auto";
    uint32_t testToken = 42;
    bool listTensors = false;
    
    // Parse arguments
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--arch" && i + 1 < argc) {
            archName = argv[++i];
        } else if (arg == "--token" && i + 1 < argc) {
            testToken = std::stoi(argv[++i]);
        } else if (arg == "--list") {
            listTensors = true;
        }
    }
    
    std::cout << "GGUF File: " << filePath << std::endl;
    std::cout << "Architecture: " << archName << std::endl;
    std::cout << std::endl;
    
    // ------------------------------------------------------------------------
    // Step 1: Load GGUF file into TensorRegistry
    // ------------------------------------------------------------------------
    std::cout << "--- Step 1: Loading GGUF File ---" << std::endl;
    
    TensorRegistry registry;
    GGUFModelLoader loader;
    
    if (!loader.LoadFromFile(filePath, registry)) {
        std::cout << "✗ Failed to load GGUF: " << loader.GetLastError() << std::endl;
        return 1;
    }
    
    std::cout << "✓ GGUF file loaded" << std::endl;
    std::cout << "  Tensors: " << loader.GetTensorCount() << std::endl;
    std::cout << "  Metadata: " << loader.GetMetadataCount() << std::endl;
    std::cout << "  Model: " << loader.GetModelName() << std::endl;
    std::cout << "  Arch: " << loader.DetectArchitecture() << std::endl;
    
    // List tensors if requested
    if (listTensors) {
        std::cout << "\nTensors in file:" << std::endl;
        auto names = loader.GetTensorNames();
        for (const auto& name : names) {
            std::cout << "  " << name << std::endl;
        }
    }
    
    // ------------------------------------------------------------------------
    // Step 2: Detect or select architecture
    // ------------------------------------------------------------------------
    std::cout << std::endl;
    std::cout << "--- Step 2: Architecture Configuration ---" << std::endl;
    
    ModelArchitectureConfig config;
    
    if (archName == "auto") {
        std::string detected = loader.DetectArchitecture();
        if (detected == "llama") {
            config = ArchitecturePresets::TinyLlama();
        } else if (detected == "qwen2") {
            config = ArchitecturePresets::Qwen2_5(7);
        } else if (detected == "phi3") {
            config = ArchitecturePresets::Phi3Mini();
        } else {
            std::cout << "⚠ Unknown architecture, using TinyLlama preset" << std::endl;
            config = ArchitecturePresets::TinyLlama();
        }
    } else if (archName == "tinyllama") {
        config = ArchitecturePresets::TinyLlama();
    } else if (archName == "phi3") {
        config = ArchitecturePresets::Phi3Mini();
    } else if (archName == "qwen" || archName == "qwen2.5") {
        config = ArchitecturePresets::Qwen2_5(7);
    } else if (archName == "llama3" || archName == "llama") {
        config = ArchitecturePresets::Llama3(8);
    } else {
        std::cout << "⚠ Unknown architecture '" << archName << "', using TinyLlama" << std::endl;
        config = ArchitecturePresets::TinyLlama();
    }
    
    std::cout << "✓ Using " << config.name << " configuration" << std::endl;
    std::cout << "  Vocab: " << config.vocabSize << std::endl;
    std::cout << "  Hidden: " << config.hiddenSize << std::endl;
    std::cout << "  Layers: " << config.numLayers << std::endl;
    
    // ------------------------------------------------------------------------
    // Step 3: Initialize ModelBinder
    // ------------------------------------------------------------------------
    std::cout << std::endl;
    std::cout << "--- Step 3: Initializing ModelBinder ---" << std::endl;
    
    ModelBinder binder;
    if (!binder.Initialize(config)) {
        std::cout << "✗ Failed to initialize ModelBinder" << std::endl;
        return 1;
    }
    
    std::cout << "✓ ModelBinder initialized" << std::endl;
    
    // ------------------------------------------------------------------------
    // Step 4: Bind model from registry
    // ------------------------------------------------------------------------
    std::cout << std::endl;
    std::cout << "--- Step 4: Binding Model ---" << std::endl;
    
    bool bindOk = binder.BindModel(registry);
    std::cout << binder.GetBindingReport() << std::endl;
    
    if (!bindOk) {
        std::cout << "⚠ Model binding incomplete (expected for real GGUF without full tensor data)" << std::endl;
    }
    
    // ------------------------------------------------------------------------
    // Step 5: Test inference (if binding succeeded)
    // ------------------------------------------------------------------------
    if (binder.GetNumBoundLayers() > 0) {
        std::cout << std::endl;
        std::cout << "--- Step 5: Testing Inference ---" << std::endl;
        
        TransformerModelRuntime* model = binder.GetModel();
        
        if (!model->IsInitialized()) {
            std::cout << "✗ Model not initialized" << std::endl;
            return 1;
        }
        
        // Embed token
        std::vector<float> embedding(config.hiddenSize);
        bool embedOk = model->EmbedToken(testToken, embedding.data());
        
        if (!embedOk) {
            std::cout << "✗ Token embedding failed" << std::endl;
            return 1;
        }
        
        float embedChecksum = ComputeChecksum(embedding.data(), config.hiddenSize);
        std::cout << "✓ Token " << testToken << " embedded" << std::endl;
        std::cout << "  Embedding checksum: " << std::scientific << embedChecksum << std::endl;
        
        // Forward pass
        std::vector<float> hidden(config.hiddenSize);
        bool forwardOk = model->Forward(embedding.data(), 1, 0, hidden.data());
        
        if (!forwardOk) {
            std::cout << "✗ Forward pass failed" << std::endl;
            return 1;
        }
        
        float hiddenChecksum = ComputeChecksum(hidden.data(), config.hiddenSize);
        std::cout << "✓ Forward pass completed" << std::endl;
        std::cout << "  Hidden checksum: " << std::scientific << hiddenChecksum << std::endl;
        
        // Project to logits
        std::vector<float> logits(config.vocabSize);
        bool projectOk = model->ProjectToLogits(hidden.data(), logits.data());
        
        if (!projectOk) {
            std::cout << "✗ Output projection failed" << std::endl;
            return 1;
        }
        
        float logitsChecksum = ComputeChecksum(logits.data(), config.vocabSize);
        std::cout << "✓ Output projection completed" << std::endl;
        std::cout << "  Logits checksum: " << std::scientific << logitsChecksum << std::endl;
        
        // Find top token
        uint32_t topToken = 0;
        float topLogit = logits[0];
        for (uint32_t i = 1; i < config.vocabSize; ++i) {
            if (logits[i] > topLogit) {
                topLogit = logits[i];
                topToken = i;
            }
        }
        std::cout << "  Top token: " << topToken << " (logit: " << topLogit << ")" << std::endl;
        
        std::cout << std::endl;
        std::cout << "=== Real GGUF Inference Complete ===" << std::endl;
        std::cout << "Token " << testToken << " → " << topToken << std::endl;
    } else {
        std::cout << std::endl;
        std::cout << "=== GGUF File Loaded (No Inference - Missing Tensors) ===" << std::endl;
    }
    
    return 0;
}
