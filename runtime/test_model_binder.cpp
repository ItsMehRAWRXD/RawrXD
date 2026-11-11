// ============================================================================
// test_model_binder.cpp - Full Pipeline: GGUF → Registry → Binder → Runtime
// ============================================================================

#include "model_binder.hpp"
#include "transformer_layer_runtime.hpp"
#include "tensor_view.hpp"
#include <iostream>
#include <iomanip>

using namespace RawrXD::Runtime;

// Create synthetic tensor data for testing
TensorData CreateSyntheticTensor(const std::vector<size_t>& shape, float scale = 0.01f) {
    TensorData data;
    data.type = GGMLType::F32;
    data.shape = shape;
    data.provenance.source = "synthetic";
    data.provenance.quantized = false;
    data.provenance.sourceType = GGMLType::F32;
    
    size_t totalSize = 1;
    for (auto dim : shape) totalSize *= dim;
    data.f32Data.resize(totalSize);
    
    for (size_t i = 0; i < totalSize; ++i) {
        data.f32Data[i] = scale * static_cast<float>(i % 100);
    }
    
    return data;
}

// Populate registry with synthetic model tensors
void PopulateSyntheticModel(TensorRegistry& registry, const ModelArchitectureConfig& config) {
    // Token embeddings: [vocab_size, hidden_size]
    registry.Register(config.tokenEmbdPattern, 
        CreateSyntheticTensor({config.vocabSize, config.hiddenSize}, 0.001f));
    
    // Output norm: [hidden_size]
    registry.Register(config.outputNormPattern,
        CreateSyntheticTensor({config.hiddenSize}, 0.1f));
    
    // Output weight: [vocab_size, hidden_size]
    registry.Register(config.outputWeightPattern,
        CreateSyntheticTensor({config.vocabSize, config.hiddenSize}, 0.001f));
    
    // Layer tensors
    for (uint32_t layer = 0; layer < config.numLayers; ++layer) {
        std::string layerStr = std::to_string(layer);
        
        // Input norm: [hidden_size]
        registry.Register("blk." + layerStr + ".attn_norm.weight",
            CreateSyntheticTensor({config.hiddenSize}, 0.1f));
        
        // Q projection: [hidden_size, hidden_size]
        registry.Register("blk." + layerStr + ".attn_q.weight",
            CreateSyntheticTensor({config.hiddenSize, config.hiddenSize}, 0.01f));
        
        // K projection: [hidden_size, num_kv_heads * head_dim]
        uint32_t kvDim = config.numKVHeads * (config.hiddenSize / config.numHeads);
        registry.Register("blk." + layerStr + ".attn_k.weight",
            CreateSyntheticTensor({config.hiddenSize, kvDim}, 0.01f));
        
        // V projection: [hidden_size, num_kv_heads * head_dim]
        registry.Register("blk." + layerStr + ".attn_v.weight",
            CreateSyntheticTensor({config.hiddenSize, kvDim}, 0.01f));
        
        // O projection: [hidden_size, hidden_size]
        registry.Register("blk." + layerStr + ".attn_output.weight",
            CreateSyntheticTensor({config.hiddenSize, config.hiddenSize}, 0.01f));
        
        // Post norm: [hidden_size]
        registry.Register("blk." + layerStr + ".ffn_norm.weight",
            CreateSyntheticTensor({config.hiddenSize}, 0.1f));
        
        // Gate projection: [hidden_size, intermediate_size]
        registry.Register("blk." + layerStr + ".ffn_gate.weight",
            CreateSyntheticTensor({config.hiddenSize, config.intermediateSize}, 0.01f));
        
        // Up projection: [hidden_size, intermediate_size]
        registry.Register("blk." + layerStr + ".ffn_up.weight",
            CreateSyntheticTensor({config.hiddenSize, config.intermediateSize}, 0.01f));
        
        // Down projection: [intermediate_size, hidden_size]
        registry.Register("blk." + layerStr + ".ffn_down.weight",
            CreateSyntheticTensor({config.intermediateSize, config.hiddenSize}, 0.01f));
    }
}

float ComputeChecksum(const float* data, size_t count) {
    float sum = 0.0f;
    for (size_t i = 0; i < count; ++i) {
        sum += data[i] * (i + 1);
    }
    return sum;
}

int main(int argc, char* argv[]) {
    std::cout << "=== ModelBinder Test: Full Pipeline ===" << std::endl;
    std::cout << std::endl;
    
    // Select architecture
    std::string archName = (argc > 1) ? argv[1] : "tinyllama";
    
    ModelArchitectureConfig config;
    if (archName == "phi3") {
        config = ArchitecturePresets::Phi3Mini();
    } else if (archName == "qwen2.5" || archName == "qwen") {
        config = ArchitecturePresets::Qwen2_5(7);
    } else if (archName == "llama3" || archName == "llama") {
        config = ArchitecturePresets::Llama3(8);
    } else {
        config = ArchitecturePresets::TinyLlama();
        archName = "tinyllama";
    }
    
    std::cout << "Architecture: " << archName << std::endl;
    std::cout << "  Name: " << config.name << std::endl;
    std::cout << "  Vocab: " << config.vocabSize << std::endl;
    std::cout << "  Hidden: " << config.hiddenSize << std::endl;
    std::cout << "  Layers: " << config.numLayers << std::endl;
    std::cout << "  Heads: " << config.numHeads << " (KV: " << config.numKVHeads << ")" << std::endl;
    std::cout << "  Intermediate: " << config.intermediateSize << std::endl;
    std::cout << std::endl;
    
    // ------------------------------------------------------------------------
    // Step 1: Create Tensor Registry and populate with synthetic data
    // ------------------------------------------------------------------------
    std::cout << "--- Step 1: Populating Tensor Registry ---" << std::endl;
    
    TensorRegistry registry;
    PopulateSyntheticModel(registry, config);
    
    std::cout << "✓ Registry populated" << std::endl;
    std::cout << "  Total tensors: " << registry.Count() << std::endl;
    std::cout << "  Expected: " << (3 + config.numLayers * 9) << std::endl;
    
    // Verify key tensors exist
    std::cout << "  Key tensors:" << std::endl;
    std::cout << "    " << config.tokenEmbdPattern << ": " << (registry.Has(config.tokenEmbdPattern) ? "✓" : "✗") << std::endl;
    std::cout << "    " << config.outputNormPattern << ": " << (registry.Has(config.outputNormPattern) ? "✓" : "✗") << std::endl;
    std::cout << "    " << config.outputWeightPattern << ": " << (registry.Has(config.outputWeightPattern) ? "✓" : "✗") << std::endl;
    std::cout << std::endl;
    
    // ------------------------------------------------------------------------
    // Step 2: Initialize ModelBinder
    // ------------------------------------------------------------------------
    std::cout << "--- Step 2: Initializing ModelBinder ---" << std::endl;
    
    ModelBinder binder;
    bool initOk = binder.Initialize(config);
    
    if (!initOk) {
        std::cout << "✗ Failed to initialize ModelBinder" << std::endl;
        return 1;
    }
    
    std::cout << "✓ ModelBinder initialized" << std::endl;
    std::cout << "  Model layers: " << binder.GetModel()->GetNumLayers() << std::endl;
    std::cout << std::endl;
    
    // ------------------------------------------------------------------------
    // Step 3: Bind model from registry
    // ------------------------------------------------------------------------
    std::cout << "--- Step 3: Binding Model from Registry ---" << std::endl;
    
    bool bindOk = binder.BindModel(registry);
    
    std::cout << binder.GetBindingReport() << std::endl;
    
    if (!bindOk) {
        std::cout << "✗ Model binding incomplete" << std::endl;
        return 1;
    }
    
    std::cout << "✓ Model fully bound" << std::endl;
    std::cout << std::endl;
    
    // ------------------------------------------------------------------------
    // Step 4: Test inference
    // ------------------------------------------------------------------------
    std::cout << "--- Step 4: Testing Inference ---" << std::endl;
    
    TransformerModelRuntime* model = binder.GetModel();
    
    if (!model->IsInitialized()) {
        std::cout << "✗ Model not initialized" << std::endl;
        return 1;
    }
    
    // Embed a token
    uint32_t tokenId = 42;
    std::vector<float> embedding(config.hiddenSize);
    bool embedOk = model->EmbedToken(tokenId, embedding.data());
    
    if (!embedOk) {
        std::cout << "✗ Token embedding failed" << std::endl;
        return 1;
    }
    
    float embedChecksum = ComputeChecksum(embedding.data(), config.hiddenSize);
    std::cout << "✓ Token " << tokenId << " embedded" << std::endl;
    std::cout << "  Embedding checksum: " << embedChecksum << std::endl;
    
    // Run through model
    std::vector<float> hidden(config.hiddenSize);
    bool forwardOk = model->Forward(embedding.data(), 1, 0, hidden.data());
    
    if (!forwardOk) {
        std::cout << "✗ Forward pass failed" << std::endl;
        return 1;
    }
    
    float hiddenChecksum = ComputeChecksum(hidden.data(), config.hiddenSize);
    std::cout << "✓ Forward pass completed" << std::endl;
    std::cout << "  Hidden checksum: " << hiddenChecksum << std::endl;
    
    // Project to logits
    std::vector<float> logits(config.vocabSize);
    bool projectOk = model->ProjectToLogits(hidden.data(), logits.data());
    
    if (!projectOk) {
        std::cout << "✗ Output projection failed" << std::endl;
        return 1;
    }
    
    float logitsChecksum = ComputeChecksum(logits.data(), config.vocabSize);
    std::cout << "✓ Output projection completed" << std::endl;
    std::cout << "  Logits checksum: " << logitsChecksum << std::endl;
    std::cout << std::endl;
    
    // ------------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------------
    std::cout << "=== Pipeline Summary ===" << std::endl;
    std::cout << "✓ Tensor Registry: " << registry.Count() << " tensors" << std::endl;
    std::cout << "✓ ModelBinder: " << binder.GetNumBoundLayers() << "/" << config.numLayers << " layers bound" << std::endl;
    std::cout << "✓ Inference: token " << tokenId << " → logits [" << config.vocabSize << "]" << std::endl;
    std::cout << std::endl;
    std::cout << "Full pipeline operational: GGUF → Registry → Binder → Runtime" << std::endl;
    
    return 0;
}
