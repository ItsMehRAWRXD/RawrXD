#include "Deep2Engine.h"
#include <iostream>
#include <vector>

int main() {
    std::cout << "[TEST] Deep2Engine Bolt Load Test\n";
    
    Deep2::Deep2Engine engine;
    Deep2::EngineConfig config;
    config.maxSeqLen = 8192;
    config.useKVCache = true;
    config.weightQuant = Deep2::EngineConfig::QuantType::Q4_K;
    config.kvCacheQuant = Deep2::EngineConfig::QuantType::Q4_K;
    config.numThreads = 8;
    strcpy_s(config.modelPath, "F:\\rawrxd\\nemotron-bolt.gguf");
    
    if (!engine.initialize(config)) {
        std::cerr << "FAIL: Engine initialization failed\n";
        return 1;
    }
    std::cout << "PASS: Engine initialized\n";
    
    if (!engine.loadModel("F:\\rawrxd\\nemotron-bolt.gguf")) {
        std::cerr << "FAIL: Model loading failed\n";
        return 1;
    }
    std::cout << "PASS: Model loaded\n";
    
    const auto& metadata = engine.getModelMetadata();
    std::cout << "Architecture: " << metadata.architecture << "\n";
    std::cout << "Layers: " << metadata.numLayers << "\n";
    std::cout << "Hidden dim: " << metadata.hiddenSize << "\n";
    std::cout << "Heads: " << metadata.numHeads << "\n";
    std::cout << "KV heads: " << metadata.numKeyValueHeads << "\n";
    std::cout << "Vocab size: " << metadata.vocabSize << "\n";
    
    // Test tokenization
    std::vector<int> tokens = engine.tokenize("Hello world");
    std::cout << "Tokens: ";
    for (int t : tokens) std::cout << t << " ";
    std::cout << "\n";
    
    // Test single token generation
    std::vector<int> outputTokens(16);
    Deep2::InferenceStats stats;
    size_t generated = engine.generate(tokens.data(), tokens.size(), 
                                        outputTokens.data(), outputTokens.size(), &stats);
    std::cout << "Generated " << generated << " tokens\n";
    std::cout << "TPS: " << stats.tokensPerSecond << "\n";
    std::cout << "Latency: " << stats.latencyMs << " ms\n";
    
    // Detokenize
    std::string text = engine.detokenize(std::vector<int>(outputTokens.begin(), outputTokens.begin() + generated));
    std::cout << "Output: " << text << "\n";
    
    std::cout << "[TEST] Bolt Load Test COMPLETE\n";
    return 0;
}