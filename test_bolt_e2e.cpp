#include "Deep2Engine.h"
#include <iostream>
#include <vector>
#include <chrono>

int main() {
    std::cout << "[TEST] Deep2Engine Bolt End-to-End Forward Pass\n" << std::flush;
    
    Deep2::Deep2Engine engine;
    Deep2::EngineConfig config;
    config.maxSeqLen = 8192;
    config.useKVCache = true;
    config.numThreads = 8;
    
    strncpy_s(config.modelPath, "F:\\rawrxd\\nemotron-bolt.gguf", _TRUNCATE);
    
    std::cout << "Initializing engine..." << std::flush;
    if (!engine.initialize(config)) {
        std::cerr << "FAIL: Engine initialization failed\n";
        return 1;
    }
    std::cout << "OK\n" << std::flush;
    
    std::cout << "Loading model..." << std::flush;
    if (!engine.loadModel("F:\\rawrxd\\nemotron-bolt.gguf")) {
        std::cerr << "FAIL: Model loading failed\n";
        return 1;
    }
    std::cout << "OK\n" << std::flush;
    
    // Generate text using high-level API
    std::string prompt = "Hello world";
    std::cout << "Prompt: " << prompt << "\n" << std::flush;
    
    std::cout << "Generating..." << std::flush;
    auto start = std::chrono::high_resolution_clock::now();
    
    std::string output = engine.generateText(prompt, 64);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    std::cout << "Done in " << elapsed << " ms\n" << std::flush;
    std::cout << "Output: " << output << "\n" << std::flush;
    
    if (output.empty()) {
        std::cerr << "FAIL: No output generated\n";
        return 1;
    }
    
    std::cout << "\n[TEST] COMPLETE - End-to-end Bolt forward pass successful\n" << std::flush;
    return 0;
}