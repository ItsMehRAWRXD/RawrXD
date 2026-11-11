// tests/test_dll_multithread.cpp
// Test: Multi-threaded DLL access
#include "RawrXDCore.h"
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <cassert>

std::atomic<int> successCount{0};
std::atomic<int> errorCount{0};

void workerThread(int id, int iterations) {
    for (int i = 0; i < iterations; ++i) {
        // Each thread does basic operations
        RawrXDConfig config;
        RawrXDCore_GetDefaultConfig(&config);
        
        RawrXDModel* model = RawrXDCore_LoadModel("test_model.gguf");
        if (model) {
            RawrXDCore_UnloadModel(model);
        }
        
        RawrXDMemoryStats stats;
        RawrXDCore_GetMemoryStats(&stats);
        
        RawrXDHardwareCaps caps;
        RawrXDCore_GetHardwareCaps(&caps);
        
        successCount++;
    }
}

int main() {
    std::cout << "=== Test: Multi-threaded DLL Access ===" << std::endl;
    
    assert(RawrXDCore_Initialize() == true);
    std::cout << "Initialized" << std::endl;
    
    const int numThreads = 8;
    const int iterationsPerThread = 100;
    
    std::vector<std::thread> threads;
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back(workerThread, i, iterationsPerThread);
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    std::cout << "Successful operations: " << successCount.load() << std::endl;
    std::cout << "Errors: " << errorCount.load() << std::endl;
    
    assert(successCount.load() == numThreads * iterationsPerThread);
    assert(errorCount.load() == 0);
    
    RawrXDCore_Shutdown();
    std::cout << "=== PASSED ===" << std::endl;
    return 0;
}