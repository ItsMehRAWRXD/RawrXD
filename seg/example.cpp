// SEG (Sovereign Execution Graph) Example
// Demonstrates the unified runtime API

#include "seg_runtime.hpp"
#include <iostream>

int main(int argc, char** argv) {
    std::cout << "=== SEG Runtime Example ===\n";
    std::cout << "Version: " << seg::SEGRuntime::Version() << "\n\n";
    
    // Show available backends
    std::cout << "Available backends:\n";
    for (const auto& backend : seg::SEGRuntime::GetAvailableBackends()) {
        std::cout << "  - " << backend << ": " 
                  << seg::SEGRuntime::GetBackendInfo(backend) << "\n";
    }
    std::cout << "\n";
    
    // Configure runtime
    seg::SEGRuntimeConfig config;
    config.thread_count = 8;
    config.use_gpu = true;
    config.enable_agentic = true;
    config.enable_profiling = true;
    config.temperature = 0.8f;
    config.top_k = 40;
    config.top_p = 0.9f;
    
    // Create and initialize runtime
    seg::SEGRuntime runtime;
    
    std::cout << "Initializing SEG runtime...\n";
    if (!runtime.Initialize(config)) {
        std::cerr << "Failed to initialize runtime\n";
        return 1;
    }
    std::cout << "Runtime initialized successfully\n\n";
    
    // Access components
    std::cout << "Core components:\n";
    std::cout << "  - Memory pool: " << (runtime.GetMemory() ? "OK" : "FAIL") << "\n";
    std::cout << "  - Scheduler: " << (runtime.GetScheduler() ? "OK" : "FAIL") << "\n";
    std::cout << "  - Executor: " << (runtime.GetExecutor() ? "OK" : "FAIL") << "\n";
    std::cout << "  - Agentic system: " << (runtime.GetAgenticSystem() ? "OK" : "FAIL") << "\n";
    std::cout << "  - Inference graph: " << (runtime.GetInferenceGraph() ? "OK" : "FAIL") << "\n";
    std::cout << "\n";
    
    // Show graph structure
    if (auto graph = runtime.GetInferenceGraph()) {
        std::cout << "Inference graph:\n";
        std::cout << "  - Nodes: " << graph->GetNodeCount() << "\n";
        std::cout << "  - Edges: " << graph->GetEdgeCount() << "\n";
        
        auto levels = graph->GetExecutionLevels();
        std::cout << "  - Execution levels: " << levels.size() << "\n";
        
        if (!levels.empty()) {
            std::cout << "  - Max parallelism: " << levels[0].size() << " nodes\n";
        }
        std::cout << "\n";
    }
    
    // Show memory stats
    if (auto memory = runtime.GetMemory()) {
        std::cout << "Memory pools:\n";
        memory->PrintStats();
        std::cout << "\n";
    }
    
    // Show executor backends
    if (auto executor = runtime.GetExecutor()) {
        std::cout << "Executor backends:\n";
        for (const auto& backend : seg::SEGRuntime::GetAvailableBackends()) {
            auto be = executor->GetBackend(backend);
            std::cout << "  - " << backend << ": " << (be ? "active" : "inactive") << "\n";
        }
        std::cout << "\n";
    }
    
    // Print final stats
    runtime.PrintStats();
    
    std::cout << "\n=== Example Complete ===\n";
    return 0;
}
