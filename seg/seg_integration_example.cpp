// ============================================================================
// SEG Integration Example - Streaming Execution Graph with RawrXD Backend
// ============================================================================
// Shows how to use SEG with StreamingMultiLayerBackend for inference
// ============================================================================

#include "seg_runtime.hpp"
#include "seg_models.hpp"
#include <iostream>
#include <memory>

// Include your actual backend
// #include "../runtime/streaming_multi_layer_backend.hpp"

int main(int argc, char* argv[]) {
    std::cout << "=== SEG Integration Example ===\n\n";
    
    // ------------------------------------------------------------------------
    // Step 1: Create runtime
    // ------------------------------------------------------------------------
    std::cout << "[1] Creating SEG runtime...\n";
    
    seg::RuntimeConfig rtConfig;
    rtConfig.num_threads = 1;  // Sequential for now
    rtConfig.telemetry_enabled = true;
    
    auto runtime = std::make_unique<seg::Runtime>(rtConfig);
    
    // ------------------------------------------------------------------------
    // Step 2: Build Llama forward graph
    // ------------------------------------------------------------------------
    std::cout << "[2] Building Llama forward graph...\n";
    
    seg::LlamaGraphConfig graphConfig;
    graphConfig.num_layers = 32;  // e.g., Llama-3-8B
    
    seg::Graph graph = seg::BuildLlamaForwardGraph(graphConfig);
    
    std::cout << "    Nodes: " << graph.Nodes().size() << "\n";
    std::cout << "    Edges: " << graph.Edges().size() << "\n";
    
    // Show topological order
    auto topo = graph.TopologicalSort();
    std::cout << "    Topological order: ";
    for (size_t i = 0; i < std::min(size_t(5), topo.size()); ++i) {
        if (i > 0) std::cout << " -> ";
        auto node = graph.GetNode(topo[i]);
        std::cout << node->name;
    }
    if (topo.size() > 5) std::cout << " -> ...";
    std::cout << "\n\n";
    
    // ------------------------------------------------------------------------
    // Step 3: Initialize backend (uncomment when ready)
    // ------------------------------------------------------------------------
    std::cout << "[3] Initializing backend...\n";
    std::cout << "    (Uncomment backend integration when ready)\n\n";
    
    /*
    // Create backend
    RawrXD::Runtime::StreamingMultiLayerBackend backend;
    
    // Load model
    RawrXD::Runtime::StreamingGGUFLoader loader;
    if (!loader.Open("model.gguf")) {
        std::cerr << "Failed to load model\n";
        return 1;
    }
    
    if (!backend.Initialize(loader)) {
        std::cerr << "Failed to initialize backend\n";
        return 1;
    }
    
    // Bind backend to runtime
    runtime->SetBackend(&backend);
    */
    
    // ------------------------------------------------------------------------
    // Step 4: Execute inference
    // ------------------------------------------------------------------------
    std::cout << "[4] Executing inference...\n";
    
    seg::InferenceRequest request;
    request.token_id = 1;      // First token
    request.position = 0;    // Position 0
    
    /*
    // Run inference through graph
    auto response = runtime->Execute(graph, request);
    
    std::cout << "    Next token: " << response.next_token << "\n";
    std::cout << "    Latency: " << response.latency_ms << " ms\n";
    */
    
    std::cout << "    (Execution requires backend integration)\n\n";
    
    // ------------------------------------------------------------------------
    // Step 5: Show telemetry (if enabled)
    // ------------------------------------------------------------------------
    std::cout << "[5] Telemetry summary...\n";
    
    /*
    auto stats = runtime->GetTelemetryStats();
    std::cout << "    Nodes executed: " << stats.nodes_executed << "\n";
    std::cout << "    Total time: " << stats.total_time_ms << " ms\n";
    std::cout << "    Tokens/sec: " << stats.tokens_per_sec << "\n";
    */
    
    std::cout << "    (Telemetry requires backend integration)\n\n";
    
    // ------------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------------
    std::cout << "=== Integration Complete ===\n";
    std::cout << "\nTo fully integrate:\n";
    std::cout << "1. Uncomment backend includes and code above\n";
    std::cout << "2. Link with streaming_multi_layer_backend.cpp\n";
    std::cout << "3. Provide model path\n";
    std::cout << "4. Run inference\n";
    
    return 0;
}
