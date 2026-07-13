# Backend Adapter Guide

## Overview

The Backend Adapter layer provides a unified interface for connecting to different LLM backends (Sovereign, Ollama) with consistent APIs for inference, agent operations, and resource management.

## Supported Backends

| Backend | Endpoint | Features | Status |
|---------|----------|----------|--------|
| **Sovereign** | localhost:8080 | Full agentic capabilities, SEG, native swarm | ✅ Supported |
| **Ollama** | localhost:11434 | Inference, chat, simulated agents | ✅ Supported |

## Quick Start

### Creating a Backend Adapter

```cpp
#include "backend_factory.hpp"

using namespace rawrxd::benchmark;

// Method 1: Using factory with type
auto backend = BackendFactory::Create(BackendType::SOVEREIGN);

// Method 2: Using factory with string
auto backend = BackendFactory::Create("sovereign");

// Method 3: Direct creation
auto sovereign = std::make_unique<SovereignBackendAdapter>();
auto ollama = std::make_unique<OllamaBackendAdapter>();
```

### Initializing the Backend

```cpp
// Create configuration
BenchmarkConfig config;
config.backend = BackendType::SOVEREIGN;
config.model_name = "phi-3-mini-Q4";
config.sovereign_endpoint = "http://localhost:8080";
config.max_tokens = 512;
config.temperature = 0.0f;

// Initialize backend
if (!backend->Initialize(config)) {
    std::cerr << "Failed to initialize backend" << std::endl;
    return 1;
}

// Check health
if (!backend->HealthCheck()) {
    std::cerr << "Backend not healthy" << std::endl;
    return 1;
}

// Wait for ready (with timeout)
if (!backend->WaitForReady(30)) {
    std::cerr << "Backend failed to become ready" << std::endl;
    return 1;
}
```

## Core Inference

### Text Generation

```cpp
// Generate text
std::string prompt = "Explain quantum computing in simple terms";
std::string response = backend->Generate(prompt, 256);  // max_tokens

if (!response.empty()) {
    std::cout << "Response: " << response << std::endl;
    std::cout << "Latency: " << backend->GetLastLatencyMs() << " ms" << std::endl;
    std::cout << "Throughput: " << backend->GetLastTokensPerSec() << " TPS" << std::endl;
} else {
    std::cerr << "Generation failed" << std::endl;
}
```

### Batch Generation

```cpp
std::vector<std::string> prompts = {
    "What is machine learning?",
    "Explain neural networks",
    "What is deep learning?"
};

for (const auto& prompt : prompts) {
    std::string response = backend->Generate(prompt, 128);
    // Process response...
}
```

## Agent Operations

### Sovereign (Native Agents)

```cpp
// Spawn an agent (Sovereign only)
std::string agent_id = backend->SpawnAgent(
    "code_reviewer",                    // role
    "You are an expert code reviewer"   // context
);

if (!agent_id.empty()) {
    std::cout << "Agent spawned: " << agent_id << std::endl;
    
    // List active agents
    auto agents = backend->ListAgents();
    std::cout << "Active agents: " << agents.size() << std::endl;
    
    // Destroy agent when done
    backend->DestroyAgent(agent_id);
}
```

### Ollama (Simulated Agents)

```cpp
// Ollama simulates agents using prompts
std::string agent_id = backend->SpawnAgent(
    "assistant",
    "You are a helpful assistant"
);

// The agent is simulated - no actual process is spawned
// Operations are translated to chat API calls
```

## Swarm Operations

### Sovereign (Native Swarm)

```cpp
// Spawn a swarm of agents
std::vector<std::string> agents = backend->SpawnSwarm(
    16,                                    // count
    "Process these documents in parallel"  // task
);

std::cout << "Spawned " << agents.size() << " agents" << std::endl;

// Execute task on swarm
std::vector<std::string> results = backend->ExecuteSwarm(
    agents,
    "Summarize your assigned document"
);

// Clean up
for (const auto& agent : agents) {
    backend->DestroyAgent(agent);
}
```

### Ollama (Simulated Swarm)

```cpp
// Ollama simulates swarm with sequential processing
std::vector<std::string> agents = backend->SpawnSwarm(16, "task");

// Each "agent" is a separate chat completion
std::vector<std::string> results = backend->ExecuteSwarm(agents, "task");
```

## SEG (Sovereign Execution Graph)

### Creating Execution Graphs

```cpp
// Check if backend supports SEG
if (backend->SupportsSEG()) {
    // Create execution graph
    std::string plan = R"({
        "steps": [
            {"id": 1, "action": "fetch_data"},
            {"id": 2, "action": "process_data", "depends_on": [1]},
            {"id": 3, "action": "save_results", "depends_on": [2]}
        ]
    })";
    
    std::string graph_id = backend->CreateExecutionGraph(plan);
    
    if (!graph_id.empty()) {
        // Execute the graph
        bool success = backend->ExecuteGraph(graph_id);
        
        if (success) {
            std::cout << "Graph executed successfully" << std::endl;
        }
    }
}
```

## Decision Making

```cpp
// Make a decision
std::string context = "Select the best algorithm for sorting 1 million items";
std::vector<std::string> options = {
    "QuickSort",
    "MergeSort",
    "HeapSort",
    "BubbleSort"
};

std::string decision = backend->MakeDecision(context, options);

std::cout << "Selected: " << decision << std::endl;
```

## Resource Monitoring

```cpp
// Get resource usage
ResourceMetrics metrics = backend->GetResourceUsage();

std::cout << "CPU: " << metrics.cpu_percent << "%" << std::endl;
std::cout << "Memory: " << metrics.memory_mb << " MB" << std::endl;
std::cout << "GPU: " << metrics.gpu_percent << "%" << std::endl;
std::cout << "VRAM: " << metrics.vram_mb << " MB" << std::endl;
```

## Backend-Specific APIs

### Sovereign-Specific

```cpp
auto* sovereign = dynamic_cast<SovereignBackendAdapter*>(backend.get());

if (sovereign) {
    // Get version
    std::string version = sovereign->GetVersion();
    std::cout << "Sovereign version: " << version << std::endl;
    
    // Get statistics
    auto stats = sovereign->GetStats();
    std::cout << "Total requests: " << stats.total_requests << std::endl;
    std::cout << "Avg latency: " << stats.average_latency_ms << " ms" << std::endl;
    std::cout << "Total tokens: " << stats.total_tokens_generated << std::endl;
}
```

### Ollama-Specific

```cpp
auto* ollama = dynamic_cast<OllamaBackendAdapter*>(backend.get());

if (ollama) {
    // List available models
    auto models = ollama->ListModels();
    for (const auto& model : models) {
        std::cout << "Model: " << model.name << std::endl;
        std::cout << "  Size: " << model.size << " bytes" << std::endl;
        std::cout << "  Family: " << model.details.family << std::endl;
    }
    
    // Pull a model
    bool pulled = ollama->PullModel("llama3:8b");
    
    // Check if model is running
    bool running = ollama->IsModelRunning("phi3:mini");
    
    // Wait for model to be ready
    bool ready = ollama->WaitForModelReady("phi3:mini", 60);
    
    // Get statistics
    auto stats = ollama->GetStats();
}
```

## Error Handling

```cpp
// Check for errors
std::string response = backend->Generate("prompt", 100);

if (response.empty()) {
    // Generation failed
    std::cerr << "Generation failed" << std::endl;
    
    // Check backend health
    if (!backend->HealthCheck()) {
        std::cerr << "Backend is not healthy" << std::endl;
        
        // Try to reconnect
        backend->Shutdown();
        if (backend->Initialize(config)) {
            std::cout << "Reconnected successfully" << std::endl;
        }
    }
}
```

## Feature Matrix

| Feature | Sovereign | Ollama | Notes |
|---------|-----------|--------|-------|
| Text Generation | ✅ | ✅ | Both support streaming and non-streaming |
| Agent Spawn | ✅ Native | ⚠️ Simulated | Ollama uses prompt-based simulation |
| Swarm Operations | ✅ Native | ⚠️ Simulated | Ollama processes sequentially |
| SEG (Execution Graphs) | ✅ | ❌ | Sovereign-only feature |
| Decision Making | ✅ | ✅ | Both use chat API |
| Resource Monitoring | ✅ | ⚠️ Limited | Ollama has limited metrics |
| Health Checks | ✅ | ✅ | Both supported |
| Model Management | ❌ | ✅ | Ollama can pull/delete models |

## Configuration Reference

### Sovereign Configuration

```cpp
BenchmarkConfig config;
config.backend = BackendType::SOVEREIGN;
config.sovereign_endpoint = "http://localhost:8080";
config.model_name = "phi-3-mini-Q4";
config.enable_seg = true;
config.enable_learning = true;
config.enable_telemetry = true;
```

### Ollama Configuration

```cpp
BenchmarkConfig config;
config.backend = BackendType::OLLAMA;
config.ollama_url = "http://localhost:11434";
config.ollama_model = "phi3:mini";
```

## Best Practices

1. **Always Check Health**: Verify backend is healthy before operations
2. **Use WaitForReady**: Ensure backend is fully initialized
3. **Handle Empty Responses**: Check for empty strings indicating failures
4. **Monitor Resources**: Track CPU/GPU usage during benchmarks
5. **Clean Up Agents**: Destroy agents when done to free resources
6. **Use Connection Pooling**: Enable for better performance
7. **Set Appropriate Timeouts**: Balance reliability vs responsiveness

## Troubleshooting

### Connection Refused

```cpp
// Check if backend is running
if (!backend->HealthCheck()) {
    std::cerr << "Backend not responding. Is it running?" << std::endl;
    std::cerr << "Sovereign: http://localhost:8080" << std::endl;
    std::cerr << "Ollama: http://localhost:11434" << std::endl;
}
```

### Model Not Found

```cpp
// For Ollama, check available models
auto models = ollama->ListModels();
bool found = false;
for (const auto& model : models) {
    if (model.name == config.ollama_model) {
        found = true;
        break;
    }
}

if (!found) {
    std::cerr << "Model not found. Pulling..." << std::endl;
    ollama->PullModel(config.ollama_model);
}
```

### High Latency

```cpp
// Check resource usage
auto metrics = backend->GetResourceUsage();

if (metrics.gpu_percent > 95.0) {
    std::cerr << "GPU saturated, consider reducing load" << std::endl;
}

if (metrics.memory_mb > 16000) {
    std::cerr << "High memory usage detected" << std::endl;
}
```

## See Also

- [HTTP Client API](http_client_api.md)
- [Configuration Reference](configuration_reference.md)
- [Troubleshooting Guide](troubleshooting.md)
- [Benchmark Runner Guide](benchmark_runner_guide.md)
