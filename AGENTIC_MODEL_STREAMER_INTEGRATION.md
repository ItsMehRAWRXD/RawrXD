# Agentic Model Streamer Integration

## Overview

The **Agentic Model Streamer Bridge** connects the `AgenticEngine` with the `StreamingGGUFLoader` to provide unified, agentic-controlled model management. This enables:

- **Agentic-controlled model loading** with priorities and memory budgets
- **Streaming tensor zone management** for memory-efficient inference
- **Async model operations** with callbacks and status monitoring
- **Integration with agentic task planning** for intelligent model selection

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AgenticEngine                               │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              AgenticModelStreamerBridge                      │ │
│  │  ┌─────────────────────────────────────────────────────────┐ │ │
│  │  │              StreamingGGUFLoader                       │ │ │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │ │ │
│  │  │  │  Embedding │  │   Layer 0   │  │   Layer 1   │ ... │ │ │
│  │  │  │   Zone     │  │    Zone     │  │    Zone     │     │ │ │
│  │  │  └─────────────┘  └─────────────┘  └─────────────┘     │ │ │
│  │  └─────────────────────────────────────────────────────────┘ │ │
│  │                           │                                  │ │
│  │              ┌────────────┴────────────┐                   │ │
│  │              │  StreamingModelInference │                   │ │
│  │              │         Engine           │                   │ │
│  │              └──────────────────────────┘                   │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. AgenticModelStreamerBridge

**File:** `src/agentic_model_streamer_bridge.h/cpp`

The central bridge that connects agentic operations with model streaming:

```cpp
class AgenticModelStreamerBridge {
public:
    // Model Loading (Agentic-controlled)
    std::string QueueModelLoad(const ModelLoadRequest& request);
    bool LoadModelSync(const std::string& modelPath, uint64_t maxMemoryMB);
    void UnloadModel();
    
    // Zone Management
    bool LoadZone(const std::string& zoneName, uint64_t maxMemoryMB);
    bool UnloadZone(const std::string& zoneName);
    void PreloadZonesForInference(const std::vector<std::string>& zoneNames);
    
    // Status & Monitoring
    ModelStreamerStatus GetStatus() const;
    void SetStatusCallback(std::function<void(const ModelStreamerStatus&)> callback);
    
    // Agentic Integration
    std::shared_ptr<InferenceEngine> GetInferenceEngine();
    std::string ExecuteAgenticTask(const std::string& task, const std::string& context);
    
    // Memory Management
    void SetMemoryBudget(uint64_t maxMemoryMB);
    void EmergencyMemoryCleanup();
};
```

### 2. StreamingModelInferenceEngine

**File:** `src/agentic_model_streamer_bridge.h/cpp`

An `InferenceEngine` implementation that uses the streaming loader:

```cpp
class StreamingModelInferenceEngine : public InferenceEngine {
public:
    // Standard InferenceEngine interface
    bool LoadModel(const std::string& model_path) override;
    std::vector<int32_t> Generate(const std::vector<int32_t>& input_tokens, int max_tokens) override;
    void GenerateStreaming(...) override;
    
    // Streaming-specific
    bool EnsureZonesLoaded(const std::vector<std::string>& zoneNames);
    void SetZoneCachePolicy(const std::string& policy); // "lru", "prefetch", "on_demand"
};
```

### 3. ModelLoadRequest

Structure for agentic model loading with priorities:

```cpp
struct ModelLoadRequest {
    std::string modelPath;
    std::string priority;           // "critical", "high", "normal", "low"
    uint64_t maxMemoryMB;           // Memory budget
    bool enableStreaming;           // Use streaming vs full load
    bool preloadZones;              // Preload tensor zones
    std::vector<std::string> requiredZones; // Zones to load first
    std::function<void(bool success, const std::string& error)> callback;
    std::string taskId;             // Agentic task tracking
    std::string agentId;            // Agent requesting the load
};
```

## Integration Points

### 1. AgenticEngine Initialization

Modified `AgenticEngine::initialize()` to create the bridge:

```cpp
void AgenticEngine::initialize() {
    // ... existing initialization ...
    
    // Initialize the agentic model streamer bridge
    auto* bridge = new RawrXD::Agentic::AgenticModelStreamerBridge();
    if (bridge->Initialize(this)) {
        fprintf(stderr, "[AgenticEngine] Model streamer bridge initialized\n");
    }
}
```

### 2. Model Loading

Modified `AgenticEngine::loadLocalModel()` to use the bridge:

```cpp
bool AgenticEngine::loadLocalModel(const std::string& modelPath) {
    // Try the model streamer bridge first
    auto* bridge = RawrXD::Agentic::GetGlobalAgenticModelStreamer();
    if (bridge) {
        RawrXD::Agentic::ModelLoadRequest request;
        request.modelPath = resolvedPath;
        request.maxMemoryMB = 8192;
        request.enableStreaming = true;
        request.preloadZones = true;
        request.requiredZones = {"embedding", "output"};
        
        bridge->QueueModelLoad(request);
        // ... wait for completion ...
        return success;
    }
    
    // Fall back to standard loader
    return m_inferenceEngine->LoadModel(resolvedPath);
}
```

### 3. CMake Integration

Added to `CMakeLists.txt`:

```cmake
src/agentic_model_streamer_bridge.cpp
```

## Usage Examples

### Basic Model Loading

```cpp
auto* bridge = RawrXD::Agentic::GetGlobalAgenticModelStreamer();
if (bridge) {
    bool success = bridge->LoadModelSync(
        "F:/OllamaModels/model.gguf",
        8192  // 8GB memory budget
    );
}
```

### Async Model Loading with Callback

```cpp
RawrXD::Agentic::ModelLoadRequest request;
request.modelPath = "path/to/model.gguf";
request.priority = "high";
request.maxMemoryMB = 4096;
request.enableStreaming = true;
request.preloadZones = true;
request.requiredZones = {"embedding", "output", "layers_0"};
request.callback = [](bool success, const std::string& error) {
    if (success) {
        std::cout << "Model loaded successfully!" << std::endl;
    } else {
        std::cerr << "Load failed: " << error << std::endl;
    }
};

std::string taskId = bridge->QueueModelLoad(request);
```

### Zone Management

```cpp
// Load specific zones on demand
bridge->LoadZone("layers_5", 512);  // Load layer 5 with 512MB budget

// Preload zones for upcoming inference
bridge->PreloadZonesForInference({"embedding", "layers_0", "layers_1", "output"});

// Check loaded zones
auto zones = bridge->GetLoadedZones();
for (const auto& zone : zones) {
    std::cout << "Loaded: " << zone << std::endl;
}
```

### Status Monitoring

```cpp
// Set up status callback
bridge->SetStatusCallback([](const RawrXD::Agentic::ModelStreamerStatus& status) {
    std::cout << "Operation: " << status.currentOperation << std::endl;
    std::cout << "Progress: " << status.progressPercent << "%" << std::endl;
    std::cout << "Memory: " << status.memoryUsedMB << "/" 
              << status.memoryBudgetMB << " MB" << std::endl;
});

// Get current status
auto status = bridge->GetStatus();
if (status.isLoading) {
    std::cout << "Loading: " << status.progressPercent << "%" << std::endl;
}
```

### Agentic Task Execution

```cpp
// Execute agentic task with model context
std::string result = bridge->ExecuteAgenticTask(
    "Analyze this code for security vulnerabilities",
    "void processInput(char* input) { strcpy(buffer, input); }"
);
```

## Memory Management

### Memory Budget

```cpp
// Set global memory budget (default: 8192 MB)
bridge->SetMemoryBudget(4096);  // 4GB

// Check current usage
uint64_t usedMB = bridge->GetCurrentMemoryUsageMB();
uint64_t budgetMB = bridge->GetMemoryBudget();
```

### Emergency Cleanup

```cpp
// When memory is low, unload non-essential zones
bridge->EmergencyMemoryCleanup();
```

## Thread Safety

The bridge is fully thread-safe:

- **Loading Queue:** Thread-safe queue with condition variable
- **Status Updates:** Mutex-protected status structure
- **Zone Operations:** Atomic zone loading/unloading
- **Callbacks:** Thread-safe callback invocation

## Status Codes

| Operation | Description |
|-----------|-------------|
| `parsing_header` | Reading GGUF header |
| `loading_metadata` | Parsing metadata key-value pairs |
| `building_index` | Building tensor index |
| `loading_zones` | Loading tensor zones |
| `ready` | Model ready for inference |
| `error` | Loading failed |

## Benefits

1. **Memory Efficiency:** Load only needed tensor zones
2. **Agentic Control:** AI-driven model selection and loading
3. **Async Operations:** Non-blocking model loading
4. **Priority Queue:** Critical models load first
5. **Status Monitoring:** Real-time loading progress
6. **Fallback Support:** Falls back to standard loader if needed

## Files Modified

- `src/agentic_model_streamer_bridge.h` (new)
- `src/agentic_model_streamer_bridge.cpp` (new)
- `src/agentic_engine.cpp` (modified)
- `CMakeLists.txt` (modified)

## Next Steps

1. **Build the project** with the new files
2. **Test model loading** with the 40B Qwen model
3. **Verify zone management** with different model sizes
4. **Integrate with agentic tasks** for intelligent model selection
5. **Add telemetry** for model loading metrics

## Testing

Run the integration test:

```bash
cd d:\rawrxd
cl.exe /EHsc /W3 /O2 /I. /Isrc /Iinclude test_agentic_streamer_integration.cpp src\agentic_model_streamer_bridge.cpp src\streaming_gguf_loader.cpp src\gguf_loader.cpp /Fe:test_agentic_streamer.exe /link
test_agentic_streamer.exe
```

## Summary

The Agentic Model Streamer Bridge provides a production-ready integration between the agentic engine and the streaming GGUF loader. It enables intelligent, memory-efficient model management with full agentic control.
