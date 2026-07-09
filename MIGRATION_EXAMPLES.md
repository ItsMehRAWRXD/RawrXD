# Migration Examples: Legacy to Unified API

## Overview

This document provides concrete examples of migrating code from legacy APIs to the new unified interfaces.

## AgenticEngine → Core Migration

### Example 1: File Operations

#### Before (Legacy)
```cpp
#include "agentic_engine.h"

void ProcessFiles() {
    AgenticEngine engine;
    engine.initialize();
    
    // Read file
    std::string content = engine.readFile("config.json");
    
    // Write file
    engine.writeFile("output.txt", "Hello World");
    
    // List directory
    std::string listing = engine.listDir(".");
}
```

#### After (Unified)
```cpp
#include "src/agentic/Core.h"
#include "src/agentic/LegacyCoreAdapter.h"

using namespace RawrXD::Agentic;

void ProcessFiles() {
    auto core = LegacyCoreAdapter::Create(nullptr); // Or pass real engine
    core->Initialize();
    
    // Read file
    Task readTask;
    readTask.type = TaskType::File;
    readTask.fileParams.operation = "read";
    readTask.fileParams.path = "config.json";
    auto readResult = core->ExecuteSync(readTask);
    std::string content = readResult.output;
    
    // Write file
    Task writeTask;
    writeTask.type = TaskType::File;
    writeTask.fileParams.operation = "write";
    writeTask.fileParams.path = "output.txt";
    writeTask.fileParams.content = "Hello World";
    core->ExecuteSync(writeTask);
    
    // List directory
    Task listTask;
    listTask.type = TaskType::File;
    listTask.fileParams.operation = "list";
    listTask.fileParams.path = ".";
    auto listResult = core->ExecuteSync(listTask);
}
```

### Example 2: Search Operations

#### Before (Legacy)
```cpp
void SearchCodebase() {
    AgenticEngine engine;
    engine.initialize();
    
    std::string results = engine.grepFiles("class.*Agentic", "./src");
    std::cout << results << std::endl;
}
```

#### After (Unified)
```cpp
void SearchCodebase() {
    auto core = LegacyCoreAdapter::Create(nullptr);
    core->Initialize();
    
    Task searchTask;
    searchTask.type = TaskType::Search;
    searchTask.searchParams.query = "class.*Agentic";
    searchTask.searchParams.paths = {"./src"};
    
    auto result = core->ExecuteSync(searchTask);
    std::cout << result.output << std::endl;
}
```

### Example 3: Command Execution

#### Before (Legacy)
```cpp
void RunBuild() {
    AgenticEngine engine;
    engine.initialize();
    
    if (engine.isCommandSafe("make -j4")) {
        std::string output = engine.executeCommand("make -j4", false);
        std::cout << output << std::endl;
    }
}
```

#### After (Unified)
```cpp
void RunBuild() {
    auto core = LegacyCoreAdapter::Create(nullptr);
    core->Initialize();
    
    Task cmdTask;
    cmdTask.type = TaskType::Terminal;
    cmdTask.terminalParams.command = "make -j4";
    cmdTask.terminalParams.isPowerShell = false;
    
    // Policy validation happens automatically
    auto result = core->ExecuteSync(cmdTask);
    std::cout << result.output << std::endl;
}
```

### Example 4: Async Operations

#### Before (Legacy)
```cpp
void AsyncOperations() {
    AgenticEngine engine;
    engine.initialize();
    
    // No built-in async support
    std::thread t([&engine]() {
        std::string result = engine.grepFiles("TODO", ".");
        ProcessResult(result);
    });
    t.detach();
}
```

#### After (Unified)
```cpp
void AsyncOperations() {
    auto core = LegacyCoreAdapter::Create(nullptr);
    core->Initialize();
    
    Task task;
    task.type = TaskType::Search;
    task.searchParams.query = "TODO";
    task.searchParams.paths = {"./src"};
    
    // Built-in async support
    auto future = core->SubmitTask(task);
    
    // Do other work...
    
    // Get result later
    auto result = future.get();
    ProcessResult(result.output);
}
```

## CPUInferenceEngine → InferenceEngine Migration

### Example 1: Model Loading

#### Before (Legacy)
```cpp
#include "cpu_inference_engine.h"

void LoadModel() {
    auto engine = CPUInferenceEngine::GetSharedInstance();
    
    if (!engine->IsModelLoaded()) {
        // Load model
        engine->LoadModel("model.gguf");
    }
}
```

#### After (Unified)
```cpp
#include "src/inference/InferenceEngine.h"
#include "src/inference/LegacyInferenceAdapter.h"

using namespace RawrXD::Inference;

void LoadModel() {
    EngineConfig config;
    config.modelPath = "model.gguf";
    config.maxContextLength = 4096;
    
    auto engine = LegacyInferenceAdapter::Create(nullptr, config);
    
    if (!engine->IsModelLoaded()) {
        engine->LoadModel("model.gguf");
    }
}
```

### Example 2: Text Generation

#### Before (Legacy)
```cpp
void GenerateText() {
    auto engine = CPUInferenceEngine::GetSharedInstance();
    
    std::vector<int32_t> tokens = engine->Tokenize("Hello, world!");
    
    // Generate
    std::string output = engine->Generate(tokens, 100, 0.7f);
    
    std::cout << output << std::endl;
}
```

#### After (Unified)
```cpp
void GenerateText() {
    EngineConfig config;
    auto engine = LegacyInferenceAdapter::Create(nullptr, config);
    
    std::vector<int> tokens = engine->Tokenize("Hello, world!");
    
    GenerationParams params;
    params.maxTokens = 100;
    params.temperature = 0.7f;
    
    auto result = engine->Generate("Hello, world!", params);
    
    if (result.success) {
        std::cout << result.text << std::endl;
    }
}
```

### Example 3: Streaming Generation

#### Before (Legacy)
```cpp
void StreamGeneration() {
    auto engine = CPUInferenceEngine::GetSharedInstance();
    
    // No built-in streaming support
    std::string output = engine->Generate(prompt, maxTokens, temp);
    std::cout << output << std::flush;
}
```

#### After (Unified)
```cpp
void StreamGeneration() {
    EngineConfig config;
    auto engine = LegacyInferenceAdapter::Create(nullptr, config);
    
    GenerationParams params;
    params.maxTokens = 100;
    params.temperature = 0.7f;
    params.streamOutput = true;
    params.streamInterval = 1;
    
    auto result = engine->GenerateStreaming(
        "Hello, world!",
        params,
        [](const std::string& token) {
            std::cout << token << std::flush;
        }
    );
}
```

## Common Patterns

### Pattern 1: Error Handling

#### Before
```cpp
std::string result = engine.readFile("file.txt");
if (result.empty()) {
    // Handle error
}
```

#### After
```cpp
auto result = core->ExecuteSync(task);
if (!result.success) {
    LOG_ERROR("Core", "Task failed: %s", result.errorMessage.c_str());
}
```

### Pattern 2: Resource Management

#### Before
```cpp
AgenticEngine engine;
engine.initialize();
// Use engine...
// Cleanup happens in destructor
```

#### After
```cpp
{
    auto core = LegacyCoreAdapter::Create(nullptr);
    core->Initialize();
    // Use core...
    core->Shutdown(std::chrono::seconds(5));
} // Cleanup happens automatically
```

### Pattern 3: Configuration

#### Before
```cpp
AgenticEngine engine;
engine.setWorkspaceRoot("/workspace");
engine.updateConfig(config);
```

#### After
```cpp
CoreConfig config;
config.workspaceRoot = "/workspace";
auto core = LegacyCoreAdapter::Create(nullptr, config);
core->Initialize();
```

## Migration Checklist

- [ ] Replace `#include "agentic_engine.h"` with unified headers
- [ ] Replace `AgenticEngine` with `Core` interface
- [ ] Replace direct method calls with `Task` submission
- [ ] Add error handling with `TaskResult`
- [ ] Update async code to use `std::future`
- [ ] Add proper initialization and shutdown
- [ ] Test migrated code
- [ ] Update documentation

## Tips

1. **Start Small**: Migrate test files first
2. **Use Adapters**: LegacyCoreAdapter provides backward compatibility
3. **Test Thoroughly**: Verify functionality is preserved
4. **Incremental**: Migrate one component at a time
5. **Document**: Keep track of API changes

## Support

For questions about migration:
1. Review this document
2. Check the unified interface headers
3. Run the migration candidate identifier tool
4. Consult the architecture documentation
