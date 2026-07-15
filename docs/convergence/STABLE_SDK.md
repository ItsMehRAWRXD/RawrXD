# RawrXD Stable SDK v1.0.0

## Public API Reference

*Phase W.5/5 - Sovereign Convergence & Runtime Validation*

---

## Overview

The RawrXD Stable SDK provides a frozen public API for integrating with the RawrXD Sovereign AI Runtime. This SDK guarantees backward compatibility for all v1.x releases.

**Version**: 1.0.0  
**Stability**: Stable  
**Compatibility**: C++17 or later

---

## Quick Start

```cpp
#include <rawrxd/RawrXD.hpp>

int main() {
    // Initialize the runtime
    RawrXD::Initialize({});
    
    // Create an inference session
    auto session = RawrXD::CreateSession("model.gguf");
    
    // Run inference
    auto result = session->Generate("Hello, world!");
    
    // Cleanup
    RawrXD::Shutdown();
    return 0;
}
```

---

## Core API

### Initialization

```cpp
namespace RawrXD {

// Runtime configuration
struct Config {
    std::string model_path;
    uint32_t thread_count = 0;  // 0 = auto-detect
    uint32_t context_length = 4096;
    bool enable_gpu = true;
    std::string device = "auto";  // "cpu", "cuda", "vulkan", "auto"
};

// Initialize the runtime
bool Initialize(const Config& config);

// Shutdown the runtime
void Shutdown();

// Check if runtime is initialized
bool IsInitialized();

} // namespace RawrXD
```

### Inference Session

```cpp
namespace RawrXD {

// Generation parameters
struct GenerationParams {
    uint32_t max_tokens = 256;
    float temperature = 0.7f;
    float top_p = 0.9f;
    uint32_t top_k = 40;
    float repeat_penalty = 1.1f;
    std::string stop_sequence;
};

// Generation result
struct GenerationResult {
    std::string text;
    uint32_t tokens_generated;
    float tokens_per_second;
    std::chrono::milliseconds duration;
    bool truncated;
};

// Inference session interface
class ISession {
public:
    virtual ~ISession() = default;
    
    // Synchronous generation
    virtual GenerationResult Generate(const std::string& prompt) = 0;
    virtual GenerationResult Generate(const std::string& prompt, 
                                      const GenerationParams& params) = 0;
    
    // Streaming generation
    using TokenCallback = std::function<void(const std::string& token)>;
    virtual void GenerateStream(const std::string& prompt,
                                 TokenCallback callback) = 0;
    virtual void GenerateStream(const std::string& prompt,
                                 const GenerationParams& params,
                                 TokenCallback callback) = 0;
    
    // Session state
    virtual void ClearContext() = 0;
    virtual uint32_t GetContextLength() const = 0;
    virtual uint32_t GetTokenCount() const = 0;
};

// Create a new session
std::unique_ptr<ISession> CreateSession(const std::string& model_path);
std::unique_ptr<ISession> CreateSession(const std::string& model_path,
                                         const Config& config);

} // namespace RawrXD
```

---

## Agentic API

### Agent Creation

```cpp
namespace RawrXD::Agentic {

// Agent configuration
struct AgentConfig {
    std::string name;
    std::string model;
    std::string system_prompt;
    bool enable_tools = true;
    bool enable_memory = true;
    bool enable_reflection = true;
    uint32_t max_iterations = 10;
};

// Task result
struct TaskResult {
    bool success;
    std::string output;
    uint32_t iterations_used;
    std::chrono::milliseconds duration;
    std::vector<std::string> tools_used;
};

// Agent interface
class IAgent {
public:
    virtual ~IAgent() = default;
    
    // Execute a task
    virtual TaskResult Execute(const std::string& task) = 0;
    
    // Streaming execution
    using StreamCallback = std::function<void(const std::string& chunk)>;
    virtual void ExecuteStream(const std::string& task,
                                StreamCallback callback) = 0;
    
    // Agent state
    virtual void Reset() = 0;
    virtual std::string GetName() const = 0;
    virtual std::vector<std::string> GetCapabilities() const = 0;
};

// Create an agent
std::unique_ptr<IAgent> CreateAgent(const AgentConfig& config);

} // namespace RawrXD::Agentic
```

### Tool Registration

```cpp
namespace RawrXD::Agentic {

// Tool function signature
using ToolFunction = std::function<std::string(const std::string& params)>;

// Tool descriptor
struct ToolDescriptor {
    std::string name;
    std::string description;
    std::string parameters_schema;  // JSON schema
    ToolFunction function;
};

// Register a custom tool
bool RegisterTool(const ToolDescriptor& tool);

// Unregister a tool
bool UnregisterTool(const std::string& name);

// List available tools
std::vector<std::string> ListTools();

} // namespace RawrXD::Agentic
```

---

## Memory API

### Episodic Memory

```cpp
namespace RawrXD::Memory {

// Memory entry
struct MemoryEntry {
    std::string id;
    std::chrono::system_clock::time_point timestamp;
    std::string content;
    std::vector<std::string> tags;
    float importance;
};

// Search result
struct SearchResult {
    MemoryEntry entry;
    float relevance_score;
};

// Episodic memory interface
class IEpisodicMemory {
public:
    virtual ~IEpisodicMemory() = default;
    
    // Store a memory
    virtual std::string Store(const std::string& content,
                               const std::vector<std::string>& tags = {}) = 0;
    
    // Retrieve memories
    virtual std::vector<SearchResult> Search(const std::string& query,
                                                uint32_t limit = 10) = 0;
    virtual std::optional<MemoryEntry> Get(const std::string& id) = 0;
    
    // Memory management
    virtual bool Delete(const std::string& id) = 0;
    virtual void Clear() = 0;
    virtual uint32_t Count() const = 0;
};

// Get episodic memory instance
std::shared_ptr<IEpisodicMemory> GetEpisodicMemory();

} // namespace RawrXD::Memory
```

---

## Metacognitive API

### Self-Reflection

```cpp
namespace RawrXD::Metacognitive {

// Reflection result
struct ReflectionResult {
    std::string analysis;
    float confidence_score;
    std::vector<std::string> recommendations;
    std::chrono::milliseconds duration;
};

// Performance metrics
struct PerformanceMetrics {
    float tokens_per_second;
    float latency_ms;
    float memory_usage_mb;
    float cpu_utilization;
    float gpu_utilization;
};

// Reflection interface
class ISelfReflection {
public:
    virtual ~ISelfReflection() = default;
    
    // Analyze recent performance
    virtual ReflectionResult AnalyzePerformance(
        const PerformanceMetrics& metrics) = 0;
    
    // Analyze a specific output
    virtual ReflectionResult AnalyzeOutput(
        const std::string& output,
        const std::string& expected = "") = 0;
    
    // Get current confidence level
    virtual float GetConfidence() const = 0;
    
    // Enable/disable reflection
    virtual void SetEnabled(bool enabled) = 0;
    virtual bool IsEnabled() const = 0;
};

// Get self-reflection instance
std::shared_ptr<ISelfReflection> GetSelfReflection();

} // namespace RawrXD::Metacognitive
```

---

## Configuration API

### Runtime Configuration

```cpp
namespace RawrXD::Config {

// Configuration value types
using ConfigValue = std::variant<
    bool,
    int64_t,
    double,
    std::string,
    std::vector<std::string>
>;

// Get configuration value
template<typename T>
std::optional<T> Get(const std::string& key);

// Set configuration value
template<typename T>
void Set(const std::string& key, const T& value);

// Check if key exists
bool Has(const std::string& key);

// Remove configuration key
void Remove(const std::string& key);

// Load from file
bool LoadFromFile(const std::string& path);

// Save to file
bool SaveToFile(const std::string& path);

// Reset to defaults
void Reset();

} // namespace RawrXD::Config
```

---

## Error Handling

### Exception Types

```cpp
namespace RawrXD {

// Base exception
class RawrXDException : public std::exception {
public:
    explicit RawrXDException(const std::string& message);
    const char* what() const noexcept override;
};

// Specific exceptions
class ModelLoadException : public RawrXDException {
    using RawrXDException::RawrXDException;
};

class InferenceException : public RawrXDException {
    using RawrXDException::RawrXDException;
};

class ConfigurationException : public RawrXDException {
    using RawrXDException::RawrXDException;
};

class OutOfMemoryException : public RawrXDException {
    using RawrXDException::RawrXDException;
};

} // namespace RawrXD
```

### Error Codes

```cpp
namespace RawrXD {

enum class ErrorCode {
    Success = 0,
    InvalidArgument = 1,
    ModelNotFound = 2,
    ModelLoadFailed = 3,
    OutOfMemory = 4,
    DeviceNotAvailable = 5,
    InferenceFailed = 6,
    Timeout = 7,
    Cancelled = 8,
    NotInitialized = 9,
    AlreadyInitialized = 10,
    ConfigurationError = 11,
    Unknown = 99
};

// Get error code from exception
ErrorCode GetErrorCode(const RawrXDException& e);

// Get error message
std::string GetErrorMessage(ErrorCode code);

} // namespace RawrXD
```

---

## Thread Safety

All SDK APIs are thread-safe unless otherwise noted:

| API | Thread Safety |
|-----|---------------|
| `Initialize/Shutdown` | Not thread-safe (call from main thread) |
| `ISession` | Thread-safe for concurrent reads |
| `IAgent` | Thread-safe |
| `IEpisodicMemory` | Thread-safe |
| `ISelfReflection` | Thread-safe |
| `Config::*` | Thread-safe |
| `RegisterTool` | Thread-safe |

---

## Version Compatibility

### Semantic Versioning

RawrXD follows semantic versioning:
- **MAJOR**: Breaking changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

### Compatibility Matrix

| SDK Version | Runtime Version | Status |
|-------------|-----------------|--------|
| 1.0.x | 1.0.x - 1.9.x | ✅ Compatible |
| 1.0.x | 2.0.x+ | ❌ Incompatible |

---

## Examples

### Basic Inference

```cpp
#include <rawrxd/RawrXD.hpp>
#include <iostream>

int main() {
    // Initialize
    RawrXD::Config config;
    config.model_path = "models/llama-7b.gguf";
    config.thread_count = 8;
    
    if (!RawrXD::Initialize(config)) {
        std::cerr << "Failed to initialize\n";
        return 1;
    }
    
    // Create session
    auto session = RawrXD::CreateSession(config.model_path);
    
    // Generate
    auto result = session->Generate("What is AI?");
    std::cout << result.text << "\n";
    std::cout << "TPS: " << result.tokens_per_second << "\n";
    
    // Cleanup
    RawrXD::Shutdown();
    return 0;
}
```

### Streaming Generation

```cpp
auto session = RawrXD::CreateSession("model.gguf");

session->GenerateStream("Tell me a story", 
    [](const std::string& token) {
        std::cout << token << std::flush;
    });

std::cout << "\n";
```

### Agent with Tools

```cpp
using namespace RawrXD::Agentic;

// Register a custom tool
RegisterTool({
    "calculate",
    "Perform mathematical calculations",
    R"({"type": "object", "properties": {"expression": {"type": "string"}}})",
    [](const std::string& params) -> std::string {
        // Parse and calculate
        return "42";
    }
});

// Create agent
AgentConfig agent_config;
agent_config.name = "MathAssistant";
agent_config.model = "models/llama-7b.gguf";
agent_config.system_prompt = "You are a helpful math assistant.";
agent_config.enable_tools = true;

auto agent = CreateAgent(agent_config);

// Execute task
auto result = agent->Execute("What is 15 * 23?");
std::cout << result.output << "\n";
```

---

## Building

### CMake Integration

```cmake
find_package(RawrXD REQUIRED)

target_link_libraries(myapp PRIVATE RawrXD::RawrXD)
```

### pkg-config

```bash
g++ myapp.cpp $(pkg-config --cflags --libs rawrxd) -o myapp
```

---

## License

The RawrXD Stable SDK is provided under the MIT License. See LICENSE file for details.

---

*For the latest documentation, visit: https://docs.rawrxd.io/sdk*

*For support, contact: sdk-support@rawrxd.io*
