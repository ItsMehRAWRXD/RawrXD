# RawrXD Complete API Reference

## Phase Z.5/5: Final Integration & Project Completion

---

## Table of Contents

1. [Core API](#core-api)
2. [Inference API](#inference-api)
3. [Agentic API](#agentic-api)
4. [Memory API](#memory-api)
5. [Metacognitive API](#metacognitive-api)
6. [Plugin API](#plugin-api)
7. [Extension API](#extension-api)
8. [Configuration API](#configuration-api)
9. [Monitoring API](#monitoring-api)
10. [Utility API](#utility-api)

---

## Core API

### Initialization

```cpp
#include <rawrxd/RawrXD.hpp>

namespace RawrXD {

// Initialize the runtime
bool Initialize(const Config& config);
void Shutdown();
bool IsInitialized();

// Configuration
struct Config {
    std::string model_path;
    uint32_t thread_count = 0;
    uint32_t context_length = 4096;
    bool enable_gpu = true;
    std::string device = "auto";
};

} // namespace RawrXD
```

### Version Information

```cpp
namespace RawrXD {

std::string GetVersion();
std::string GetBuildHash();
std::string GetBuildDate();

} // namespace RawrXD
```

---

## Inference API

### Session Management

```cpp
namespace RawrXD {

class ISession {
public:
    virtual ~ISession() = default;
    
    // Generation
    virtual GenerationResult Generate(const std::string& prompt) = 0;
    virtual GenerationResult Generate(const std::string& prompt, 
                                      const GenerationParams& params) = 0;
    
    // Streaming
    virtual void GenerateStream(const std::string& prompt,
                                 std::function<void(const std::string&)> callback) = 0;
    
    // State
    virtual void ClearContext() = 0;
    virtual uint32_t GetContextLength() const = 0;
    virtual uint32_t GetTokenCount() const = 0;
};

std::unique_ptr<ISession> CreateSession(const std::string& model_path);

} // namespace RawrXD
```

### Generation Parameters

```cpp
namespace RawrXD {

struct GenerationParams {
    uint32_t max_tokens = 256;
    float temperature = 0.7f;
    float top_p = 0.9f;
    uint32_t top_k = 40;
    float repeat_penalty = 1.1f;
    std::string stop_sequence;
};

struct GenerationResult {
    std::string text;
    uint32_t tokens_generated;
    float tokens_per_second;
    std::chrono::milliseconds duration;
    bool truncated;
};

} // namespace RawrXD
```

---

## Agentic API

### Agent Management

```cpp
namespace RawrXD::Agentic {

class IAgent {
public:
    virtual ~IAgent() = default;
    
    // Execution
    virtual TaskResult Execute(const std::string& task) = 0;
    virtual void ExecuteStream(const std::string& task,
                                std::function<void(const std::string&)> callback) = 0;
    
    // State
    virtual void Reset() = 0;
    virtual std::string GetName() const = 0;
    virtual std::vector<std::string> GetCapabilities() const = 0;
};

std::unique_ptr<IAgent> CreateAgent(const AgentConfig& config);

} // namespace RawrXD::Agentic
```

### Tool Registration

```cpp
namespace RawrXD::Agentic {

struct ToolDescriptor {
    std::string name;
    std::string description;
    std::string parameters_schema;
    std::function<std::string(const std::string&)> function;
};

bool RegisterTool(const ToolDescriptor& tool);
bool UnregisterTool(const std::string& name);
std::vector<std::string> ListTools();

} // namespace RawrXD::Agentic
```

---

## Memory API

### Episodic Memory

```cpp
namespace RawrXD::Memory {

class IEpisodicMemory {
public:
    virtual ~IEpisodicMemory() = default;
    
    // Storage
    virtual std::string Store(const std::string& content,
                               const std::vector<std::string>& tags = {}) = 0;
    
    // Retrieval
    virtual std::vector<SearchResult> Search(const std::string& query,
                                                uint32_t limit = 10) = 0;
    virtual std::optional<MemoryEntry> Get(const std::string& id) = 0;
    
    // Management
    virtual bool Delete(const std::string& id) = 0;
    virtual void Clear() = 0;
    virtual uint32_t Count() const = 0;
};

std::shared_ptr<IEpisodicMemory> GetEpisodicMemory();

} // namespace RawrXD::Memory
```

### Semantic Memory

```cpp
namespace RawrXD::Memory {

class ISemanticMemory {
public:
    virtual ~ISemanticMemory() = default;
    
    // Knowledge
    virtual bool AddFact(const std::string& subject,
                         const std::string& predicate,
                         const std::string& object) = 0;
    
    // Query
    virtual std::vector<Triple> Query(const std::string& pattern) = 0;
    
    // Reasoning
    virtual std::vector<std::string> Infer(const std::string& query) = 0;
};

std::shared_ptr<ISemanticMemory> GetSemanticMemory();

} // namespace RawrXD::Memory
```

---

## Metacognitive API

### Self-Reflection

```cpp
namespace RawrXD::Metacognitive {

class ISelfReflection {
public:
    virtual ~ISelfReflection() = default;
    
    // Analysis
    virtual ReflectionResult AnalyzePerformance(const PerformanceMetrics& metrics) = 0;
    virtual ReflectionResult AnalyzeOutput(const std::string& output,
                                             const std::string& expected = "") = 0;
    
    // Confidence
    virtual float GetConfidence() const = 0;
    
    // Control
    virtual void SetEnabled(bool enabled) = 0;
    virtual bool IsEnabled() const = 0;
};

std::shared_ptr<ISelfReflection> GetSelfReflection();

} // namespace RawrXD::Metacognitive
```

---

## Plugin API

### Plugin Interface

```cpp
namespace RawrXD::Developer {

class IPlugin {
public:
    virtual ~IPlugin() = default;
    
    // Lifecycle
    virtual bool Initialize(const PluginContext& context) = 0;
    virtual void Shutdown() = 0;
    
    // Info
    virtual PluginManifest GetManifest() const = 0;
    
    // Capabilities
    virtual std::vector<ToolDefinition> GetTools() { return {}; }
    virtual std::vector<ModelBackendDefinition> GetModelBackends() { return {}; }
};

#define RAWRXD_DEFINE_PLUGIN(PluginClass) \
    extern "C" __declspec(dllexport) IPlugin* CreatePlugin() { \
        return new PluginClass(); \
    }

} // namespace RawrXD::Developer
```

---

## Extension API

### Extension Interface

```cpp
namespace RawrXD::Developer {

class IExtension {
public:
    virtual ~IExtension() = default;
    
    // Lifecycle
    virtual bool Activate(IExtensionAPI* api, 
                          const std::unordered_map<std::string, std::string>& context) = 0;
    virtual void Deactivate() = 0;
    
    // Info
    virtual ExtensionManifest GetManifest() const = 0;
};

#define RAWRXD_DEFINE_EXTENSION(ExtensionClass) \
    extern "C" __declspec(dllexport) IExtension* CreateExtension() { \
        return new ExtensionClass(); \
    }

} // namespace RawrXD::Developer
```

---

## Configuration API

### Configuration Management

```cpp
namespace RawrXD::Config {

// Get/Set values
template<typename T>
std::optional<T> Get(const std::string& key);

template<typename T>
void Set(const std::string& key, const T& value);

// Check existence
bool Has(const std::string& key);
void Remove(const std::string& key);

// Load/Save
bool LoadFromFile(const std::string& path);
bool SaveToFile(const std::string& path);

} // namespace RawrXD::Config
```

### Feature Flags

```cpp
namespace RawrXD::Config {

bool IsFeatureEnabled(const std::string& flag_id);
void EnableFeature(const std::string& flag_id);
void DisableFeature(const std::string& flag_id);
void SetRolloutPercentage(const std::string& flag_id, double percentage);

} // namespace RawrXD::Config
```

---

## Monitoring API

### Metrics

```cpp
namespace RawrXD::Operations {

// Record metrics
void RecordCounter(const std::string& name, int64_t value);
void RecordGauge(const std::string& name, double value);
void RecordHistogram(const std::string& name, double value);
void RecordTiming(const std::string& name, std::chrono::milliseconds duration);

// Query metrics
std::optional<TimeSeries> QueryMetric(const std::string& name,
                                       std::chrono::seconds range);

} // namespace RawrXD::Operations
```

### Alerts

```cpp
namespace RawrXD::Operations {

// Alert rules
std::string CreateAlertRule(const AlertRule& rule);
bool UpdateAlertRule(const AlertRule& rule);
bool DeleteAlertRule(const std::string& rule_id);

// Alert instances
std::vector<AlertInstance> GetActiveAlerts();
bool AcknowledgeAlert(const std::string& alert_id, const std::string& user);
bool ResolveAlert(const std::string& alert_id, const std::string& notes);

} // namespace RawrXD::Operations
```

---

## Utility API

### Logging

```cpp
namespace RawrXD {

enum class LogLevel {
    TRACE,
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    FATAL
};

void Log(LogLevel level, const std::string& message);
void Log(LogLevel level, const std::string& component, const std::string& message);

} // namespace RawrXD
```

### Error Handling

```cpp
namespace RawrXD {

class RawrXDException : public std::exception {
public:
    explicit RawrXDException(const std::string& message);
    const char* what() const noexcept override;
};

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

} // namespace RawrXD
```

### Threading

```cpp
namespace RawrXD {

class ThreadPool {
public:
    explicit ThreadPool(uint32_t num_threads);
    ~ThreadPool();
    
    template<typename F>
    auto Submit(F&& f) -> std::future<decltype(f())>;
    
    void WaitAll();
    void Shutdown();
};

} // namespace RawrXD
```

---

## Complete Example

```cpp
#include <rawrxd/RawrXD.hpp>
#include <iostream>

int main() {
    using namespace RawrXD;
    
    // Initialize
    Config config;
    config.model_path = "models/llama-7b.gguf";
    config.thread_count = 8;
    
    if (!Initialize(config)) {
        std::cerr << "Failed to initialize\n";
        return 1;
    }
    
    // Create session
    auto session = CreateSession(config.model_path);
    
    // Configure generation
    GenerationParams params;
    params.max_tokens = 512;
    params.temperature = 0.8f;
    
    // Generate
    auto result = session->Generate("Explain quantum computing:", params);
    std::cout << result.text << "\n";
    std::cout << "Tokens: " << result.tokens_generated << "\n";
    std::cout << "TPS: " << result.tokens_per_second << "\n";
    
    // Cleanup
    Shutdown();
    return 0;
}
```

---

## API Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-07-13 | Initial release |

---

*API Reference Version: 1.0.0*  
*Last Updated: 2026-07-13*
