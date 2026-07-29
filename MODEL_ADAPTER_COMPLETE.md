# Model Adapter - Implementation Complete

## Overview

The **Model Adapter** layer makes AI models interchangeable backends. This enables the "1xT=Infinite" architecture where models are just one option among many.

**Total: ~1,200 lines**

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    MODEL ADAPTER                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              IReasoningBackend (Interface)                 │   │
│  │  ├─ Complete(ctx) → ModelResponse                       │   │
│  │  ├─ CompleteStreaming(ctx, callback)                   │   │
│  │  ├─ Supports(capability) → bool                        │   │
│  │  ├─ GetName() → string                                 │   │
│  │  ├─ GetMaxContextLength() → uint32                     │   │
│  │  ├─ IsHealthy() → bool                                 │   │
│  │  └─ SetEnabled(bool)                                   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│         ┌────────────────────┼────────────────────┐             │
│         │                    │                    │             │
│    ┌────┴────┐        ┌────┴────┐        ┌────┴────┐        │
│    │  Kimi   │        │Moonshot │        │  GGUF   │        │
│    │ Backend │        │ Backend │        │ Backend │        │
│    │ 200K ctx│        │ 128K ctx│        │  32K ctx│        │
│    │ All caps│        │Most caps│        │Basic caps│       │
│    └─────────┘        └─────────┘        └─────────┘        │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              ModelAdapter (Router)                       │ │
│  │  ├─ RegisterBackend(backend)                            │ │
│  │  ├─ SelectBackend(capability) → backend                 │ │
│  │  ├─ Complete(ctx) → response                          │ │
│  │  └─ ConvertToIntent(response) → intent                  │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. IReasoningBackend Interface

Abstract base class for all model backends:

```cpp
class IReasoningBackend {
public:
    virtual ~IReasoningBackend() = default;
    
    // Core completion
    virtual ModelResponse Complete(const ModelContext& ctx) = 0;
    
    // Streaming completion
    virtual void CompleteStreaming(
        const ModelContext& ctx,
        std::function<void(const std::string& chunk)> on_chunk
    ) = 0;
    
    // Capabilities
    virtual bool Supports(ModelCapability cap) const = 0;
    
    // Info
    virtual std::string GetName() const = 0;
    virtual std::string GetVersion() const = 0;
    virtual uint32_t GetMaxContextLength() const = 0;
    
    // Health & toggle
    virtual bool IsHealthy() const = 0;
    virtual void SetEnabled(bool enabled) = 0;
    virtual bool IsEnabled() const = 0;
};
```

### 2. Model Capabilities

```cpp
enum class ModelCapability : uint32_t {
    NONE = 0,
    COMPLETION = 1 << 0,      // Basic text completion
    CHAT = 1 << 1,            // Chat/conversation
    STREAMING = 1 << 2,       // Streaming responses
    FUNCTION_CALLING = 1 << 3, // Function calling
    REASONING = 1 << 4,       // Chain-of-thought
    CODE_GENERATION = 1 << 5, // Code generation
    CODE_ANALYSIS = 1 << 6,   // Code analysis
    LONG_CONTEXT = 1 << 7,    // Long context window
    TOOL_USE = 1 << 8,        // Tool use
};
```

### 3. Concrete Backends

#### Kimi Backend
- **Context:** 200K tokens
- **Capabilities:** All (completion, chat, streaming, function calling, reasoning, code, long context, tools)
- **Use case:** Primary backend for complex tasks

#### Moonshot Backend
- **Context:** 128K tokens
- **Capabilities:** Most (no long context like Kimi)
- **Use case:** Secondary backend, cost optimization

#### GGUF Backend
- **Context:** 32K tokens
- **Capabilities:** Basic (completion, chat, code)
- **Use case:** Local inference, privacy, offline

### 4. ModelAdapter Router

```cpp
class ModelAdapter {
public:
    static ModelAdapter& Instance();
    
    // Register backends
    void RegisterBackend(std::shared_ptr<IReasoningBackend> backend);
    void UnregisterBackend(const std::string& name);
    
    // Select best backend
    std::shared_ptr<IReasoningBackend> SelectBackend(ModelCapability required);
    std::shared_ptr<IReasoningBackend> SelectBackend(
        ModelCapability required,
        const std::string& preferred
    );
    
    // Complete with auto-selection
    ModelResponse Complete(const ModelContext& ctx);
    ModelResponse Complete(const ModelContext& ctx, 
                           const std::string& preferred_backend);
    
    // Convert to intent
    IntentResponse ConvertToIntent(const ModelResponse& response);
    
    // Toggle
    void EnableAdapter(bool enable);
    bool IsEnabled() const;
};
```

## Usage Examples

### Basic Completion

```cpp
// Build context
ModelContext ctx;
ctx.system_prompt = "You are a coding assistant.";
ctx.messages = {{"user", "Optimize this function"}};
ctx.relevant_files = {"src/main.cpp"};
ctx.max_tokens = 4096;
ctx.temperature = 0.7f;

// Complete (auto-selects best backend)
auto response = MODEL_ADAPTER.Complete(ctx);

if (response.success) {
    std::cout << "Response: " << response.content << "\n";
    std::cout << "Tokens: " << response.tokens_used << "\n";
    std::cout << "Latency: " << response.latency_ms << "ms\n";
}
```

### Preferred Backend

```cpp
// Use specific backend
auto response = MODEL_ADAPTER.Complete(ctx, "kimi");

// Falls back to any available if preferred unavailable
```

### Streaming

```cpp
auto backend = MODEL_ADAPTER.SelectBackend(ModelCapability::STREAMING);
if (backend) {
    backend->CompleteStreaming(ctx, [](const std::string& chunk) {
        std::cout << chunk << std::flush;
    });
}
```

### Register Custom Backend

```cpp
// Create backend
BackendConfig config;
config.name = "custom";
config.type = "custom";
config.enabled = true;

auto backend = std::make_shared<MyCustomBackend>(config);

// Register
MODEL_ADAPTER.RegisterBackend(backend);

// Now available for selection
auto selected = MODEL_ADAPTER.SelectBackend(ModelCapability::COMPLETION);
```

### Convert to Intent

```cpp
// Get model response
auto response = MODEL_ADAPTER.Complete(ctx);

// Convert to intent
IntentResponse intent = MODEL_ADAPTER.ConvertToIntent(response);

if (intent.status == IntentStatus::PENDING_VALIDATION) {
    // Process intent through pipeline
    auto result = EXECUTION_PIPELINE.Execute(intent.request);
}
```

## Backend Configuration

```cpp
BackendConfig config;
config.name = "kimi-production";
config.type = "kimi";
config.endpoint = "https://api.moonshot.cn";
config.api_key = "${KIMI_API_KEY}";  // Loaded from env
config.model_name = "kimi-latest";
config.timeout_ms = 30000;
config.max_retries = 3;
config.enabled = true;
config.priority = 10;  // Higher = preferred

// Save/load
config.SaveToFile("backends/kimi.json");
config.LoadFromFile("backends/kimi.json");
```

## Toggle System

### Compile-Time

```cpp
// In CMakeLists.txt
option(RAWR_MODEL_ADAPTER "Enable model adapter" ON)

// In code
#if RAWR_MODEL_ADAPTER_ENABLED
    #define RAWR_CT_MODEL_ADAPTER(code) code
#else
    #define RAWR_CT_MODEL_ADAPTER(code)
#endif
```

### Runtime

```cpp
// Disable entire adapter
MODEL_ADAPTER.EnableAdapter(false);

// Disable specific backend
auto backend = MODEL_ADAPTER.SelectBackend(...);
backend->SetEnabled(false);

// Check status
if (MODEL_ADAPTER.IsEnabled() && backend->IsEnabled()) {
    // Use backend
}
```

## Integration with Sovereign Substrate

```
Model Response
      ↓
[ModelAdapter::ConvertToIntent]
      ↓
IntentResponse
      ↓
[IntentExecutionPipeline::Execute]
      ↓
[Security Pre-Check]
      ↓
[Patch Firewall]
      ↓
[Execution]
      ↓
Result
```

## Test Coverage

| Test Category | Tests | Coverage |
|--------------|-------|----------|
| Core Adapter | 4 | Singleton, toggle, registration, selection |
| Backend Caps | 3 | Kimi, Moonshot, GGUF capabilities |
| Functionality | 5 | Completion, streaming, context, conversion |
| Configuration | 4 | Persistence, health, flags, disabled |
| **Total** | **16** | **Complete** |

## Files Created

- `src/intent/model_adapter.hpp` - Interface and declarations
- `src/intent/model_adapter.cpp` - Implementation (~900 lines)
- `tests/test_model_adapter.cpp` - 16 unit tests (~400 lines)

## Complete Statistics

| Component | Lines | Status |
|-----------|-------|--------|
| Intent Guardrails | ~3,500 | ✅ |
| Sovereign Puppeteer | ~2,970 | ✅ |
| Sovereign Agent Kernel | ~4,500 | ✅ |
| Repository Memory Graph | ~1,500 | ✅ |
| Control Plane UI | ~1,200 | ✅ |
| Security Hardening | ~1,700 | ✅ |
| Model Adapter | ~1,200 | ✅ |
| Tests + Build + Demo | ~2,000 | ✅ |
| **Total** | **~18,200** | **✅** |

## The Constitution

> **The model proposes. The IDE decides. The Agent evolves.**
> > **Models are interchangeable. The substrate is sovereign.**
> **Kimi, Moonshot, GGUF - all serve the same purpose.**
> **The architecture transcends any single model.**

---

**Date:** 2026-07-20  
**Status:** Model Adapter Complete  
**Total:** ~18,200 lines
