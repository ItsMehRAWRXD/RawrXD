# RawrXD Validation Plan - Next Milestone

**Target:** L4 (Real backend exercised)  
**Date:** 2026-07-09  
**Focus:** Minimal contract, actual GGML execution

---

## Current State (L3)

```
Core (L3 ✓)
  ↓
IAgenticEngine
  ↓
MockAgenticEngine (L3 ✓)
```

**Verified:** Orchestration layer works end-to-end with mock.

---

## Target State (L4)

```
Core (L3 ✓)
  ↓
IAgenticEngine
  ↓
GGMLAgenticEngine (target L4)
  ↓
Phi-3-mini GGUF
  ↓
Generate one deterministic token
```

**Goal:** Contract test passes with real GGML backend.

---

## Minimal Contract (5 methods)

```cpp
class IAgenticEngine {
public:
    virtual ~IAgenticEngine() = default;
    
    // Lifecycle
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    
    // Model
    virtual bool LoadModel(const std::string& path) = 0;
    virtual bool IsModelLoaded() const = 0;
    
    // Tokenization
    virtual std::vector<int> Tokenize(const std::string& text) = 0;
    
    // Generation
    virtual std::string Generate(
        const std::vector<int>& tokens,
        size_t maxTokens
    ) = 0;
};
```

**Intentionally excludes:**
- Streaming (can be added later)
- Cancellation (can be added later)
- Capabilities query (can be added later)
- Async operations (keep it simple)

---

## Validation Sequence

### Step 1: GGMLAgenticEngine Implementation

```cpp
class GGMLAgenticEngine : public IAgenticEngine {
private:
    ggml_context* ctx = nullptr;
    ggml_model* model = nullptr;
    
public:
    bool Initialize() override {
        // Initialize GGML context
        ctx = ggml_init({.mem_size = 1GB});
        return ctx != nullptr;
    }
    
    bool LoadModel(const std::string& path) override {
        // Load GGUF file
        model = ggml_load_model(ctx, path.c_str());
        return model != nullptr;
    }
    
    std::vector<int> Tokenize(const std::string& text) override {
        // Use model's tokenizer
        return model->tokenize(text);
    }
    
    std::string Generate(const std::vector<int>& tokens, 
                         size_t maxTokens) override {
        // Run inference
        // Return generated text
    }
    
    void Shutdown() override {
        if (model) ggml_free_model(model);
        if (ctx) ggml_free(ctx);
    }
};
```

### Step 2: Contract Test

```cpp
TEST(Contract, GGMLAgenticEngine) {
    auto engine = std::make_unique<GGMLAgenticEngine>();
    
    // Initialize
    ASSERT_TRUE(engine->Initialize());
    
    // Load model
    ASSERT_TRUE(engine->LoadModel("phi-3-mini.gguf"));
    ASSERT_TRUE(engine->IsModelLoaded());
    
    // Tokenize
    auto tokens = engine->Tokenize("Hello");
    ASSERT_FALSE(tokens.empty());
    
    // Generate
    auto text = engine->Generate(tokens, 1);  // Just 1 token
    ASSERT_FALSE(text.empty());
    
    // Shutdown
    engine->Shutdown();
}
```

### Step 3: Deterministic Validation

Run with fixed seed, verify:
- Same input → same token ID
- Same token ID → same output
- No crashes, no memory leaks

---

## Success Criteria

| Test | Expected | Evidence |
|------|----------|----------|
| Initialize | Returns true | Console output |
| LoadModel | Returns true | File loaded |
| Tokenize | Returns tokens | Token count > 0 |
| Generate | Returns text | Non-empty string |
| Shutdown | No crash | Clean exit |
| **Contract** | **All pass** | **L4 achieved** |

---

## Blockers to Address

| Blocker | Resolution |
|---------|------------|
| GGML headers | Include from `src/ggml/` |
| GGUF loader | Reuse existing loader |
| Memory management | RAII wrappers |
| Error handling | Return false on failure |

---

### Files Created

```
src/agentic/
├── IAgenticEngine.h          ✓ (minimal, 5 methods)
├── MockAgenticEngine.h       ✓ (L3 verified)
├── GGMLAgenticEngine.h       ✓ (header)
├── GGMLAgenticEngine.cpp     ✓ (stub implementation)

tests/
├── l4_contract_test.cpp      ✓ (L4 validation)
└── contract_test.cpp         (update for minimal interface)
```

---

## Definition of Done

- [ ] `GGMLAgenticEngine` implements `IAgenticEngine`
- [ ] Contract test passes with `phi-3-mini.gguf`
- [ ] Generates at least 1 deterministic token
- [ ] No memory leaks (valgrind/checked)
- [ ] Level L4 achieved

---

## After L4

| Level | Work |
|-------|------|
| L5 | Differential correctness vs reference |
| L6 | Performance benchmarks (tokens/sec) |
| L7 | Long-duration stress testing |

**Current:** L3 (mock backend)  
**Next:** L4 (GGML backend)  
**Then:** L5-L7 (hardening)
