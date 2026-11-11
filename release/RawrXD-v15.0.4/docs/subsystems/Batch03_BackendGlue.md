# Batch 03 - Backend Glue
## Sovereign IDE Subsystem Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The Backend Glue layer provides the bridge between the low-level ABI layer and higher-level subsystems. It handles ABI-to-SEG routing, ABI-to-MoE routing, and subsystem registry management.

### Key Characteristics

| Attribute | Value |
|-----------|-------|
| **Language** | C++17 |
| **Lines of Code** | ~3,200 |
| **Components** | 4 |
| **SEG Nodes** | 1 |
| **MoE Experts** | 0 |

---

## Responsibilities

1. **ABI-to-SEG Routing** - Translates ABI calls to SEG node execution
2. **ABI-to-MoE Routing** - Routes requests to appropriate MoE experts
3. **Subsystem Registry** - Manages subsystem registration and lifecycle
4. **Dependency Resolution** - Resolves inter-subsystem dependencies

---

## Architecture

```
┌─────────────────────────────────────────────┐
│           Backend Glue Layer                │
├─────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────────┐    │
│  │ ABI-to-SEG   │  │ ABI-to-MoE       │    │
│  │ Router       │  │ Router           │    │
│  └──────────────┘  └──────────────────┘    │
│  ┌──────────────┐  ┌──────────────────┐    │
│  │ Subsystem    │  │ Dependency       │    │
│  │ Registry     │  │ Resolver         │    │
│  └──────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────┘
```

---

## ABI Surfaces

```cpp
// Backend initialization
SOVEREIGN_API BackendResult Backend_Initialize();
SOVEREIGN_API void Backend_Shutdown();

// Routing
SOVEREIGN_API BackendResult Backend_RouteToSEG(
    const char* nodeType,
    const void* input,
    void* output
);

SOVEREIGN_API BackendResult Backend_RouteToMoE(
    const char* domain,
    const void* input,
    void* output
);

// Subsystem management
SOVEREIGN_API BackendResult Backend_RegisterSubsystem(
    uint32_t batchId,
    const SubsystemDescriptor* descriptor
);

SOVEREIGN_API BackendResult Backend_InitializeSubsystem(
    uint32_t batchId
);
```

---

## SEG Nodes

| Node ID | Name | Type | Description |
|---------|------|------|-------------|
| 0x0003 | `SEGNode_BackendDispatch` | Dispatch | Routes calls to appropriate backends |

---

## Implementation Details

### ABI-to-SEG Router

```cpp
class ABIToSEGRouter {
public:
    static SEGResult Route(const char* nodeType, 
                          const void* input, 
                          void* output) {
        // Lookup node factory
        auto factory = SEGRegistry::GetFactory(nodeType);
        if (!factory) {
            return SEG_ERROR_UNKNOWN_NODE_TYPE;
        }
        
        // Create node
        auto node = factory();
        
        // Execute
        ExecutionContext ctx(input);
        auto result = node->Execute(ctx);
        
        // Copy output
        if (result.IsSuccess()) {
            result.CopyTo(output);
        }
        
        return result;
    }
};
```

### Subsystem Registry

```cpp
class SubsystemRegistry {
public:
    bool Register(uint32_t batchId, const SubsystemDescriptor& desc) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (m_subsystems.count(batchId)) {
            return false; // Already registered
        }
        
        m_subsystems[batchId] = desc;
        return true;
    }
    
    bool Initialize(uint32_t batchId) {
        auto it = m_subsystems.find(batchId);
        if (it == m_subsystems.end()) {
            return false;
        }
        
        // Resolve dependencies first
        for (auto dep : it->second.dependencies) {
            if (!Initialize(dep)) {
                return false;
            }
        }
        
        // Initialize this subsystem
        return it->second.initFunc();
    }
    
private:
    std::unordered_map<uint32_t, SubsystemDescriptor> m_subsystems;
    std::mutex m_mutex;
};
```

---

## Testing

```cpp
TEST(BackendGlue, RouteToSEG) {
    // Register test node
    SEGRegistry::Register("TestNode", []() {
        return std::make_unique<TestNode>();
    });
    
    // Route to node
    int input = 42;
    int output = 0;
    auto result = Backend_RouteToSEG("TestNode", &input, &output);
    
    EXPECT_EQ(result, BACKEND_SUCCESS);
    EXPECT_EQ(output, 42);
}

TEST(BackendGlue, SubsystemRegistration) {
    SubsystemDescriptor desc = {
        .name = "TestSubsystem",
        .initFunc = []() { return true; },
        .dependencies = {1, 2}
    };
    
    auto result = Backend_RegisterSubsystem(3, &desc);
    EXPECT_EQ(result, BACKEND_SUCCESS);
}
```

---

## Summary

Batch 03 - Backend Glue provides:

- ✅ **ABI-to-SEG routing**
- ✅ **ABI-to-MoE routing**
- ✅ **Subsystem registry**
- ✅ **Dependency resolution**

**Status:** ✅ Complete
