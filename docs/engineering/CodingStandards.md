# Sovereign IDE - Coding Standards
## Internal Engineering Guide

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Complete

---

## Table of Contents

1. [Overview](#overview)
2. [General Principles](#general-principles)
3. [Naming Conventions](#naming-conventions)
4. [Code Organization](#code-organization)
5. [MASM Standards](#masm-standards)
6. [C/C++ Standards](#cc-standards)
7. [Documentation Standards](#documentation-standards)
8. [Testing Standards](#testing-standards)
9. [Review Checklist](#review-checklist)

---

## Overview

This document defines the coding standards for the Sovereign IDE codebase. All contributors must follow these standards.

### Scope

- MASM assembly code
- C ABI surfaces
- C++ implementation code
- Header files
- Build scripts
- Documentation

---

## General Principles

### Core Values

1. **Clarity over cleverness** - Code should be readable first
2. **Determinism** - All execution paths must be predictable
3. **Safety** - Bounds checking, error handling, no undefined behavior
4. **Performance** - Optimize hot paths, profile before optimizing
5. **Maintainability** - Future developers must understand the code

### Code Quality Metrics

| Metric | Target | Minimum |
|--------|--------|---------|
| Cyclomatic complexity | < 10 | < 20 |
| Function length | < 50 lines | < 100 lines |
| File length | < 500 lines | < 1000 lines |
| Comment ratio | > 20% | > 10% |
| Test coverage | > 90% | > 80% |

---

## Naming Conventions

### MASM Naming

```asm
; Functions: PascalCase with module prefix
SovereignKernel_Init PROC
SovereignKernel_Shutdown PROC
SEGNode_Execute PROC

; Labels: snake_case with descriptive names
.init_section:
.error_handler:
.loop_begin:

; Variables: g_ prefix for global, local for local
g_kernel_initialized QWORD 0
local_buffer BYTE 256 DUP(?)

; Constants: UPPER_SNAKE_CASE
MAX_SEG_NODES EQU 256
MOE_EXPERT_COUNT EQU 128

; Registers: Use standard names
; rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8-r15
; xmm0-xmm15, ymm0-ymm15, zmm0-zmm31
```

### C Naming

```c
// Functions: Module_PascalCase
SDKResult SDK_Initialize(const SDKConfig* config, SDKHandle* outHandle);
SDKResult SDK_Shutdown(SDKHandle handle);

// Types: PascalCase with suffix
typedef struct SDKConfig {
    uint32_t version;
    const char* logPath;
} SDKConfig;

typedef enum SDKResult {
    SDK_SUCCESS = 0,
    SDK_ERROR_INVALID_PARAM = 1,
    SDK_ERROR_OUT_OF_MEMORY = 2
} SDKResult;

// Constants: kCamelCase or UPPER_SNAKE_CASE
static const uint32_t kMaxCapabilities = 487;
#define MAX_SEG_NODES 256

// Macros: UPPER_SNAKE_CASE with module prefix
#define SOVEREIGN_VERSION_MAJOR 1
#define SOVEREIGN_VERSION_MINOR 0
```

### C++ Naming

```cpp
// Classes: PascalCase
class SegEngine {
public:
    // Methods: PascalCase
    bool Initialize(const Config& config);
    void Shutdown();
    
    // Member variables: m_ prefix + camelCase
    bool m_initialized;
    std::vector<Node> m_nodes;
    
    // Static members: s_ prefix
    static SegEngine* s_instance;
};

// Namespaces: lowercase
namespace sovereign {
namespace seg {

// Template parameters: PascalCase
template<typename NodeType>
class NodePool {
    // ...
};

} // namespace seg
} // namespace sovereign

// Enums: PascalCase + k prefix for values
enum class CapabilityType {
    kAnalysis,
    kTransformation,
    kExploit,
    kAgentic
};

// Concepts (C++20): PascalCase
template<typename T>
concept CapabilityProvider = requires(T t) {
    { t.GetCapabilities() } -> std::convertible_to<std::vector<Capability>>;
};
```

---

## Code Organization

### File Structure

```
src/
├── kernel/              # MASM kernel code
│   ├── kernel.asm
│   ├── memory.asm
│   └── init.asm
├── abi/                 # C ABI surfaces
│   ├── abi.c
│   ├── abi.h
│   └── exports.def
├── seg/                 # SEG engine
│   ├── seg_engine.cpp
│   ├── seg_engine.h
│   ├── node.cpp
│   └── node.h
├── moe/                 # MoE router
│   ├── moe_router.cpp
│   ├── moe_router.h
│   └── expert.cpp
├── batches/             # Batch implementations
│   ├── batch_01/
│   ├── batch_02/
│   └── ...
└── gui/                 # GUI layer
    ├── main_window.cpp
    └── panels/
```

### Header Organization

```cpp
// file.h - Header file template
#pragma once

// 1. System includes
#include <cstdint>
#include <vector>
#include <string>

// 2. Third-party includes
#include <nlohmann/json.hpp>

// 3. Project includes
#include "sovereign/types.h"
#include "sovereign/result.h"

// 4. Forward declarations
namespace sovereign {
class SegEngine;
class MoERouter;
}

// 5. Namespace
namespace sovereign {

// 6. Declarations
class MyClass {
public:
    MyClass();
    ~MyClass();
    
    bool Initialize(const Config& config);
    void Shutdown();
    
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace sovereign
```

### Source Organization

```cpp
// file.cpp - Source file template

// 1. Corresponding header
#include "sovereign/myclass.h"

// 2. System includes
#include <algorithm>
#include <mutex>

// 3. Third-party includes

// 4. Project includes
#include "sovereign/logger.h"

// 5. Anonymous namespace for internal helpers
namespace {
    constexpr uint32_t kBufferSize = 4096;
    
    bool ValidateInput(const Config& config) {
        return config.version > 0;
    }
}

// 6. Namespace
namespace sovereign {

// 7. Implementation
MyClass::MyClass() : m_impl(std::make_unique<Impl>()) {}

MyClass::~MyClass() = default;

bool MyClass::Initialize(const Config& config) {
    if (!ValidateInput(config)) {
        Logger::Error("Invalid config");
        return false;
    }
    
    return m_impl->Initialize(config);
}

void MyClass::Shutdown() {
    m_impl->Shutdown();
}

} // namespace sovereign
```

---

## MASM Standards

### File Template

```asm
; file.asm - MASM source file
; Description: Brief description of module purpose
; Author: Name
; Date: YYYY-MM-DD

; Includes
include sovereign.inc
include kernel.inc

; Exports
PUBLIC SovereignKernel_Init
PUBLIC SovereignKernel_Shutdown

; Data section
.DATA
    ; Constants
    KERNEL_VERSION EQU 0100h
    
    ; Global variables
    ALIGN 8
    g_kernel_initialized QWORD 0
    g_error_count QWORD 0

; Code section
.CODE

;-----------------------------------------------------------------------------
; SovereignKernel_Init
; Initializes the Sovereign kernel
;
; Parameters:
;   rcx - pointer to KernelConfig
;
; Returns:
;   rax - RESULT_SUCCESS or error code
;-----------------------------------------------------------------------------
SovereignKernel_Init PROC FRAME
    ; Save non-volatile registers
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    push rsi
    .pushreg rsi
    
    ; Allocate stack space
    sub rsp, 40
    .allocstack 40
    
    .endprolog
    
    ; Function body
    mov rbx, rcx                    ; Save config pointer
    
    ; Check if already initialized
    mov rax, g_kernel_initialized
    test rax, rax
    jnz .already_initialized
    
    ; Initialize subsystems
    call InitializeMemory
    test rax, rax
    jnz .error
    
    call InitializeTelemetry
    test rax, rax
    jnz .error
    
    ; Mark as initialized
    mov g_kernel_initialized, 1
    
    ; Return success
    xor rax, rax
    jmp .exit
    
.already_initialized:
    mov rax, RESULT_ALREADY_INITIALIZED
    jmp .exit
    
.error:
    inc g_error_count
    
.exit:
    ; Restore stack
    add rsp, 40
    
    ; Restore registers
    pop rsi
    pop rdi
    pop rbx
    
    ret
SovereignKernel_Init ENDP

;-----------------------------------------------------------------------------
; SovereignKernel_Shutdown
; Shuts down the Sovereign kernel
;-----------------------------------------------------------------------------
SovereignKernel_Shutdown PROC FRAME
    ; Implementation
    mov g_kernel_initialized, 0
    xor rax, rax
    ret
SovereignKernel_Shutdown ENDP

END
```

### MASM Best Practices

```asm
; 1. Always use FRAME for unwind info
MyFunction PROC FRAME
    ; ...
MyFunction ENDP

; 2. Align data appropriately
ALIGN 8     ; For 64-bit values
ALIGN 16    ; For XMM operations
ALIGN 64    ; For cache line optimization

; 3. Use explicit operand sizes
mov rax, QWORD PTR [rbx]    ; Clear size
mov eax, DWORD PTR [rbx]    ; Clear size
mov ax, WORD PTR [rbx]      ; Clear size
mov al, BYTE PTR [rbx]      ; Clear size

; 4. Preserve non-volatile registers
; RBX, RBP, RDI, RSI, R12-R15, XMM6-XMM15

; 5. Shadow space for Windows x64
sub rsp, 32     ; Allocate shadow space
add rsp, 32     ; Deallocate

; 6. Stack must be 16-byte aligned
; Before CALL: (RSP + 8) % 16 == 0
```

---

## C/C++ Standards

### Error Handling

```cpp
// Use Result<T, E> pattern
template<typename T, typename E>
class Result {
public:
    bool IsOk() const { return m_isOk; }
    bool IsErr() const { return !m_isOk; }
    
    T& Value() { return m_value; }
    E& Error() { return m_error; }
    
private:
    bool m_isOk;
    union {
        T m_value;
        E m_error;
    };
};

// Usage
Result<Handle, ErrorCode> OpenFile(const std::string& path) {
    Handle h = ::OpenFile(path.c_str());
    if (h == INVALID_HANDLE) {
        return Result<Handle, ErrorCode>::Err(ERROR_OPEN_FAILED);
    }
    return Result<Handle, ErrorCode>::Ok(h);
}

// Or use exceptions for exceptional cases
try {
    auto file = OpenFile("config.json");
    auto config = ParseConfig(file);
} catch (const ConfigException& e) {
    Logger::Error("Failed to load config: {}", e.what());
    return false;
}
```

### Memory Management

```cpp
// Prefer smart pointers
std::unique_ptr<Resource> CreateResource() {
    return std::make_unique<Resource>();
}

std::shared_ptr<SharedState> GetSharedState() {
    static std::weak_ptr<SharedState> s_weak;
    auto state = s_weak.lock();
    if (!state) {
        state = std::make_shared<SharedState>();
        s_weak = state;
    }
    return state;
}

// RAII for resources
class FileHandle {
public:
    explicit FileHandle(const char* path) 
        : m_handle(::OpenFile(path)) {}
    
    ~FileHandle() {
        if (m_handle != INVALID_HANDLE) {
            ::CloseFile(m_handle);
        }
    }
    
    // Disable copying
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
    
    // Enable moving
    FileHandle(FileHandle&& other) noexcept
        : m_handle(other.m_handle) {
        other.m_handle = INVALID_HANDLE;
    }
    
private:
    Handle m_handle;
};
```

### Thread Safety

```cpp
// Use mutex for shared state
class ThreadSafeQueue {
public:
    void Push(Item item) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_queue.push(std::move(item));
        m_cv.notify_one();
    }
    
    std::optional<Item> Pop() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cv.wait(lock, [this] { return !m_queue.empty(); });
        
        if (m_queue.empty()) {
            return std::nullopt;
        }
        
        Item item = std::move(m_queue.front());
        m_queue.pop();
        return item;
    }
    
private:
    std::queue<Item> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cv;
};

// Use atomic for simple counters
std::atomic<uint64_t> g_requestCount{0};

void ProcessRequest() {
    g_requestCount.fetch_add(1, std::memory_order_relaxed);
    // ...
}
```

---

## Documentation Standards

### File Header

```cpp
/**
 * @file seg_engine.cpp
 * @brief SEG (Sovereign Execution Graph) engine implementation
 * @author Sovereign Team
 * @date 2026-07-11
 * @version 1.0.0
 * 
 * @copyright Copyright (c) 2026
 * 
 * This file implements the core SEG engine responsible for
 * deterministic execution graph management and node scheduling.
 */
```

### Function Documentation

```cpp
/**
 * @brief Initializes the SEG engine with the given configuration
 * 
 * @param config Configuration parameters for the engine
 * @return true if initialization succeeded, false otherwise
 * 
 * @pre config.version must be SOVEREIGN_CONFIG_VERSION
 * @post Engine is ready for node registration
 * 
 * @throws std::invalid_argument if config is invalid
 * 
 * @note This function is thread-safe
 * @see SegEngine::Shutdown
 */
bool Initialize(const Config& config);
```

### Inline Comments

```cpp
// Good: Explain WHY, not WHAT
// Cache frequently accessed nodes to avoid hash lookup
auto& node = m_nodeCache[nodeId];

// Bad: Explains obvious code
// Increment counter by 1
counter++;

// Good: Complex algorithm explanation
// Use Welford's online algorithm for numerical stability
// when computing running mean and variance
mean += (value - mean) / count;
variance += (value - mean) * (value - oldMean);
```

---

## Testing Standards

### Unit Test Template

```cpp
// test_seg_engine.cpp
#include <gtest/gtest.h>
#include "sovereign/seg_engine.h"

using namespace sovereign;

class SegEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        Config config;
        config.maxNodes = 100;
        ASSERT_TRUE(m_engine.Initialize(config));
    }
    
    void TearDown() override {
        m_engine.Shutdown();
    }
    
    SegEngine m_engine;
};

TEST_F(SegEngineTest, InitializeWithValidConfig) {
    EXPECT_TRUE(m_engine.IsInitialized());
}

TEST_F(SegEngineTest, RegisterNode) {
    NodeConfig nodeConfig;
    nodeConfig.name = "TestNode";
    
    auto result = m_engine.RegisterNode(nodeConfig);
    EXPECT_TRUE(result.IsOk());
    EXPECT_EQ(m_engine.GetNodeCount(), 1);
}

TEST_F(SegEngineTest, RegisterNodeExceedsLimit) {
    // Test boundary condition
    for (int i = 0; i < 100; ++i) {
        NodeConfig config;
        config.name = "Node" + std::to_string(i);
        m_engine.RegisterNode(config);
    }
    
    NodeConfig overflowConfig;
    overflowConfig.name = "Overflow";
    auto result = m_engine.RegisterNode(overflowConfig);
    EXPECT_FALSE(result.IsOk());
    EXPECT_EQ(result.Error(), ErrorCode::NODE_LIMIT_EXCEEDED);
}
```

### Test Categories

| Category | Coverage | Examples |
|----------|----------|----------|
| Unit | Individual functions | `SegEngine::RegisterNode` |
| Integration | Component interaction | SEG + MoE routing |
| System | End-to-end | Full analysis workflow |
| Performance | Benchmarks | 1000-node execution |
| Security | Fuzzing | Input validation |

---

## Review Checklist

### Pre-Submission Checklist

- [ ] Code compiles without warnings (treat warnings as errors)
- [ ] All tests pass
- [ ] New code has unit tests (>80% coverage)
- [ ] Documentation updated
- [ ] No memory leaks (verified with Valgrind/ASan)
- [ ] Thread safety verified
- [ ] Performance regression checked
- [ ] Code review completed

### Review Criteria

| Aspect | Criteria |
|--------|----------|
| Correctness | Logic is correct, edge cases handled |
| Performance | No unnecessary allocations, hot paths optimized |
| Safety | Bounds checking, error handling, no UB |
| Style | Follows naming conventions, formatting |
| Documentation | Comments explain why, not what |
| Testing | Adequate test coverage |

---

## Summary

Coding standards include:

- ✅ **Naming conventions** for MASM, C, and C++
- ✅ **Code organization** patterns
- ✅ **MASM standards** with examples
- ✅ **C/C++ standards** for error handling, memory, threads
- ✅ **Documentation standards** with templates
- ✅ **Testing standards** with examples
- ✅ **Review checklist**

**Status:** ✅ Complete

---

*End of Coding Standards*
