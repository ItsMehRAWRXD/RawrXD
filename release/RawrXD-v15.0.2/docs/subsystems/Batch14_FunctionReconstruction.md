# Batch 14 - Function Reconstruction
## Sovereign IDE Subsystem Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The Function Reconstruction subsystem reconstructs function boundaries and calling conventions. It provides prologue/epilogue detection, stack frame reconstruction, calling convention inference, and parameter/return type inference.

### Key Characteristics

| Attribute | Value |
|-----------|-------|
| **Language** | C++17 |
| **Lines of Code** | ~5,800 |
| **Calling Conventions** | cdecl, stdcall, fastcall, thiscall, vectorcall |
| **Architectures** | x86, x64, ARM, ARM64 |
| **SEG Nodes** | 1 |
| **MoE Experts** | 1 |

---

## Responsibilities

1. **Prologue/Epilogue Detection** - Identify function entry/exit
2. **Stack Frame Reconstruction** - Rebuild stack frame layout
3. **Calling Convention Inference** - Detect calling convention used
4. **Parameter Type Inference** - Infer parameter types
5. **Return Type Inference** - Infer return type

---

## Architecture

```
┌─────────────────────────────────────────────┐
│         Function Reconstruction             │
├─────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Prologue/  │  │   Stack Frame    │    │
│  │   Epilogue   │  │   Reconstructor  │    │
│  │   Detector   │  │                  │    │
│  └──────────────┘  └──────────────────┘    │
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Calling    │  │   Type           │    │
│  │   Convention │  │   Inference      │    │
│  │   Inference  │  │                  │    │
│  └──────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────┘
```

---

## ABI Surfaces

```cpp
// Function reconstruction initialization
SOVEREIGN_API FuncReconResult FuncRecon_Initialize();
SOVEREIGN_API void FuncRecon_Shutdown();

// Function detection
SOVEREIGN_API Function* FuncRecon_DetectFunction(BinaryHandle binary, 
                                                  uint64_t address);
SOVEREIGN_API FunctionList* FuncRecon_DetectAllFunctions(BinaryHandle binary);

// Analysis
SOVEREIGN_API CallingConvention FuncRecon_InferCallingConvention(Function* func);
SOVEREIGN_API StackFrame* FuncRecon_ReconstructStackFrame(Function* func);
SOVEREIGN_API Type* FuncRecon_InferParameterType(Function* func, size_t index);
SOVEREIGN_API Type* FuncRecon_InferReturnType(Function* func);

// Information
SOVEREIGN_API uint64_t FuncRecon_GetEntryPoint(Function* func);
SOVEREIGN_API uint64_t FuncRecon_GetExitPoint(Function* func);
SOVEREIGN_API size_t FuncRecon_GetSize(Function* func);
```

---

## SEG Nodes

| Node ID | Name | Type | Description |
|---------|------|------|-------------|
| 0x0012 | `SEGNode_FunctionReconstruct` | Analysis | Reconstruct function information |

---

## MoE Experts

| Expert Name | Domain | Description |
|-------------|--------|-------------|
| `Expert_FunctionInference` | function | Infer function characteristics |

---

## Implementation Details

### Prologue/Epilogue Detection

```cpp
class FunctionDetector {
public:
    Function* DetectFunction(uint64_t address) {
        Function* func = new Function();
        func->entryPoint = address;
        
        // Detect prologue
        if (!DetectPrologue(func)) {
            delete func;
            return nullptr;
        }
        
        // Find function end
        if (!FindFunctionEnd(func)) {
            delete func;
            return nullptr;
        }
        
        // Detect epilogue
        DetectEpilogue(func);
        
        // Infer calling convention
        func->callingConvention = InferCallingConvention(func);
        
        return func;
    }
    
private:
    bool DetectPrologue(Function* func) {
        auto insts = GetInstructions(func->entryPoint, 10);
        
        // x64: push rbp; mov rbp, rsp
        // x86: push ebp; mov ebp, esp
        if (insts.size() >= 2) {
            if (IsPushBP(insts[0]) && IsMovBPToSP(insts[1])) {
                func->hasFramePointer = true;
                func->framePointerReg = insts[0].operands[0].reg;
                return true;
            }
        }
        
        // Frameless function (no prologue)
        func->hasFramePointer = false;
        return true;
    }
    
    bool FindFunctionEnd(Function* func) {
        uint64_t addr = func->entryPoint;
        
        while (true) {
            auto inst = GetInstruction(addr);
            
            // Check for return instruction
            if (IsReturn(inst)) {
                func->exitPoint = addr;
                func->size = addr - func->entryPoint + inst.size;
                return true;
            }
            
            // Check for jump outside function (tail call)
            if (IsJump(inst) && IsOutsideRange(inst.target, func)) {
                func->exitPoint = addr;
                func->size = addr - func->entryPoint + inst.size;
                return true;
            }
            
            addr += inst.size;
            
            // Safety limit
            if (addr - func->entryPoint > MAX_FUNCTION_SIZE) {
                return false;
            }
        }
    }
    
    CallingConvention InferCallingConvention(Function* func) {
        // Analyze parameter passing
        bool usesRCX = false, usesRDX = false, usesR8 = false, usesR9 = false;
        bool usesXMM0 = false;
        
        for (const auto& inst : GetInstructions(func)) {
            if (UsesRegister(inst, REG_RCX)) usesRCX = true;
            if (UsesRegister(inst, REG_RDX)) usesRDX = true;
            if (UsesRegister(inst, REG_R8)) usesR8 = true;
            if (UsesRegister(inst, REG_R9)) usesR9 = true;
            if (UsesRegister(inst, REG_XMM0)) usesXMM0 = true;
        }
        
        // x64 Windows: RCX, RDX, R8, R9 for integers
        // x64 Linux: RDI, RSI, RDX, RCX, R8, R9 for integers
        if (usesRCX && usesRDX && usesR8 && usesR9) {
            return CALLCONV_FASTCALL;
        }
        
        // Check for thiscall (ECX/RCX used early)
        if (usesRCX && IsUsedInFirstInstructions(func, REG_RCX, 3)) {
            return CALLCONV_THISCALL;
        }
        
        return CALLCONV_CDECL;
    }
};
```

### Stack Frame Reconstruction

```cpp
class StackFrameReconstructor {
public:
    StackFrame* Reconstruct(Function* func) {
        auto frame = new StackFrame();
        
        if (!func->hasFramePointer) {
            // Frameless function - analyze ESP/RSP usage
            ReconstructFrameless(frame, func);
        } else {
            // Function with frame pointer
            ReconstructWithFramePointer(frame, func);
        }
        
        return frame;
    }
    
private:
    void ReconstructWithFramePointer(StackFrame* frame, Function* func) {
        // Find sub rsp, X or add rsp, -X (stack allocation)
        for (const auto& inst : GetInstructions(func)) {
            if (IsStackAllocation(inst)) {
                frame->localSize = GetStackAllocationSize(inst);
                break;
            }
        }
        
        // Analyze stack accesses
        for (const auto& inst : GetInstructions(func)) {
            if (IsStackAccess(inst)) {
                auto offset = GetStackOffset(inst);
                
                if (offset > 0) {
                    // Parameter (above frame pointer)
                    frame->parameters[offset] = InferType(inst);
                } else if (offset < 0) {
                    // Local variable (below frame pointer)
                    frame->locals[-offset] = InferType(inst);
                }
            }
        }
    }
    
    void ReconstructFrameless(StackFrame* frame, Function* func) {
        // Track ESP/RSP changes
        int32_t stackOffset = 0;
        
        for (const auto& inst : GetInstructions(func)) {
            if (IsPush(inst)) {
                stackOffset += GetOperandSize(inst.operands[0]);
            } else if (IsPop(inst)) {
                stackOffset -= GetOperandSize(inst.operands[0]);
            } else if (IsSubESP(inst)) {
                stackOffset += inst.operands[1].immediate;
            } else if (IsAddESP(inst)) {
                stackOffset -= inst.operands[1].immediate;
            }
            
            // Track stack-relative accesses
            if (IsStackAccess(inst)) {
                auto offset = GetStackOffset(inst) + stackOffset;
                // ...
            }
        }
    }
};
```

---

## Testing

```cpp
TEST(FunctionReconstruction, DetectFunction) {
    FuncRecon_Initialize();
    
    // Load test binary
    auto binary = Loader_Load("test_functions.exe");
    
    // Detect function at known address
    auto func = FuncRecon_DetectFunction(binary, 0x1000);
    EXPECT_NE(func, nullptr);
    
    // Verify function properties
    EXPECT_EQ(FuncRecon_GetEntryPoint(func), 0x1000);
    EXPECT_GT(FuncRecon_GetSize(func), 0);
    
    // Detect all functions
    auto funcList = FuncRecon_DetectAllFunctions(binary);
    EXPECT_GT(funcList->count, 0);
    
    FuncRecon_Shutdown();
}

TEST(FunctionReconstruction, InferCallingConvention) {
    FuncRecon_Initialize();
    
    auto binary = Loader_Load("test_callconv.exe");
    auto func = FuncRecon_DetectFunction(binary, 0x2000);
    
    // Infer calling convention
    auto cc = FuncRecon_InferCallingConvention(func);
    EXPECT_EQ(cc, CALLCONV_FASTCALL);
    
    // Reconstruct stack frame
    auto frame = FuncRecon_ReconstructStackFrame(func);
    EXPECT_NE(frame, nullptr);
    EXPECT_GT(frame->localSize, 0);
    
    FuncRecon_Shutdown();
}
```

---

## Summary

Batch 14 - Function Reconstruction provides:

- ✅ **Prologue/epilogue detection**
- ✅ **Stack frame reconstruction**
- ✅ **Calling convention inference**
- ✅ **Parameter type inference**
- ✅ **Return type inference**

**Status:** ✅ Complete
