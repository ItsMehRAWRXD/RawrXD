# Sovereign IDE — Engineering Manual: Decompiler
## Batch 46 — AI-Assisted Decompiler

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** Complete

---

## 1. Purpose

The Decompiler subsystem transforms machine code into high-level pseudocode using CFG reconstruction, type inference, and semantic lifting.

It operates as a first-class agent within the agentic runtime, capable of:

- Instruction lifting
- CFG → HLL reconstruction
- Type inference
- Semantic reconstruction
- Variable recovery
- Control flow structuring

---

## 2. Architecture

### 2.1 Component Diagram

```
┌─────────────────────────────────────────────┐
│            Decompiler Engine                │
├─────────────────────────────────────────────┤
│  Lifter      │  Analyzer   │  Emitter       │
│  - Disasm  │  - CFG      │  - HLL         │
│  - SSA     │  - Types    │  - Format      │
│  - IR      │  - Semantics│  - Output      │
└──────────────┴─────────────┴────────────────┘
         │              │              │
         ▼              ▼              ▼
┌─────────────────────────────────────────────┐
│         Agentic Surfaces (Batch 49)         │
└─────────────────────────────────────────────┘
```

### 2.2 Key Components

| Component | Responsibility |
|-----------|---------------|
| Lifter | Disassemble and lift to intermediate representation |
| Analyzer | Build CFG, infer types, recover semantics |
| Emitter | Generate high-level pseudocode |
| Type Recovery | Infer types from usage patterns |

---

## 3. Decompilation Pipeline

### 3.1 Pipeline Stages

```
Binary Input
    ↓
Disassembly (Batch 17)
    ↓
Instruction Lifting → SSA IR
    ↓
CFG Reconstruction (Batch 11)
    ↓
Type Inference (Batch 15)
    ↓
Semantic Analysis
    ↓
HLL Generation
    ↓
Pseudocode Output
```

### 3.2 Supported Architectures

| Architecture | Status |
|--------------|--------|
| x86/x64 | Complete |
| ARM/ARM64 | Complete |
| RISC-V | Beta |
| MIPS | Planned |
| WebAssembly | Planned |

---

## 4. ABI Surfaces

### 4.1 Core API

```cpp
// Decompiler initialization
DecompilerResult Decompiler_Init();
DecompilerResult Decompiler_Shutdown();

// Decompilation
DecompilerResult Decompiler_Decompile(
    const BinaryRegion* region,
    DecompileConfig* config,
    DecompileResult* outResult
);

// Configuration
DecompilerResult Decompiler_SetTarget(
    Architecture arch,
    CallingConvention cc
);

DecompilerResult Decompiler_SetOptimization(
    OptimizationLevel level
);
```

### 4.2 Agentic Integration

```cpp
// Register as agentic capability
CapabilityInfo decompileCapability = {
    .name = "Code.Decompile",
    .description = "Binary to pseudocode decompilation",
    .version = "1.0.0",
    .batchId = 46,
    .cost = 16,
    .priority = 9
};

// Action handler
ActionResult Decompiler_ExecuteAction(const ActionRequest& request) {
    switch (request.actionType) {
        case ACTION_DECOMPILE_FUNCTION:
            return Decompiler_Decompile(/* ... */);
        case ACTION_DECOMPILE_BINARY:
            return Decompiler_Decompile(/* ... */);
    }
}
```

---

## 5. SEG Nodes

### 5.1 Decompiler SEG Nodes

| Node ID | Name | Purpose |
|---------|------|---------|
| 4600 | SEGNode_LiftInstructions | Lift to SSA IR |
| 4601 | SEGNode_ReconstructCFG_HLL | Build HLL CFG |
| 4602 | SEGNode_InferTypes | Type recovery |
| 4603 | SEGNode_ReconstructSemantics | Semantic analysis |
| 4604 | SEGNode_GeneratePseudocode | HLL output |

### 5.2 Execution Flow

```
SEGNode_LiftInstructions
    ↓
SEGNode_ReconstructCFG_HLL
    ↓
SEGNode_InferTypes
    ↓
SEGNode_ReconstructSemantics
    ↓
SEGNode_GeneratePseudocode
```

---

## 6. MoE Experts

### 6.1 Decompilation Experts

| Expert | Domain | Confidence |
|--------|--------|------------|
| Expert_HLLReconstruction | Pseudocode generation | 0.91 |
| Expert_SemanticInference | Semantic analysis | 0.89 |
| Expert_TypeRecovery | Type inference | 0.87 |
| Expert_ControlFlowStructuring | Loop/branch recovery | 0.88 |

### 6.2 Expert Routing

```cpp
MoEInput input;
input.SetDomain("code_decompilation");
input.SetFeature("architecture", "x64");
input.SetFeature("complexity", "high");

MoEOutput output = MoERouter::Route(input);
// Routes to Expert_HLLReconstruction
```

---

## 7. Output Formats

### 7.1 Pseudocode Styles

| Style | Description |
|-------|-------------|
| C-like | Standard C syntax |
| C++-like | Modern C++ with classes |
| Rust-like | Safe Rust patterns |
| Python-like | Pythonic syntax |

### 7.2 Example Output

```cpp
// Decompiled from x64 binary
int64_t process_data(int64_t* data, int64_t count) {
    int64_t sum = 0;
    for (int64_t i = 0; i < count; i++) {
        sum += data[i] * 2;
    }
    return sum;
}
```

---

## 8. IDE Integration

### 8.1 Decompiler Panel

- **Location:** Center panel (split with disassembly)
- **Features:**
  - Side-by-side disassembly/pseudocode
  - Click-to-navigate between views
  - Type annotations
  - Variable renaming
  - Comment insertion

### 8.2 Commands

```cpp
void Command_DecompileFunction(SDKHandle sdk);
void Command_DecompileSelection(SDKHandle sdk);
void Command_DecompileBinary(SDKHandle sdk);
void Command_ExportPseudocode(SDKHandle sdk);
```

---

## 9. Performance

| Metric | Target |
|--------|--------|
| Decompilation speed | 1K instructions/sec |
| Accuracy | > 85% for well-formed code |
| Memory overhead | < 5x binary size |

---

## Summary

The Decompiler provides:

- ✅ Multi-architecture decompilation
- ✅ SSA-based intermediate representation
- ✅ Type inference and recovery
- ✅ Semantic analysis
- ✅ Multiple output formats
- ✅ IDE integration
- ✅ Agentic task integration

**Status:** Complete

---

*End of Engineering Manual: Decompiler*
