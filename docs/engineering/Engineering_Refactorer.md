# Sovereign IDE — Engineering Manual: Refactorer
## Batch 47 — Autonomous Codebase Refactorer

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** Complete

---

## 1. Purpose

The Refactorer subsystem provides autonomous code refactoring, structural optimization, and architectural evolution capabilities for the Sovereign IDE.

It operates as a first-class agent within the agentic runtime, capable of:

- Code structure analysis
- Function splitting/merging
- Loop normalization
- Architectural pattern enforcement
- Multi-file refactoring
- Language-aware transformations

---

## 2. Architecture

### 2.1 Component Diagram

```
┌─────────────────────────────────────────────┐
│           Refactorer Engine                 │
├─────────────────────────────────────────────┤
│  Analyzer    │  Planner    │  Executor      │
│  - Parse     │  - Strategy │  - Transform   │
│  - Pattern   │  - Schedule │  - Apply       │
│  - Metrics   │  - Validate │  - Verify      │
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
| Analyzer | Parse code, identify patterns, calculate metrics |
| Planner | Determine refactoring strategy, schedule operations |
| Executor | Apply transformations, verify correctness |
| Validator | Ensure semantic preservation, test equivalence |

---

## 3. Refactoring Capabilities

### 3.1 Supported Transformations

| Transformation | Description | Languages |
|----------------|-------------|-----------|
| Extract Method | Move code block to new function | C, C++, Rust, Python, JS |
| Inline Method | Replace call with body | C, C++, Rust, Python, JS |
| Rename Symbol | Safe identifier renaming | All |
| Move Class/File | Relocate types across modules | C++, Rust, Python |
| Loop Normalize | Convert to canonical forms | C, C++, Rust |
| Modernize C++ | C++98 → C++20 transformations | C++ |
| Modernize Python | Py2 → Py3, type hints | Python |
| Pattern Enforcement | Apply architectural rules | All |

### 3.2 Multi-File Refactoring

The Refactorer supports cross-file transformations:

```cpp
// Before: Function in main.cpp
void process() {
    // 100 lines of logic
}

// After: Extracted to processor.cpp
// main.cpp
void process() {
    Processor::execute();  // 1 line
}

// processor.cpp
namespace Processor {
    void execute() {
        // 100 lines moved here
    }
}
```

---

## 4. ABI Surfaces

### 4.1 Core API

```cpp
// Refactorer initialization
RefactorerResult Refactorer_Init();
RefactorerResult Refactorer_Shutdown();

// Analysis
RefactorerResult Refactorer_Analyze(
    const char* filePath,
    AnalysisResult* outResult
);

// Refactoring operations
RefactorerResult Refactorer_ExtractMethod(
    const char* filePath,
    uint32_t startLine,
    uint32_t endLine,
    const char* newMethodName,
    RefactoringResult* outResult
);

RefactorerResult Refactorer_RenameSymbol(
    const char* filePath,
    uint32_t line,
    uint32_t column,
    const char* newName,
    RefactoringResult* outResult
);

RefactorerResult Refactorer_Modernize(
    const char* filePath,
    ModernizeTarget target,  // CPP_11, CPP_14, CPP_17, CPP_20
    RefactoringResult* outResult
);
```

### 4.2 Agentic Integration

```cpp
// Register as agentic capability
CapabilityInfo refactorCapability = {
    .name = "Code.Refactor",
    .description = "Autonomous code refactoring",
    .version = "1.0.0",
    .batchId = 47,
    .cost = 12,
    .priority = 8
};

// Action handler
ActionResult Refactorer_ExecuteAction(const ActionRequest& request) {
    switch (request.actionType) {
        case ACTION_EXTRACT_METHOD:
            return Refactorer_ExtractMethod(/* ... */);
        case ACTION_RENAME_SYMBOL:
            return Refactorer_RenameSymbol(/* ... */);
        case ACTION_MODERNIZE:
            return Refactorer_Modernize(/* ... */);
    }
}
```

---

## 5. SEG Nodes

### 5.1 Refactorer SEG Nodes

| Node ID | Name | Purpose |
|---------|------|---------|
| 4700 | SEGNode_AnalyzeCodeStructure | Analyze codebase structure |
| 4701 | SEGNode_GenerateRefactorPlan | Create refactoring strategy |
| 4702 | SEGNode_ExecuteRefactor | Apply transformations |
| 4703 | SEGNode_ValidateRefactor | Verify correctness |
| 4704 | SEGNode_MultiFileRefactor | Cross-file operations |

### 5.2 Execution Flow

```
SEGNode_AnalyzeCodeStructure
    ↓
SEGNode_GenerateRefactorPlan
    ↓
SEGNode_ExecuteRefactor
    ↓
SEGNode_ValidateRefactor
```

---

## 6. MoE Experts

### 6.1 Refactoring Experts

| Expert | Domain | Confidence |
|--------|--------|------------|
| Expert_RefactorHeuristics | Pattern detection | 0.92 |
| Expert_CodeOptimization | Performance tuning | 0.88 |
| Expert_ArchitectureEnforcement | Pattern compliance | 0.90 |
| Expert_MultiFileRefactor | Cross-file analysis | 0.85 |

### 6.2 Expert Routing

```cpp
MoEInput input;
input.SetDomain("code_refactoring");
input.SetFeature("language", "cpp");
input.SetFeature("complexity", "high");
input.SetFeature("multi_file", true);

MoEOutput output = MoERouter::Route(input);
// Routes to Expert_MultiFileRefactor
```

---

## 7. IDE Integration

### 7.1 Refactorer Panel

- **Location:** Right sidebar
- **Features:**
  - Code structure visualization
  - Refactoring suggestions list
  - Transformation preview
  - Multi-file change preview
  - Undo/redo stack

### 7.2 Editor Integration

- Context menu: "Refactor → Extract Method"
- Context menu: "Refactor → Rename Symbol"
- Context menu: "Refactor → Modernize"
- Keyboard shortcut: Ctrl+Shift+R (refactor menu)
- Inline hints for refactoring opportunities

### 7.3 Commands

```cpp
void Command_RefactorExtractMethod(SDKHandle sdk);
void Command_RefactorRenameSymbol(SDKHandle sdk);
void Command_RefactorModernize(SDKHandle sdk);
void Command_RefactorMultiFile(SDKHandle sdk);
```

---

## 8. Testing & Validation

### 8.1 Semantic Preservation

The Refactorer guarantees semantic equivalence:

- AST comparison before/after
- Symbol resolution verification
- Type checking validation
- Control flow preservation
- Side-effect analysis

### 8.2 Test Generation

```cpp
// Generate tests to verify refactoring
TestSuite Refactorer_GenerateValidationTests(
    const char* originalCode,
    const char* refactoredCode
);
```

---

## 9. Performance

| Metric | Target |
|--------|--------|
| Analysis speed | 10K LOC/sec |
| Refactoring latency | < 100ms |
| Multi-file scope | < 1 sec |
| Memory overhead | < 2x source size |

---

## 10. Dependencies

- **Batch 11-20:** AI backend for pattern recognition
- **Batch 46:** Decompiler for semantic analysis
- **Batch 49:** Agentic surfaces for task orchestration
- **Batch 48:** Runtime optimizer for performance guidance

---

## Summary

The Refactorer provides:

- ✅ Autonomous code refactoring
- ✅ Multi-file transformations
- ✅ Language-aware modernization
- ✅ Architectural pattern enforcement
- ✅ Semantic preservation guarantees
- ✅ IDE integration
- ✅ Agentic task integration

**Status:** Complete

---

*End of Engineering Manual: Refactorer*
