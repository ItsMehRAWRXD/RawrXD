# Sovereign IDE SDK - Binary Analysis API Reference
## Batches 21-30: Binary Loading, Disassembly, Decompilation, Fuzzing

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Complete

---

## Table of Contents

1. [Binary Loading API](#binary-loading-api)
2. [Disassembly API](#disassembly-api)
3. [Decompilation API](#decompilation-api)
4. [Fuzzing API](#fuzzing-api)
5. [Data Types](#data-types)
6. [Constants](#constants)

---

## Binary Loading API

### Overview

The Binary Loading API provides support for loading and parsing executable files in various formats (PE, ELF, Mach-O).

### Functions

#### SDK_Binary_Load

Loads a binary file.

```cpp
SDKResult SDK_Binary_Load(
    SDKHandle sdk,
    const char* path,
    BinaryHandle* outBinary
);
```

**Parameters:**
- `sdk` - SDK handle
- `path` - Path to binary file
- `outBinary` - Output binary handle

**Returns:** `SDK_SUCCESS` on success

**Example:**
```cpp
BinaryHandle binary;
SDKResult result = SDK_Binary_Load(sdk, "target.exe", &binary);
if (result == SDK_SUCCESS) {
    // Binary loaded successfully
}
```

---

#### SDK_Binary_Unload

Unloads a binary file.

```cpp
SDKResult SDK_Binary_Unload(
    SDKHandle sdk,
    BinaryHandle binary
);
```

**Parameters:**
- `sdk` - SDK handle
- `binary` - Binary handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Binary_GetInfo

Gets information about a loaded binary.

```cpp
SDKResult SDK_Binary_GetInfo(
    SDKHandle sdk,
    BinaryHandle binary,
    BinaryInfo* outInfo
);
```

**Parameters:**
- `sdk` - SDK handle
- `binary` - Binary handle
- `outInfo` - Output binary information

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Binary_GetSections

Gets the sections of a binary.

```cpp
SDKResult SDK_Binary_GetSections(
    SDKHandle sdk,
    BinaryHandle binary,
    SectionInfo* sections,
    uint32_t* sectionCount
);
```

**Parameters:**
- `sdk` - SDK handle
- `binary` - Binary handle
- `sections` - Array to receive section info
- `sectionCount` - On input: array size; on output: actual count

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Binary_GetSymbols

Gets the symbols of a binary.

```cpp
SDKResult SDK_Binary_GetSymbols(
    SDKHandle sdk,
    BinaryHandle binary,
    SymbolInfo* symbols,
    uint32_t* symbolCount
);
```

**Parameters:**
- `sdk` - SDK handle
- `binary` - Binary handle
- `symbols` - Array to receive symbol info
- `symbolCount` - On input: array size; on output: actual count

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Binary_GetImports

Gets the imports of a binary.

```cpp
SDKResult SDK_Binary_GetImports(
    SDKHandle sdk,
    BinaryHandle binary,
    ImportInfo* imports,
    uint32_t* importCount
);
```

**Parameters:**
- `sdk` - SDK handle
- `binary` - Binary handle
- `imports` - Array to receive import info
- `importCount` - On input: array size; on output: actual count

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Binary_GetExports

Gets the exports of a binary.

```cpp
SDKResult SDK_Binary_GetExports(
    SDKHandle sdk,
    BinaryHandle binary,
    ExportInfo* exports,
    uint32_t* exportCount
);
```

**Parameters:**
- `sdk` - SDK handle
- `binary` - Binary handle
- `exports` - Array to receive export info
- `exportCount` - On input: array size; on output: actual count

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Binary_ReadMemory

Reads memory from a binary.

```cpp
SDKResult SDK_Binary_ReadMemory(
    SDKHandle sdk,
    BinaryHandle binary,
    uint64_t address,
    void* buffer,
    uint32_t size
);
```

**Parameters:**
- `sdk` - SDK handle
- `binary` - Binary handle
- `address` - Virtual address to read from
- `buffer` - Buffer to receive data
- `size` - Number of bytes to read

**Returns:** `SDK_SUCCESS` on success

---

## Disassembly API

### Overview

The Disassembly API provides instruction decoding and disassembly capabilities for multiple architectures.

### Functions

#### SDK_Disasm_Function

Disassembles a function.

```cpp
SDKResult SDK_Disasm_Function(
    SDKHandle sdk,
    BinaryHandle binary,
    uint64_t address,
    Disassembly* outDisassembly
);
```

**Parameters:**
- `sdk` - SDK handle
- `binary` - Binary handle
- `address` - Function address
- `outDisassembly` - Output disassembly

**Returns:** `SDK_SUCCESS` on success

**Example:**
```cpp
Disassembly disasm;
SDK_Disasm_Function(sdk, binary, 0x401000, &disasm);

for (uint32_t i = 0; i < disasm.instructionCount; i++) {
    printf("%016llX: %s\n",
           disasm.instructions[i].address,
           disasm.instructions[i].text);
}
```

---

#### SDK_Disasm_Range

Disassembles a memory range.

```cpp
SDKResult SDK_Disasm_Range(
    SDKHandle sdk,
    BinaryHandle binary,
    uint64_t start,
    uint64_t end,
    Disassembly* outDisassembly
);
```

**Parameters:**
- `sdk` - SDK handle
- `binary` - Binary handle
- `start` - Start address
- `end` - End address
- `outDisassembly` - Output disassembly

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Disasm_GetInstructionInfo

Gets detailed information about an instruction.

```cpp
SDKResult SDK_Disasm_GetInstructionInfo(
    SDKHandle sdk,
    const Instruction* instruction,
    InstructionInfo* outInfo
);
```

**Parameters:**
- `sdk` - SDK handle
- `instruction` - Instruction
- `outInfo` - Output instruction information

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Disasm_BuildCFG

Builds a control flow graph.

```cpp
SDKResult SDK_Disasm_BuildCFG(
    SDKHandle sdk,
    const Disassembly* disassembly,
    CFG* outCFG
);
```

**Parameters:**
- `sdk` - SDK handle
- `disassembly` - Disassembly
- `outCFG` - Output control flow graph

**Returns:** `SDK_SUCCESS` on success

---

## Decompilation API

### Overview

The Decompilation API transforms machine code into readable high-level pseudocode.

### Functions

#### SDK_Decomp_Function

Decompiles a function.

```cpp
SDKResult SDK_Decomp_Function(
    SDKHandle sdk,
    BinaryHandle binary,
    uint64_t address,
    char* code,
    uint32_t* codeSize
);
```

**Parameters:**
- `sdk` - SDK handle
- `binary` - Binary handle
- `address` - Function address
- `code` - Buffer to receive decompiled code
- `codeSize` - On input: buffer size; on output: actual size

**Returns:** `SDK_SUCCESS` on success

**Example:**
```cpp
char code[10000];
uint32_t size = sizeof(code);
SDK_Decomp_Function(sdk, binary, 0x401000, code, &size);
printf("Decompiled code:\n%s\n", code);
```

---

#### SDK_Decomp_GetTypeInfo

Gets type information from decompiled code.

```cpp
SDKResult SDK_Decomp_GetTypeInfo(
    SDKHandle sdk,
    BinaryHandle binary,
    TypeInfo* types,
    uint32_t* typeCount
);
```

**Parameters:**
- `sdk` - SDK handle
- `binary` - Binary handle
- `types` - Array to receive type info
- `typeCount` - On input: array size; on output: actual count

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Decomp_GetVariableInfo

Gets variable information from decompiled code.

```cpp
SDKResult SDK_Decomp_GetVariableInfo(
    SDKHandle sdk,
    BinaryHandle binary,
    uint64_t functionAddress,
    VariableInfo* variables,
    uint32_t* variableCount
);
```

**Parameters:**
- `sdk` - SDK handle
- `binary` - Binary handle
- `functionAddress` - Function address
- `variables` - Array to receive variable info
- `variableCount` - On input: array size; on output: actual count

**Returns:** `SDK_SUCCESS` on success

---

## Fuzzing API

### Overview

The Fuzzing API provides coverage-guided fuzzing capabilities for finding vulnerabilities.

### Functions

#### SDK_Fuzz_CreateTarget

Creates a fuzzing target.

```cpp
SDKResult SDK_Fuzz_CreateTarget(
    SDKHandle sdk,
    const char* binaryPath,
    const FuzzConfig* config,
    FuzzTargetHandle* outTarget
);
```

**Parameters:**
- `sdk` - SDK handle
- `binaryPath` - Path to target binary
- `config` - Fuzzing configuration
- `outTarget` - Output fuzzing target handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Fuzz_DestroyTarget

Destroys a fuzzing target.

```cpp
SDKResult SDK_Fuzz_DestroyTarget(
    SDKHandle sdk,
    FuzzTargetHandle target
);
```

**Parameters:**
- `sdk` - SDK handle
- `target` - Fuzzing target handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Fuzz_Start

Starts fuzzing.

```cpp
SDKResult SDK_Fuzz_Start(
    SDKHandle sdk,
    FuzzTargetHandle target,
    FuzzCallback callback,
    void* userData
);
```

**Parameters:**
- `sdk` - SDK handle
- `target` - Fuzzing target handle
- `callback` - Fuzzing callback
- `userData` - User data

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Fuzz_Stop

Stops fuzzing.

```cpp
SDKResult SDK_Fuzz_Stop(
    SDKHandle sdk,
    FuzzTargetHandle target
);
```

**Parameters:**
- `sdk` - SDK handle
- `target` - Fuzzing target handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Fuzz_GetStats

Gets fuzzing statistics.

```cpp
SDKResult SDK_Fuzz_GetStats(
    SDKHandle sdk,
    FuzzTargetHandle target,
    FuzzStats* outStats
);
```

**Parameters:**
- `sdk` - SDK handle
- `target` - Fuzzing target handle
- `outStats` - Output statistics

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Fuzz_GetCrashes

Gets discovered crashes.

```cpp
SDKResult SDK_Fuzz_GetCrashes(
    SDKHandle sdk,
    FuzzTargetHandle target,
    CrashInfo* crashes,
    uint32_t* crashCount
);
```

**Parameters:**
- `sdk` - SDK handle
- `target` - Fuzzing target handle
- `crashes` - Array to receive crash info
- `crashCount` - On input: array size; on output: actual count

**Returns:** `SDK_SUCCESS` on success

---

## Data Types

### BinaryInfo

```cpp
struct BinaryInfo {
    char path[256];
    BinaryFormat format;
    Architecture arch;
    uint64_t entryPoint;
    uint64_t imageBase;
    uint64_t imageSize;
    uint32_t sectionCount;
    uint32_t symbolCount;
    bool hasDebugInfo;
    bool isStripped;
};
```

### SectionInfo

```cpp
struct SectionInfo {
    char name[32];
    uint64_t virtualAddress;
    uint64_t virtualSize;
    uint64_t rawOffset;
    uint64_t rawSize;
    SectionFlags flags;
};
```

### SymbolInfo

```cpp
struct SymbolInfo {
    char name[128];
    uint64_t address;
    uint64_t size;
    SymbolType type;
    SectionIndex section;
};
```

### ImportInfo

```cpp
struct ImportInfo {
    char moduleName[128];
    char functionName[128];
    uint64_t importAddress;
    uint16_t ordinal;
    bool isOrdinal;
};
```

### ExportInfo

```cpp
struct ExportInfo {
    char name[128];
    uint64_t address;
    uint32_t ordinal;
    uint64_t forwarderAddress;
    bool isForwarder;
};
```

### Instruction

```cpp
struct Instruction {
    uint64_t address;
    uint8_t bytes[16];
    uint32_t size;
    char text[128];
    char mnemonic[16];
    char operands[64];
    InstructionCategory category;
    bool isBranch;
    bool isCall;
    bool isReturn;
    uint64_t branchTarget;
};
```

### Disassembly

```cpp
struct Disassembly {
    Instruction* instructions;
    uint32_t instructionCount;
    uint64_t startAddress;
    uint64_t endAddress;
    Architecture arch;
};
```

### CFG

```cpp
struct CFG {
    BasicBlock* blocks;
    uint32_t blockCount;
    uint32_t* edges;
    uint32_t edgeCount;
    uint32_t entryBlock;
};
```

### BasicBlock

```cpp
struct BasicBlock {
    uint64_t startAddress;
    uint64_t endAddress;
    uint32_t instructionStart;
    uint32_t instructionCount;
    uint32_t* successors;
    uint32_t successorCount;
    uint32_t* predecessors;
    uint32_t predecessorCount;
};
```

### TypeInfo

```cpp
struct TypeInfo {
    char name[128];
    TypeKind kind;
    uint32_t size;
    uint32_t alignment;
    union {
        StructType structType;
        EnumType enumType;
        PointerType pointerType;
        ArrayType arrayType;
    } data;
};
```

### VariableInfo

```cpp
struct VariableInfo {
    char name[128];
    char type[128];
    uint64_t address;
    uint32_t size;
    bool isLocal;
    bool isParameter;
    bool isGlobal;
};
```

### FuzzConfig

```cpp
struct FuzzConfig {
    uint64_t maxIterations;
    uint32_t timeout;
    uint32_t corpusSize;
    uint32_t maxInputSize;
    bool useCoverage;
    bool useSanitizer;
    char corpusPath[256];
    char crashPath[256];
};
```

### FuzzStats

```cpp
struct FuzzStats {
    uint64_t iterations;
    uint64_t crashes;
    uint64_t hangs;
    uint64_t corpusSize;
    float coverage;
    uint64_t execsPerSecond;
    uint64_t startTime;
    uint64_t elapsedTime;
};
```

### CrashInfo

```cpp
struct CrashInfo {
    uint64_t id;
    char inputFile[256];
    char stackTrace[4096];
    CrashType type;
    uint64_t address;
    uint64_t timestamp;
};
```

---

## Constants

### BinaryFormat

```cpp
enum BinaryFormat {
    FORMAT_UNKNOWN = 0,
    FORMAT_PE = 1,
    FORMAT_ELF = 2,
    FORMAT_MACHO = 3,
    FORMAT_RAW = 4
};
```

### Architecture

```cpp
enum Architecture {
    ARCH_UNKNOWN = 0,
    ARCH_X86 = 1,
    ARCH_X64 = 2,
    ARCH_ARM = 3,
    ARCH_ARM64 = 4,
    ARCH_MIPS = 5,
    ARCH_RISCV = 6
};
```

### SectionFlags

```cpp
enum SectionFlags {
    SECTION_CODE = 0x01,
    SECTION_DATA = 0x02,
    SECTION_READ = 0x04,
    SECTION_WRITE = 0x08,
    SECTION_EXECUTE = 0x10
};
```

### SymbolType

```cpp
enum SymbolType {
    SYMBOL_UNKNOWN = 0,
    SYMBOL_FUNCTION = 1,
    SYMBOL_OBJECT = 2,
    SYMBOL_SECTION = 3,
    SYMBOL_FILE = 4
};
```

### InstructionCategory

```cpp
enum InstructionCategory {
    INSN_UNKNOWN = 0,
    INSN_DATA = 1,
    INSN_CONTROL = 2,
    INSN_ARITHMETIC = 3,
    INSN_LOGICAL = 4,
    INSN_MEMORY = 5,
    INSN_SYSTEM = 6
};
```

### TypeKind

```cpp
enum TypeKind {
    TYPE_UNKNOWN = 0,
    TYPE_VOID = 1,
    TYPE_BOOL = 2,
    TYPE_INT = 3,
    TYPE_FLOAT = 4,
    TYPE_POINTER = 5,
    TYPE_ARRAY = 6,
    TYPE_STRUCT = 7,
    TYPE_UNION = 8,
    TYPE_ENUM = 9,
    TYPE_FUNCTION = 10
};
```

### CrashType

```cpp
enum CrashType {
    CRASH_UNKNOWN = 0,
    CRASH_ACCESS_VIOLATION = 1,
    CRASH_STACK_OVERFLOW = 2,
    CRASH_HEAP_CORRUPTION = 3,
    CRASH_ASSERT = 4,
    CRASH_ABORT = 5
};
```

---

## Summary

The Binary Analysis API provides:

- ✅ **Binary Loading API** - PE, ELF, Mach-O support
- ✅ **Disassembly API** - Multi-architecture disassembly
- ✅ **Decompilation API** - Machine code to pseudocode
- ✅ **Fuzzing API** - Coverage-guided fuzzing
- ✅ **Comprehensive data types** for binary analysis

**Status:** ✅ Complete

---

*End of Binary Analysis API Documentation*
