# Sovereign IDE — API Reference: Binary Analysis SDK
## Complete API Documentation for Binary Analysis Functions

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** Complete

---

## 1. Overview

The Binary Analysis SDK provides APIs for loading, analyzing, disassembling, and manipulating binary files. It supports multiple architectures and enables reverse engineering, vulnerability analysis, and binary transformation workflows.

### 1.1 API Categories

| Category | Description | Header |
|----------|-------------|--------|
| Binary Loading | Load PE, ELF, Mach-O files | `sdk/binary/loader.h` |
| Disassembly | Convert machine code to assembly | `sdk/binary/disasm.h` |
| CFG Analysis | Control flow graph reconstruction | `sdk/binary/cfg.h` |
| Symbol Analysis | Import/export analysis | `sdk/binary/symbols.h` |
| Pattern Matching | Signature-based detection | `sdk/binary/patterns.h` |

---

## 2. Binary Loading API

### 2.1 Loader Operations

```cpp
// sdk/binary/loader.h

/**
 * Binary formats
 */
typedef enum {
    FORMAT_AUTO = 0,
    FORMAT_PE = 1,
    FORMAT_ELF = 2,
    FORMAT_MACHO = 3,
    FORMAT_RAW = 4
} BinaryFormat;

/**
 * Architecture types
 */
typedef enum {
    ARCH_X86 = 0,
    ARCH_X64 = 1,
    ARCH_ARM = 2,
    ARCH_ARM64 = 3,
    ARCH_RISCV = 4,
    ARCH_MIPS = 5
} Architecture;

/**
 * Load binary file
 * @param sdk SDK handle
 * @param filePath Path to binary
 * @param format Binary format (or FORMAT_AUTO)
 * @param outBinary Output binary handle
 * @return SDKResult
 */
SDKResult SDK_Binary_Load(
    SDKHandle sdk,
    const char* filePath,
    BinaryFormat format,
    BinaryHandle* outBinary
);

/**
 * Load binary from memory
 * @param sdk SDK handle
 * @param data Binary data
 * @param size Data size
 * @param format Binary format
 * @param outBinary Output binary handle
 * @return SDKResult
 */
SDKResult SDK_Binary_LoadFromMemory(
    SDKHandle sdk,
    const uint8_t* data,
    uint32_t size,
    BinaryFormat format,
    BinaryHandle* outBinary
);

/**
 * Close binary
 * @param sdk SDK handle
 * @param binary Binary handle
 * @return SDKResult
 */
SDKResult SDK_Binary_Close(
    SDKHandle sdk,
    BinaryHandle binary
);

/**
 * Get binary information
 * @param sdk SDK handle
 * @param binary Binary handle
 * @param outInfo Output info
 * @return SDKResult
 */
SDKResult SDK_Binary_GetInfo(
    SDKHandle sdk,
    BinaryHandle binary,
    BinaryInfo* outInfo
);
```

### 2.2 Binary Information

```cpp
/**
 * Binary information
 */
typedef struct {
    char filePath[512];
    BinaryFormat format;
    Architecture architecture;
    uint64_t entryPoint;
    uint64_t imageBase;
    uint32_t sectionCount;
    bool is64Bit;
    bool isPacked;
    bool isStripped;
} BinaryInfo;

/**
 * Section information
 */
typedef struct {
    char name[64];
    uint64_t virtualAddress;
    uint64_t virtualSize;
    uint64_t rawAddress;
    uint64_t rawSize;
    uint32_t characteristics;
} SectionInfo;

/**
 * Get section information
 * @param sdk SDK handle
 * @param binary Binary handle
 * @param index Section index
 * @param outSection Output section info
 * @return SDKResult
 */
SDKResult SDK_Binary_GetSection(
    SDKHandle sdk,
    BinaryHandle binary,
    uint32_t index,
    SectionInfo* outSection
);

/**
 * Read section data
 * @param sdk SDK handle
 * @param binary Binary handle
 * @param sectionIndex Section index
 * @param outData Output data buffer
 * @param dataSize Buffer size
 * @param outRead Output bytes read
 * @return SDKResult
 */
SDKResult SDK_Binary_ReadSection(
    SDKHandle sdk,
    BinaryHandle binary,
    uint32_t sectionIndex,
    uint8_t* outData,
    uint32_t dataSize,
    uint32_t* outRead
);
```

---

## 3. Disassembly API

### 3.1 Disassembler Operations

```cpp
// sdk/binary/disasm.h

/**
 * Disassembler configuration
 */
typedef struct {
    Architecture architecture;
    uint64_t baseAddress;
    bool showBytes;
    bool showComments;
    SyntaxStyle syntax;
} DisasmConfig;

/**
 * Syntax styles
 */
typedef enum {
    SYNTAX_INTEL = 0,
    SYNTAX_ATT = 1,
    SYNTAX_MASM = 2
} SyntaxStyle;

/**
 * Instruction information
 */
typedef struct {
    uint64_t address;
    uint8_t bytes[16];
    uint32_t byteCount;
    char mnemonic[32];
    char operands[128];
    char comment[256];
    uint32_t size;
    bool isBranch;
    bool isCall;
    bool isReturn;
} InstructionInfo;

/**
 * Initialize disassembler
 * @param sdk SDK handle
 * @param config Disassembler configuration
 * @param outDisasm Output disassembler handle
 * @return SDKResult
 */
SDKResult SDK_Disasm_Init(
    SDKHandle sdk,
    const DisasmConfig* config,
    DisasmHandle* outDisasm
);

/**
 * Disassemble single instruction
 * @param sdk SDK handle
 * @param disasm Disassembler handle
 * @param code Code bytes
 * @param codeSize Code size
 * @param outInstruction Output instruction
 * @return SDKResult
 */
SDKResult SDK_Disasm_Disassemble(
    SDKHandle sdk,
    DisasmHandle disasm,
    const uint8_t* code,
    uint32_t codeSize,
    InstructionInfo* outInstruction
);

/**
 * Disassemble range
 * @param sdk SDK handle
 * @param disasm Disassembler handle
 * @param binary Binary handle
 * @param startAddress Start address
 * @param endAddress End address
 * @param outInstructions Output instruction array
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_Disasm_DisassembleRange(
    SDKHandle sdk,
    DisasmHandle disasm,
    BinaryHandle binary,
    uint64_t startAddress,
    uint64_t endAddress,
    InstructionInfo** outInstructions,
    uint32_t* outCount
);

/**
 * Close disassembler
 * @param sdk SDK handle
 * @param disasm Disassembler handle
 * @return SDKResult
 */
SDKResult SDK_Disasm_Close(
    SDKHandle sdk,
    DisasmHandle disasm
);
```

---

## 4. CFG Analysis API

### 4.1 Control Flow Graph

```cpp
// sdk/binary/cfg.h

/**
 * Basic block
 */
typedef struct {
    uint64_t startAddress;
    uint64_t endAddress;
    uint32_t instructionCount;
    uint64_t* successors;
    uint32_t successorCount;
    uint64_t* predecessors;
    uint32_t predecessorCount;
} BasicBlock;

/**
 * Control flow graph
 */
typedef struct {
    uint64_t entryPoint;
    BasicBlock* blocks;
    uint32_t blockCount;
    uint32_t edgeCount;
} ControlFlowGraph;

/**
 * Build CFG for function
 * @param sdk SDK handle
 * @param binary Binary handle
 * @param functionAddress Function start address
 * @param outCFG Output CFG
 * @return SDKResult
 */
SDKResult SDK_CFG_Build(
    SDKHandle sdk,
    BinaryHandle binary,
    uint64_t functionAddress,
    ControlFlowGraph* outCFG
);

/**
 * Build CFG for entire binary
 * @param sdk SDK handle
 * @param binary Binary handle
 * @param outCFG Output CFG
 * @return SDKResult
 */
SDKResult SDK_CFG_BuildFull(
    SDKHandle sdk,
    BinaryHandle binary,
    ControlFlowGraph* outCFG
);

/**
 * Free CFG
 * @param sdk SDK handle
 * @param cfg CFG to free
 * @return SDKResult
 */
SDKResult SDK_CFG_Free(
    SDKHandle sdk,
    ControlFlowGraph* cfg
);

/**
 * Find path between blocks
 * @param sdk SDK handle
 * @param cfg CFG handle
 * @param startBlock Start block address
 * @param endBlock End block address
 * @param outPath Output path array
 * @param outPathLength Output path length
 * @return SDKResult
 */
SDKResult SDK_CFG_FindPath(
    SDKHandle sdk,
    const ControlFlowGraph* cfg,
    uint64_t startBlock,
    uint64_t endBlock,
    uint64_t** outPath,
    uint32_t* outPathLength
);
```

---

## 5. Symbol Analysis API

### 5.1 Import/Export Analysis

```cpp
// sdk/binary/symbols.h

/**
 * Symbol information
 */
typedef struct {
    char name[256];
    uint64_t address;
    uint32_t type;  // IMPORT, EXPORT, LOCAL
    char moduleName[128];
    uint32_t ordinal;
} SymbolInfo;

/**
 * Import information
 */
typedef struct {
    char moduleName[128];
    char functionName[256];
    uint64_t importAddress;
    uint32_t ordinal;
} ImportInfo;

/**
 * Export information
 */
typedef struct {
    char functionName[256];
    uint64_t exportAddress;
    uint32_t ordinal;
    uint32_t hint;
} ExportInfo;

/**
 * Get imports
 * @param sdk SDK handle
 * @param binary Binary handle
 * @param outImports Output import array
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_Symbols_GetImports(
    SDKHandle sdk,
    BinaryHandle binary,
    ImportInfo** outImports,
    uint32_t* outCount
);

/**
 * Get exports
 * @param sdk SDK handle
 * @param binary Binary handle
 * @param outExports Output export array
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_Symbols_GetExports(
    SDKHandle sdk,
    BinaryHandle binary,
    ExportInfo** outExports,
    uint32_t* outCount
);

/**
 * Get symbols
 * @param sdk SDK handle
 * @param binary Binary handle
 * @param outSymbols Output symbol array
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_Symbols_GetSymbols(
    SDKHandle sdk,
    BinaryHandle binary,
    SymbolInfo** outSymbols,
    uint32_t* outCount
);

/**
 * Resolve symbol address
 * @param sdk SDK handle
 * @param binary Binary handle
 * @param symbolName Symbol name
 * @param outAddress Output address
 * @return SDKResult
 */
SDKResult SDK_Symbols_Resolve(
    SDKHandle sdk,
    BinaryHandle binary,
    const char* symbolName,
    uint64_t* outAddress
);
```

---

## 6. Pattern Matching API

### 6.1 Signature Detection

```cpp
// sdk/binary/patterns.h

/**
 * Pattern match result
 */
typedef struct {
    uint64_t address;
    char patternName[128];
    uint32_t confidence;
    char description[256];
} PatternMatch;

/**
 * Define pattern
 * @param sdk SDK handle
 * @param name Pattern name
 * @param pattern Byte pattern (with wildcards)
 * @param mask Pattern mask (FF = match, 00 = wildcard)
 * @param outPatternId Output pattern ID
 * @return SDKResult
 */
SDKResult SDK_Pattern_Define(
    SDKHandle sdk,
    const char* name,
    const uint8_t* pattern,
    const uint8_t* mask,
    uint32_t patternSize,
    char* outPatternId
);

/**
 * Scan binary for patterns
 * @param sdk SDK handle
 * @param binary Binary handle
 * @param patternId Pattern ID
 * @param outMatches Output match array
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_Pattern_Scan(
    SDKHandle sdk,
    BinaryHandle binary,
    const char* patternId,
    PatternMatch** outMatches,
    uint32_t* outCount
);

/**
 * Scan all patterns
 * @param sdk SDK handle
 * @param binary Binary handle
 * @param outMatches Output match array
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_Pattern_ScanAll(
    SDKHandle sdk,
    BinaryHandle binary,
    PatternMatch** outMatches,
    uint32_t* outCount
);

/**
 * YARA rule support
 * @param sdk SDK handle
 * @param binary Binary handle
 * @param yaraRule YARA rule string
 * @param outMatches Output match array
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_Pattern_ScanYARA(
    SDKHandle sdk,
    BinaryHandle binary,
    const char* yaraRule,
    PatternMatch** outMatches,
    uint32_t* outCount
);
```

---

## 7. Usage Examples

### 7.1 Loading and Analyzing a Binary

```cpp
#include <sdk/core/init.h>
#include <sdk/binary/loader.h>
#include <sdk/binary/disasm.h>
#include <sdk/binary/cfg.h>
#include <sdk/binary/symbols.h>

void analyzeBinary(SDKHandle sdk, const char* filePath) {
    // Load binary
    BinaryHandle binary;
    SDK_Binary_Load(sdk, filePath, FORMAT_AUTO, &binary);
    
    // Get info
    BinaryInfo info;
    SDK_Binary_GetInfo(sdk, binary, &info);
    
    printf("Binary: %s\n", info.filePath);
    printf("Format: %s\n", 
           info.format == FORMAT_PE ? "PE" :
           info.format == FORMAT_ELF ? "ELF" : "Mach-O");
    printf("Architecture: %s\n",
           info.architecture == ARCH_X64 ? "x64" :
           info.architecture == ARCH_X86 ? "x86" : "Other");
    printf("Entry Point: 0x%llx\n", info.entryPoint);
    printf("Sections: %d\n", info.sectionCount);
    
    // Get imports
    ImportInfo* imports;
    uint32_t importCount;
    SDK_Symbols_GetImports(sdk, binary, &imports, &importCount);
    
    printf("\nImports (%d):\n", importCount);
    for (uint32_t i = 0; i < importCount && i < 10; i++) {
        printf("  %s!%s @ 0x%llx\n",
               imports[i].moduleName,
               imports[i].functionName,
               imports[i].importAddress);
    }
    
    // Disassemble entry point
    DisasmConfig disasmConfig = {
        .architecture = info.architecture,
        .baseAddress = info.imageBase,
        .showBytes = true,
        .showComments = true,
        .syntax = SYNTAX_INTEL
    };
    
    DisasmHandle disasm;
    SDK_Disasm_Init(sdk, &disasmConfig, &disasm);
    
    InstructionInfo* instructions;
    uint32_t instructionCount;
    SDK_Disasm_DisassembleRange(sdk, disasm, binary,
                                 info.entryPoint,
                                 info.entryPoint + 100,
                                 &instructions, &instructionCount);
    
    printf("\nEntry Point Disassembly:\n");
    for (uint32_t i = 0; i < instructionCount && i < 20; i++) {
        printf("  0x%llx: %s %s\n",
               instructions[i].address,
               instructions[i].mnemonic,
               instructions[i].operands);
    }
    
    // Cleanup
    SDK_Disasm_Close(sdk, disasm);
    SDK_Binary_Close(sdk, binary);
}
```

### 7.2 Pattern Scanning

```cpp
void scanForPatterns(SDKHandle sdk, BinaryHandle binary) {
    // Define pattern for function prologue
    uint8_t pattern[] = {0x55, 0x48, 0x89, 0xE5};  // push rbp; mov rbp, rsp
    uint8_t mask[] = {0xFF, 0xFF, 0xFF, 0xFF};
    
    char patternId[64];
    SDK_Pattern_Define(sdk, "FunctionPrologue", pattern, mask, 4, patternId);
    
    // Scan
    PatternMatch* matches;
    uint32_t matchCount;
    SDK_Pattern_Scan(sdk, binary, patternId, &matches, &matchCount);
    
    printf("Found %d function prologues\n", matchCount);
    for (uint32_t i = 0; i < matchCount && i < 10; i++) {
        printf("  0x%llx: %s\n",
               matches[i].address,
               matches[i].description);
    }
}
```

---

## Summary

The Binary Analysis SDK API provides:

- ✅ Multi-format binary loading (PE, ELF, Mach-O)
- ✅ Multi-architecture disassembly
- ✅ Control flow graph construction
- ✅ Import/export analysis
- ✅ Pattern matching and signature detection
- ✅ YARA rule support

**Status:** Complete

---

*End of API Reference: Binary Analysis SDK*
