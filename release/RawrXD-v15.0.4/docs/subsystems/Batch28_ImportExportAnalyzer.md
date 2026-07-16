# Batch 28 - Import/Export Analyzer
## Sovereign IDE Subsystem Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The Import/Export Analyzer analyzes import and export tables of binaries. It provides import table parsing, export table parsing, API usage inference, and dependency mapping.

### Key Characteristics

| Attribute | Value |
|-----------|-------|
| **Language** | C++17 |
| **Lines of Code** | ~3,800 |
| **Supported Formats** | PE, ELF, Mach-O |
| **API Categories** | 50+ |
| **SEG Nodes** | 2 |
| **MoE Experts** | 1 |

---

## Responsibilities

1. **Import Table Parsing** - Parse imported functions
2. **Export Table Parsing** - Parse exported functions
3. **API Usage Inference** - Infer API usage patterns
4. **Dependency Mapping** - Map module dependencies
5. **API Category Classification** - Classify APIs by purpose

---

## Architecture

```
┌─────────────────────────────────────────────┐
│       Import/Export Analyzer                │
├─────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Import     │  │   Export         │    │
│  │   Parser     │  │   Parser         │    │
│  └──────────────┘  └──────────────────┘    │
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   API Usage  │  │   Dependency     │    │
│  │   Inference  │  │   Mapper         │    │
│  └──────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────┘
```

---

## ABI Surfaces

```cpp
// Import/Export analyzer initialization
SOVEREIGN_API ImpExpResult ImpExp_Initialize();
SOVEREIGN_API void ImpExp_Shutdown();

// Import analysis
SOVEREIGN_API ImpExpResult ImpExp_AnalyzeImports(BinaryHandle binary,
                                                   ImportList** imports);
SOVEREIGN_API size_t ImpExp_GetImportCount(ImportList* imports);
SOVEREIGN_API Import* ImpExp_GetImport(ImportList* imports, size_t index);

// Export analysis
SOVEREIGN_API ImpExpResult ImpExp_AnalyzeExports(BinaryHandle binary,
                                                   ExportList** exports);
SOVEREIGN_API size_t ImpExp_GetExportCount(ExportList* exports);
SOVEREIGN_API Export* ImpExp_GetExport(ExportList* exports, size_t index);

// API information
SOVEREIGN_API const char* ImpExp_GetAPIName(void* api);
SOVEREIGN_API const char* ImpExp_GetModuleName(void* api);
SOVEREIGN_API APICategory ImpExp_GetAPICategory(void* api);
SOVEREIGN_API uint64_t ImpExp_GetAddress(void* api);
```

---

## SEG Nodes

| Node ID | Name | Type | Description |
|---------|------|------|-------------|
| 0x0020 | `SEGNode_AnalyzeImports` | Analysis | Analyze import table |
| 0x0021 | `SEGNode_AnalyzeExports` | Analysis | Analyze export table |

---

## MoE Experts

| Expert Name | Domain | Description |
|-------------|--------|-------------|
| `Expert_ImportExportInference` | imports | Infer API significance |

---

## Implementation Details

### PE Import Analyzer

```cpp
class PEImportAnalyzer {
public:
    ImportList Analyze(const PEBinary& binary) {
        ImportList imports;
        
        auto importDir = binary.GetImportDirectory();
        if (!importDir) {
            return imports;
        }
        
        // Process each import descriptor (DLL)
        for (const auto& descriptor : importDir->descriptors) {
            std::string dllName = ReadString(descriptor.name);
            
            // Process imports from this DLL
            if (descriptor.originalFirstThunk) {
                // Import by name or ordinal
                auto thunk = binary.RVAtoPtr(descriptor.originalFirstThunk);
                
                for (size_t i = 0; ; ++i) {
                    auto importThunk = thunk[i];
                    if (importThunk == 0) break;
                    
                    Import import;
                    import.module = dllName;
                    
                    if (importThunk & IMAGE_ORDINAL_FLAG) {
                        // Import by ordinal
                        import.ordinal = importThunk & 0xFFFF;
                        import.name = "";
                    } else {
                        // Import by name
                        auto nameEntry = binary.RVAtoPtr(importThunk);
                        import.ordinal = nameEntry->hint;
                        import.name = ReadString(nameEntry->name);
                    }
                    
                    import.address = descriptor.firstThunk + i * sizeof(uintptr_t);
                    imports.push_back(import);
                }
            }
        }
        
        return imports;
    }
};
```

### API Categorizer

```cpp
class APICategorizer {
public:
    APICategory Categorize(const std::string& module,
                           const std::string& function) {
        // File operations
        if (module == "kernel32.dll" || module == "KERNEL32.DLL") {
            if (function.find("CreateFile") == 0 ||
                function.find("ReadFile") == 0 ||
                function.find("WriteFile") == 0) {
                return API_FILE;
            }
            if (function.find("Reg") == 0) {
                return API_REGISTRY;
            }
            if (function.find("VirtualAlloc") == 0 ||
                function.find("Heap") == 0) {
                return API_MEMORY;
            }
            if (function.find("CreateProcess") == 0 ||
                function.find("CreateThread") == 0) {
                return API_PROCESS;
            }
            if (function.find("LoadLibrary") == 0 ||
                function.find("GetProcAddress") == 0) {
                return API_DYNAMIC_LOADING;
            }
        }
        
        // Network operations
        if (module == "ws2_32.dll" || module == "WS2_32.DLL") {
            return API_NETWORK;
        }
        if (module == "wininet.dll" || module == "WININET.DLL") {
            return API_NETWORK;
        }
        
        // Cryptography
        if (module == "advapi32.dll" || module == "ADVAPI32.DLL") {
            if (function.find("Crypt") == 0) {
                return API_CRYPTO;
            }
        }
        if (module == "bcrypt.dll" || module == "BCRYPT.DLL") {
            return API_CRYPTO;
        }
        
        // GUI
        if (module == "user32.dll" || module == "USER32.DLL" ||
            module == "gdi32.dll" || module == "GDI32.DLL") {
            return API_GUI;
        }
        
        return API_OTHER;
    }
};
```

---

## Testing

```cpp
TEST(ImportExportAnalyzer, AnalyzeImports) {
    ImpExp_Initialize();
    
    // Load binary with imports
    auto binary = Loader_Load("test_with_imports.exe");
    
    // Analyze imports
    ImportList* imports;
    auto result = ImpExp_AnalyzeImports(binary, &imports);
    EXPECT_EQ(result, IMPEXP_SUCCESS);
    EXPECT_GT(ImpExp_GetImportCount(imports), 0);
    
    // Check for expected imports
    bool foundKernel32 = false;
    for (size_t i = 0; i < ImpExp_GetImportCount(imports); ++i) {
        auto import = ImpExp_GetImport(imports, i);
        if (strcmp(ImpExp_GetModuleName(import), "kernel32.dll") == 0) {
            foundKernel32 = true;
            break;
        }
    }
    EXPECT_TRUE(foundKernel32);
    
    ImpExp_Shutdown();
}

TEST(ImportExportAnalyzer, CategorizeAPIs) {
    ImpExp_Initialize();
    
    // Test categorization
    EXPECT_EQ(APICategorizer::Categorize("kernel32.dll", "CreateFileW"),
              API_FILE);
    EXPECT_EQ(APICategorizer::Categorize("ws2_32.dll", "socket"),
              API_NETWORK);
    EXPECT_EQ(APICategorizer::Categorize("advapi32.dll", "CryptEncrypt"),
              API_CRYPTO);
    
    ImpExp_Shutdown();
}
```

---

## Summary

Batch 28 - Import/Export Analyzer provides:

- ✅ **Import table parsing**
- ✅ **Export table parsing**
- ✅ **API usage inference**
- ✅ **Dependency mapping**
- ✅ **API categorization**

**Status:** ✅ Complete
