# Batch 10 - Binary Loader
## Sovereign IDE Subsystem Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The Binary Loader loads binaries into the Sovereign runtime for analysis. It supports PE, ELF, Mach-O, and firmware blob formats.

### Key Characteristics

| Attribute | Value |
|-----------|-------|
| **Language** | C++17 |
| **Lines of Code** | ~5,500 |
| **Formats** | PE, ELF, Mach-O, Raw |
| **Architectures** | x86, x64, ARM, ARM64 |
| **SEG Nodes** | 1 |
| **MoE Experts** | 1 |

---

## Responsibilities

1. **PE Loader** - Load Windows PE files
2. **ELF Loader** - Load Linux ELF files
3. **Mach-O Loader** - Load macOS Mach-O files
4. **Firmware Blob Loader** - Load raw firmware images
5. **Architecture Detection** - Detect target architecture

---

## Architecture

```
┌─────────────────────────────────────────────┐
│           Binary Loader                     │
├─────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Format     │  │   Architecture   │    │
│  │   Detectors  │  │   Analyzer       │    │
│  │   (PE, ELF,  │  │                  │    │
│  │   Mach-O)    │  │                  │    │
│  └──────────────┘  └──────────────────┘    │
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Section    │  │   Symbol         │    │
│  │   Mapper     │  │   Resolver       │    │
│  └──────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────┘
```

---

## ABI Surfaces

```cpp
// Loader initialization
SOVEREIGN_API LoaderResult Loader_Initialize();
SOVEREIGN_API void Loader_Shutdown();

// Loading
SOVEREIGN_API BinaryHandle Loader_Load(const char* path);
SOVEREIGN_API BinaryHandle Loader_LoadFromMemory(const void* data, size_t size);
SOVEREIGN_API void Loader_Unload(BinaryHandle handle);

// Information
SOVEREIGN_API const char* Loader_GetFormat(BinaryHandle handle);
SOVEREIGN_API const char* Loader_GetArchitecture(BinaryHandle handle);
SOVEREIGN_API uint64_t Loader_GetEntryPoint(BinaryHandle handle);
SOVEREIGN_API size_t Loader_GetSectionCount(BinaryHandle handle);

// Sections
SOVEREIGN_API SectionHandle Loader_GetSection(BinaryHandle handle, size_t index);
SOVEREIGN_API SectionHandle Loader_FindSection(BinaryHandle handle, const char* name);
SOVEREIGN_API const void* Loader_ReadSection(SectionHandle section);

// Symbols
SOVEREIGN_API SymbolHandle Loader_FindSymbol(BinaryHandle handle, const char* name);
SOVEREIGN_API uint64_t Loader_GetSymbolAddress(SymbolHandle symbol);
```

---

## SEG Nodes

| Node ID | Name | Type | Description |
|---------|------|------|-------------|
| 0x000D | `SEGNode_BinaryLoad` | Loading | Load binary for analysis |

---

## MoE Experts

| Expert Name | Domain | Description |
|-------------|--------|-------------|
| `Expert_BinaryAnalysis` | binary | Analyze binary structure |

---

## Implementation Details

### Binary Base Class

```cpp
class Binary {
public:
    virtual ~Binary() = default;
    
    // Information
    virtual const char* GetFormat() const = 0;
    virtual const char* GetArchitecture() const = 0;
    virtual uint64_t GetEntryPoint() const = 0;
    
    // Sections
    virtual size_t GetSectionCount() const = 0;
    virtual Section* GetSection(size_t index) = 0;
    virtual Section* FindSection(const std::string& name) = 0;
    
    // Symbols
    virtual Symbol* FindSymbol(const std::string& name) = 0;
    
    // Raw access
    virtual const uint8_t* GetData() const = 0;
    virtual size_t GetSize() const = 0;
};
```

### PE Loader

```cpp
class PEBinary : public Binary {
public:
    bool Load(const std::string& path) {
        m_file = std::ifstream(path, std::ios::binary);
        if (!m_file) {
            return false;
        }
        
        // Read DOS header
        m_file.read(reinterpret_cast<char*>(&m_dosHeader), sizeof(m_dosHeader));
        
        // Verify magic
        if (m_dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }
        
        // Read NT headers
        m_file.seekg(m_dosHeader.e_lfanew);
        m_file.read(reinterpret_cast<char*>(&m_ntHeaders), sizeof(m_ntHeaders));
        
        // Verify PE signature
        if (m_ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }
        
        // Read sections
        auto numSections = m_ntHeaders.FileHeader.NumberOfSections;
        m_sections.resize(numSections);
        m_file.read(reinterpret_cast<char*>(m_sections.data()),
                    numSections * sizeof(IMAGE_SECTION_HEADER));
        
        return true;
    }
    
    const char* GetFormat() const override { return "PE"; }
    
    const char* GetArchitecture() const override {
        switch (m_ntHeaders.FileHeader.Machine) {
            case IMAGE_FILE_MACHINE_I386: return "x86";
            case IMAGE_FILE_MACHINE_AMD64: return "x64";
            case IMAGE_FILE_MACHINE_ARM: return "ARM";
            case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
            default: return "unknown";
        }
    }
    
    uint64_t GetEntryPoint() const override {
        return m_ntHeaders.OptionalHeader.AddressOfEntryPoint +
               m_ntHeaders.OptionalHeader.ImageBase;
    }
    
private:
    IMAGE_DOS_HEADER m_dosHeader;
    IMAGE_NT_HEADERS m_ntHeaders;
    std::vector<IMAGE_SECTION_HEADER> m_sections;
    std::ifstream m_file;
};
```

### Format Detection

```cpp
class FormatDetector {
public:
    static std::unique_ptr<Binary> Detect(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            return nullptr;
        }
        
        // Read magic bytes
        uint16_t magic;
        file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        
        // Check signatures
        if (magic == IMAGE_DOS_SIGNATURE) {
            return std::make_unique<PEBinary>();
        }
        
        // Check ELF
        file.seekg(0);
        char elfMagic[4];
        file.read(elfMagic, 4);
        if (elfMagic[0] == 0x7f && elfMagic[1] == 'E' &&
            elfMagic[2] == 'L' && elfMagic[3] == 'F') {
            return std::make_unique<ELFBinary>();
        }
        
        // Check Mach-O
        file.seekg(0);
        uint32_t machoMagic;
        file.read(reinterpret_cast<char*>(&machoMagic), sizeof(machoMagic));
        if (machoMagic == MH_MAGIC || machoMagic == MH_MAGIC_64 ||
            machoMagic == MH_CIGAM || machoMagic == MH_CIGAM_64) {
            return std::make_unique<MachOBinary>();
        }
        
        // Unknown - treat as raw binary
        return std::make_unique<RawBinary>();
    }
};
```

---

## Testing

```cpp
TEST(BinaryLoader, LoadPE) {
    Loader_Initialize();
    
    // Load test PE
    auto handle = Loader_Load("test.exe");
    EXPECT_NE(handle, nullptr);
    
    // Verify format
    EXPECT_STREQ(Loader_GetFormat(handle), "PE");
    
    // Verify architecture
    EXPECT_STREQ(Loader_GetArchitecture(handle), "x64");
    
    // Get sections
    auto sectionCount = Loader_GetSectionCount(handle);
    EXPECT_GT(sectionCount, 0);
    
    // Find .text section
    auto textSection = Loader_FindSection(handle, ".text");
    EXPECT_NE(textSection, nullptr);
    
    Loader_Unload(handle);
    Loader_Shutdown();
}

TEST(BinaryLoader, LoadELF) {
    Loader_Initialize();
    
    auto handle = Loader_Load("test.elf");
    EXPECT_NE(handle, nullptr);
    EXPECT_STREQ(Loader_GetFormat(handle), "ELF");
    
    Loader_Unload(handle);
    Loader_Shutdown();
}
```

---

## Summary

Batch 10 - Binary Loader provides:

- ✅ **Multi-format support** (PE, ELF, Mach-O, Raw)
- ✅ **Multi-architecture** (x86, x64, ARM, ARM64)
- ✅ **Section mapping**
- ✅ **Symbol resolution**
- ✅ **Format auto-detection**

**Status:** ✅ Complete
