# RawrXD Universal Runtime Architecture
## Extension is Dead. Long Live the Byte Stream.

---

## Core Philosophy

The runtime **never knows or cares about file extensions**.

```
             Anything
                 │
      ┌──────────┼──────────┐
      │          │          │
    GGUF      Safetensors   ONNX
      │          │          │
      ├──────────┼──────────┤
      │ Tensor Import Layer │
      └──────────┬──────────┘
                 │
          Canonical IR
        (ModelDescriptor)
                 │
         Runtime Planner
                 │
      Compression Runtime
                 │
      Memory Virtualization
                 │
     Kernel Dispatch Runtime
                 │
     CPU GPU NPU FPGA ASIC
                 │
           Token Stream
```

---

## Universal Header Sniffer

### Magic Number Registry

| Format | Magic | Offset | Notes |
|--------|-------|--------|-------|
| **GGUF** | `GGUF` | 0 | Primary tensor format |
| **GGML** | `GGML` | 0 | Legacy format |
| **Safetensors** | `{` | 0 | JSON header start |
| **PE32/64** | `MZ` | 0 | Windows executable |
| **ELF** | `0x7FELF` | 0 | Linux executable |
| **Mach-O** | `0xFEEDFACE` | 0 | macOS executable |
| **ZIP** | `PK\x03\x04` | 0 | Archive/container |
| **RawrXD Raw** | `RAWF/RAWH/RAWB` | 0 | Native tensor blobs |
| **RawrXD Encrypted** | `RADE` | 0 | Encrypted containers |
| **RawrXD VM** | `RAVM` | 0 | Bytecode format |

### API Usage

```cpp
// Simple file sniff
UniversalHeaderSniffer sniffer;
FileFormat fmt = sniffer.SniffFile("model.gguf");
// Returns: FileFormat::GGUF (not by extension, by magic)

// Memory-mapped stream for zero-copy
MemoryMappedStream stream("model.gguf");
FileFormat fmt2 = sniffer.Sniff(stream.Data(), stream.Size());

// High-level universal loader
UniversalLoader loader("model.gguf");
if (loader.IsLoaded()) {
    auto* importer = loader.GetImporter();
    // ModelDescriptor desc = importer->Import(loader.GetStream());
}
```

---

## Polymorphic Dispatch Table

### IModelImporter Interface

```cpp
class IModelImporter {
public:
    virtual bool Probe(const MemoryMappedStream& stream) const = 0;
    virtual ModelDescriptor Import(const MemoryMappedStream& stream) = 0;
    virtual std::string_view GetName() const = 0;
    virtual std::vector<FileFormat> GetSupportedFormats() const = 0;
};
```

### Registration Pattern

```cpp
// Register GGUF importer
ImporterRegistry::Instance().Register(
    std::make_unique<GGUFImporter>()
);

// Register Safetensors importer
ImporterRegistry::Instance().Register(
    std::make_unique<SafetensorsImporter>()
);

// Auto-detect and import
auto* importer = ImporterRegistry::Instance()
    .FindImporterForStream(stream);
auto descriptor = importer->Import(stream);
```

---

## Memory-Mapped Ingestion

### Windows
```cpp
CreateFileA() → CreateFileMapping() → MapViewOfFile()
```

### POSIX
```cpp
open() → mmap()
```

### Benefits
- **Zero-copy**: No buffer allocation or fread()
- **Instant load**: 500GB file maps in <5ms
- **OS-managed**: Pages fetched on-demand from NVMe
- **Shared**: Multiple processes share physical RAM

---

## ModelDescriptor Canonical IR

```cpp
struct ModelDescriptor {
    // Architecture
    ArchitectureType architecture;
    
    // Tensors
    TensorRegistry tensors;
    
    // Graph
    ComputeGraph graph;
    
    // Experts (for MoE)
    ExpertLayout expertLayout;
    
    // Tokenizer
    TokenizerConfig tokenizer;
    
    // KV Cache Policy
    KVPolicy kvPolicy;
    
    // Memory Layout
    MemoryLayout memoryLayout;
    
    // Compression
    CompressionScheme compression;
    
    // Execution Hints
    ExecutionHints hints;
    
    // Scheduler Hints
    SchedulerHints scheduler;
    
    // Capabilities
    CapabilitySet capabilities;
};
```

---

## Execution Flow

```
Arbitrary Input File (*.* / No Extension)
   ↓
Universal Memory-Mapped Stream
   ↓
Magic Number & Header Sniffer (Offset 0 Classification)
   ├──→ [Magic: GGUF / GGML]   → GGUFImporter → ModelDescriptor
   ├──→ [Magic: Safetensors]   → SafetensorsImporter → ModelDescriptor
   ├──→ [Magic: ONNX]          → ONNXImporter → ModelDescriptor
   ├──→ [Magic: PE / ELF]      → NativeBinaryLoader → Execution
   └──→ [Raw Byte Stream]      → DirectExecution / Custom VM
   ↓
ModelDescriptor (Canonical IR)
   ↓
Runtime Planner
   ↓
Execution Graph
   ↓
Memory Virtualization Layer
   ↓
Compression Runtime
   ↓
Dynamic Kernel Registry
   ↓
CPU / GPU / NPU / FPGA / ASIC
   ↓
Token Stream
```

---

## Future Importers

| Format | Status | Notes |
|--------|--------|-------|
| **GGUF** | ✅ Implemented | Primary format |
| **Safetensors** | 🔄 Planned | HuggingFace format |
| **ONNX** | 🔄 Planned | Industry standard |
| **PyTorch** | 🔄 Planned | .pt/.pth files |
| **TensorFlow** | 🔄 Planned | SavedModel |
| **Custom Encrypted** | 🔄 Planned | `RADE` containers |
| **VM Bytecode** | 🔄 Planned | `RAVM` format |
| **Raw Tensor Blobs** | ✅ Magic defined | `RAWF/RAWH/RAWB` |

---

## Build Instructions

```bash
# Compile the sniffer
cl UniversalHeaderSniffer.cpp /EHsc /O2 /c

# Compile test harness
cl TestUniversalSniffer.cpp UniversalHeaderSniffer.obj /EHsc /O2

# Run tests
TestUniversalSniffer.exe --test

# Sniff real files
TestUniversalSniffer.exe model.gguf model.bin model.data
```

---

## Integration with Existing Architecture

### Before
```
DeepSeekMoELoader
    ↓ (hardcoded assumptions)
DeepSeekConfig
    ↓
Execution
```

### After
```
UniversalLoader
    ↓ (magic-based dispatch)
IModelImporter (GGUF/Safetensors/ONNX/...)
    ↓
ModelDescriptor (canonical IR)
    ↓
ArchitectureFactory
    ↓
Runtime Planner
    ↓
Execution
```

---

## Key Benefits

1. **Extension Agnostic**: `.gguf`, `.bin`, `.data`, no extension - all treated equally
2. **Future Proof**: New formats = new importer, no engine changes
3. **Zero Copy**: Memory-mapped ingestion eliminates buffer copies
4. **Unified Runtime**: Single execution path for all model types
5. **Security**: Magic verification prevents misidentified files
6. **Performance**: Sub-millisecond format detection, instant mapping

---

## Next Steps

1. **Implement GGUFImporter** - Convert existing loader to IModelImporter
2. **Implement SafetensorsImporter** - HuggingFace compatibility
3. **Architecture Dispatch** - Factory pattern for architecture-specific parsing
4. **Tensor Validation Layer** - Cross-check metadata vs actual tensors
5. **Cache Reference Counting** - RAII pinning for concurrent expert execution

---

## The Vision

> "Not a DeepSeek runtime, but a **model-agnostic inference operating system** where architecture, quantization, and storage are all runtime data rather than compile-time assumptions."

The Universal Header Sniffer is the first step toward that vision.
