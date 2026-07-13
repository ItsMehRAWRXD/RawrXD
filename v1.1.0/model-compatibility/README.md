# RawrXD Sovereign v1.1.0 - Model Compatibility Framework

## Overview

The Model Compatibility Framework (V.2) extends RawrXD's inference capabilities to support multiple model formats beyond GGUF. This enables users to load and run models from ONNX, TensorRT, and other popular formats while maintaining the same high-performance inference runtime.

## Goals

- Support multiple model formats (GGUF, ONNX, TensorRT)
- Unified model loading interface
- Format-agnostic inference API
- Automatic format detection
- Model conversion utilities

## Supported Formats

| Format | Extension | Status | Backend |
|--------|-----------|--------|---------|
| **GGUF** | `.gguf` | ✅ Native | Custom |
| **ONNX** | `.onnx` | 🔄 In Progress | ONNX Runtime |
| **TensorRT** | `.trt`, `.engine` | 🔄 In Progress | TensorRT |
| **PyTorch** | `.pt`, `.pth` | 📋 Planned | LibTorch |
| **Safetensors** | `.safetensors` | 📋 Planned | Custom |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 Model Compatibility Layer                  │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  GGUFLoader │  │ ONNXLoader  │  │  TensorRTLoader     │ │
│  │   (Native)  │  │(ONNX Runtime│  │     (TensorRT)      │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                    │            │
│         └────────────────┴────────────────────┘            │
│                          │                                 │
│                          ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              UnifiedModelLoader                    │   │
│  │         (Format detection & dispatch)              │   │
│  └─────────────────────────┬───────────────────────────┘   │
└────────────────────────────┼───────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                 RawrXD Inference Runtime                     │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Tokenizer │  │    Model    │  │  Inference Engine   │  │
│  │             │  │   Weights   │  │   (Vulkan/CPU)      │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. UnifiedModelLoader

Central loader that detects model format and dispatches to appropriate loader.

```cpp
class UnifiedModelLoader {
public:
    std::shared_ptr<IModel> Load(const std::string& path);
    ModelFormat DetectFormat(const std::string& path);
    std::vector<ModelFormat> GetSupportedFormats();
};
```

### 2. Format-Specific Loaders

Each loader implements the `IModelLoader` interface:

```cpp
class IModelLoader {
public:
    virtual bool CanLoad(const std::string& path) = 0;
    virtual std::shared_ptr<IModel> Load(const std::string& path) = 0;
    virtual ModelFormat GetFormat() const = 0;
};
```

### 3. Model Interface

Unified model interface for all formats:

```cpp
class IModel {
public:
    virtual std::string GetName() const = 0;
    virtual ModelFormat GetFormat() const = 0;
    virtual std::vector<Tensor> Run(const std::vector<Tensor>& inputs) = 0;
    virtual ModelMetadata GetMetadata() const = 0;
};
```

## Directory Structure

```
model-compatibility/
├── README.md                    # This file
├── UnifiedModelLoader.hpp       # Main loader interface
├── UnifiedModelLoader.cpp       # Implementation
├── ModelInterface.hpp           # IModel interface
├── ModelMetadata.hpp            # Model metadata structures
├── ModelFormat.hpp              # Format definitions
├── loaders/
│   ├── GGUFLoader.hpp           # GGUF loader
│   ├── GGUFLoader.cpp
│   ├── ONNXLoader.hpp           # ONNX loader
│   ├── ONNXLoader.cpp
│   ├── TensorRTLoader.hpp       # TensorRT loader
│   └── TensorRTLoader.cpp
├── converters/
│   ├── ModelConverter.hpp       # Conversion interface
│   ├── GGUFToONNX.hpp           # GGUF→ONNX converter
│   └── ONNXToTensorRT.hpp       # ONNX→TensorRT converter
└── tests/
    └── ModelCompatibilityTests.cpp
```

## Usage Example

```cpp
#include <RawrXD/ModelCompatibility.hpp>

using namespace RawrXD::ModelCompatibility;

// Initialize unified loader
UnifiedModelLoader loader;

// Load model (format auto-detected)
auto model = loader.Load("model.gguf");
// or
auto model = loader.Load("model.onnx");
// or
auto model = loader.Load("model.trt");

// Run inference
std::vector<Tensor> inputs = {...};
std::vector<Tensor> outputs = model->Run(inputs);

// Get metadata
auto metadata = model->GetMetadata();
std::cout << "Model: " << metadata.name << std::endl;
std::cout << "Format: " << metadata.format << std::endl;
std::cout << "Parameters: " << metadata.parameter_count << std::endl;
```

## Format Detection

The loader automatically detects model format by:

1. File extension (`.gguf`, `.onnx`, `.trt`)
2. Magic bytes in file header
3. File structure validation

```cpp
ModelFormat format = loader.DetectFormat("model.gguf");
// Returns: ModelFormat::GGUF
```

## Model Conversion

Convert between formats:

```cpp
ModelConverter converter;

// Convert GGUF to ONNX
converter.Convert("model.gguf", "model.onnx", ModelFormat::ONNX);

// Convert ONNX to TensorRT
converter.Convert("model.onnx", "model.trt", ModelFormat::TensorRT);
```

## Status

🔄 **V.2 IN PROGRESS**

### Completed
- [ ] UnifiedModelLoader interface
- [ ] ModelFormat definitions
- [ ] IModel interface
- [ ] GGUFLoader integration
- [ ] ONNXLoader implementation
- [ ] TensorRTLoader implementation
- [ ] Model conversion utilities

### Next Steps
1. Create UnifiedModelLoader.hpp/cpp
2. Define ModelFormat enum
3. Create IModel interface
4. Implement GGUFLoader wrapper
5. Implement ONNXLoader (ONNX Runtime)
6. Implement TensorRTLoader
7. Add model conversion utilities

## Dependencies

| Component | Dependency | Version |
|-----------|------------|---------|
| ONNXLoader | ONNX Runtime | 1.16+ |
| TensorRTLoader | TensorRT | 8.6+ |
| GGUFLoader | Native | Built-in |

## License

MIT License - See LICENSE file in repository root.

---

**RawrXD Sovereign v1.1.0** | Model Compatibility Framework | 2026
