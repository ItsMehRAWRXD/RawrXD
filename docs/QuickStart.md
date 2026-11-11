# RawrXD Quick Start Guide

Get up and running with RawrXD in 5 minutes.

## Prerequisites

- **OS**: Windows 10/11, Ubuntu 20.04+, macOS 12+
- **Compiler**: C++17 compatible (MSVC 2019+, GCC 9+, Clang 10+)
- **CMake**: 3.16 or higher
- **Python**: 3.8+ (for scripts)

## Installation

### Option 1: Pre-built Binaries (Recommended)

```bash
# Download latest release
curl -L https://github.com/ItsMehRAWRXD/RawrXD/releases/latest/download/rawrxd-linux-x64.tar.gz | tar xz

# Add to PATH
export PATH="$PWD/rawrxd/bin:$PATH"

# Verify installation
rawrxd --version
```

### Option 2: Build from Source

```bash
# Clone repository
git clone --recursive https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD

# Configure build
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build --parallel

# Install
sudo cmake --install build
```

## Your First Inference

### 1. Download a Model

```bash
# Download a GGUF model (e.g., Llama 2 7B Q4_K_M)
rawrxd model pull llama2-7b-q4km

# Or use your own
rawrxd model add /path/to/your/model.gguf --name my-model
```

### 2. Run Inference

```bash
# Interactive mode
rawrxd chat --model llama2-7b-q4km

# Single prompt
rawrxd complete --model llama2-7b-q4km --prompt "Hello, world!"

# From file
rawrxd complete --model llama2-7b-q4km --file input.txt
```

### 3. Programmatic API (C++)

```cpp
#include <rawrxd/RawrXD.hpp>

int main() {
    // Initialize runtime
    auto runtime = rawrxd::Runtime::Create();
    runtime->Initialize();
    
    // Load model
    auto model = runtime->LoadModel("llama2-7b-q4km");
    
    // Create session
    auto session = runtime->CreateSession(model);
    
    // Generate text
    auto result = session->Complete("Hello, world!");
    if (result.IsOk()) {
        std::cout << result.Value() << std::endl;
    }
    
    return 0;
}
```

## Configuration

### Global Config

```bash
# Edit global config
rawrxd config edit

# Or set specific values
rawrxd config set inference.threads 8
rawrxd config set inference.gpu_layers 35
```

### Per-Session Config

```cpp
rawrxd::SessionConfig config;
config.maxTokens = 512;
config.temperature = 0.7f;
config.topP = 0.9f;

auto session = runtime->CreateSession(model, config);
```

## Next Steps

- [Build Guide](Build.md) - Detailed build instructions
- [Architecture Overview](Architecture.md) - Understand RawrXD design
- [Examples](Examples.md) - More code samples
- [API Reference](../include/rawrxd/) - Complete API documentation

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/ItsMehRAWRXD/RawrXD/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ItsMehRAWRXD/RawrXD/discussions)
- **FAQ**: [Frequently Asked Questions](FAQ.md)
- **Troubleshooting**: [Troubleshooting Guide](Troubleshooting.md)
