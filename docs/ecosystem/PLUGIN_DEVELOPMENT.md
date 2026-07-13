# Phase M.5/5: Ecosystem Marketplace & Developer Documentation

## Plugin Development Guide

This guide covers everything you need to know to develop plugins for RawrXD Sovereign AI Runtime.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Plugin Architecture](#plugin-architecture)
3. [Creating Your First Plugin](#creating-your-first-plugin)
4. [Plugin Capabilities](#plugin-capabilities)
5. [API Reference](#api-reference)
6. [Testing & Debugging](#testing--debugging)
7. [Publishing](#publishing)
8. [Best Practices](#best-practices)

---

## Getting Started

### Prerequisites

- C++17 compatible compiler (GCC 9+, Clang 10+, MSVC 2019+)
- CMake 3.16+
- RawrXD SDK (installed or built from source)
- Git

### Installation

```bash
# Clone the plugin template
git clone https://github.com/ItsMehRAWRXD/rawrxd-plugin-template.git my-plugin
cd my-plugin

# Configure
mkdir build && cd build
cmake .. -DRAWRXD_SDK_PATH=/path/to/rawrxd/sdk

# Build
cmake --build . --config Release
```

---

## Plugin Architecture

### Plugin Lifecycle

```
Load → Initialize → [Run] → Shutdown → Unload
```

### Core Interface

All plugins must implement the `IPlugin` interface:

```cpp
#include <RawrXD/Plugins/PluginManager.hpp>

class MyPlugin : public RawrXD::Plugins::IPlugin {
public:
    bool Initialize(PluginContext* context) override;
    void Shutdown() override;
    const PluginMetadata& GetMetadata() const override;
    std::vector<PluginCapability> GetCapabilities() const override;
    bool HasCapability(PluginCapability capability) const override;
};
```

### Plugin Entry Point

Use the provided macro to export your plugin:

```cpp
RAWRXD_PLUGIN_ENTRYPOINT(MyPlugin)
```

---

## Creating Your First Plugin

### Step 1: Plugin Metadata

Define your plugin's metadata:

```cpp
static RawrXD::Plugins::PluginMetadata GetStaticMetadata() {
    return {
        .id = "com.example.myplugin",
        .name = "My First Plugin",
        .version = "1.0.0",
        .author = "Your Name",
        .description = "A simple example plugin",
        .license = "MIT",
        .dependencies = {},
        .exports = {"example_feature"},
        .api_version = 1,
        .hot_reloadable = true
    };
}
```

### Step 2: Implementation

```cpp
#include <RawrXD/Plugins/PluginManager.hpp>
#include <iostream>

using namespace RawrXD::Plugins;

class ExamplePlugin : public IPlugin {
private:
    PluginContext* context_ = nullptr;
    bool initialized_ = false;

public:
    bool Initialize(PluginContext* context) override {
        context_ = context;
        context->LogInfo("ExamplePlugin initializing...");
        
        // Subscribe to events
        context->SubscribeToEvent("inference.complete", 
            [](const std::string& event, const std::string& data) {
                std::cout << "Inference completed: " << data << std::endl;
            });
        
        initialized_ = true;
        return true;
    }
    
    void Shutdown() override {
        if (context_) {
            context_>LogInfo("ExamplePlugin shutting down...");
        }
        initialized_ = false;
    }
    
    const PluginMetadata& GetMetadata() const override {
        static PluginMetadata metadata = GetStaticMetadata();
        return metadata;
    }
    
    std::vector<PluginCapability> GetCapabilities() const override {
        return { PluginCapability::MONITORING_EXPORTER };
    }
    
    bool HasCapability(PluginCapability capability) const override {
        return capability == PluginCapability::MONITORING_EXPORTER;
    }
};

RAWRXD_PLUGIN_ENTRYPOINT(ExamplePlugin)
```

### Step 3: Build Configuration

**CMakeLists.txt:**

```cmake
cmake_minimum_required(VERSION 3.16)
project(MyPlugin VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find RawrXD SDK
find_package(RawrXD REQUIRED)

# Create plugin library
add_library(myplugin SHARED
    src/myplugin.cpp
)

target_link_libraries(myplugin
    PRIVATE
        RawrXD::PluginAPI
)

# Set plugin properties
set_target_properties(myplugin PROPERTIES
    PREFIX ""
    SUFFIX ".rawrxd-plugin"
)

# Install
install(TARGETS myplugin
    DESTINATION plugins
)
```

### Step 4: Build and Test

```bash
mkdir build && cd build
cmake ..
cmake --build .

# Copy to RawrXD plugins directory
cp myplugin.rawrxd-plugin /opt/rawrxd/plugins/

# Test loading
rawrxd --load-plugin myplugin
```

---

## Plugin Capabilities

### Available Capabilities

| Capability | Description | Use Case |
|------------|-------------|----------|
| `INFERENCE_PREPROCESSOR` | Modify inputs before inference | Input validation, formatting |
| `INFERENCE_POSTPROCESSOR` | Modify outputs after inference | Output filtering, formatting |
| `MODEL_LOADER` | Support custom model formats | Proprietary formats, adapters |
| `TOKENIZER_EXTENSION` | Extend tokenizer functionality | Custom vocabularies |
| `SAMPLING_STRATEGY` | Custom sampling algorithms | Novel decoding methods |
| `TOOL_PROVIDER` | Provide external tools | API integrations |
| `MONITORING_EXPORTER` | Export metrics | Custom monitoring |
| `UI_EXTENSION` | Add UI components | Custom interfaces |
| `API_MIDDLEWARE` | Process API requests | Authentication, logging |
| `CUSTOM_OPERATOR` | Custom compute operations | Optimized kernels |

### Implementing a Capability

Example: Custom Sampling Strategy

```cpp
class CustomSamplerPlugin : public IPlugin {
public:
    // ... standard plugin methods ...
    
    std::vector<PluginCapability> GetCapabilities() const override {
        return { PluginCapability::SAMPLING_STRATEGY };
    }
    
    // Custom sampling implementation
    uint32_t Sample(const std::vector<float>& logits, float temperature) {
        // Your custom sampling logic
        return CustomSampling(logits, temperature);
    }
};
```

---

## API Reference

### PluginContext

The `PluginContext` provides access to core RawrXD systems:

#### Logging

```cpp
context->LogInfo("Information message");
context->LogWarning("Warning message");
context->LogError("Error message");
```

#### Configuration

```cpp
// Get config value
std::string value = context->GetConfigValue("myplugin.setting");

// Set config value
context->SetConfigValue("myplugin.setting", "new_value");
```

#### Events

```cpp
// Subscribe to events
context->SubscribeToEvent("inference.start", 
    [](const std::string& event, const std::string& data) {
        // Handle event
    });

// Publish events
context->PublishEvent("myplugin.event", "event_data");
```

#### Plugin Interop

```cpp
// Get another plugin
IPlugin* other = context->GetPlugin("com.example.otherplugin");

// Check if plugin is loaded
bool loaded = context->IsPluginLoaded("com.example.otherplugin");
```

#### Resource Management

```cpp
// Get directories
std::string dataDir = context->GetDataDirectory();
std::string cacheDir = context->GetCacheDirectory();
```

---

## Testing & Debugging

### Unit Testing

```cpp
#include <gtest/gtest.h>
#include "myplugin.hpp"

TEST(MyPluginTest, Initialization) {
    MyPlugin plugin;
    MockPluginContext context;
    
    EXPECT_TRUE(plugin.Initialize(&context));
    EXPECT_TRUE(plugin.IsHealthy());
    
    plugin.Shutdown();
}
```

### Debugging

Enable debug logging:

```bash
export RAWRXD_PLUGIN_DEBUG=1
export RAWRXD_PLUGIN_LOG_LEVEL=debug
rawrxd --load-plugin myplugin
```

### Hot Reload

For development, enable hot reload:

```cpp
// In metadata
.hot_reloadable = true
```

Then use:

```bash
rawrxd --hot-reload myplugin
```

---

## Publishing

### Plugin Marketplace

Submit your plugin to the RawrXD Marketplace:

1. **Prepare package:**
   ```bash
   mkdir myplugin-1.0.0
   cp myplugin.rawrxd-plugin myplugin-1.0.0/
   cp README.md LICENSE myplugin-1.0.0/
   tar czf myplugin-1.0.0.tar.gz myplugin-1.0.0/
   ```

2. **Create manifest:**
   ```json
   {
     "id": "com.example.myplugin",
     "name": "My Plugin",
     "version": "1.0.0",
     "author": "Your Name",
     "description": "Short description",
     "long_description": "Detailed description...",
     "license": "MIT",
     "tags": ["monitoring", "metrics"],
     "min_rawrxd_version": "1.0.0",
     "max_rawrxd_version": "2.0.0",
     "platforms": ["linux-x64", "windows-x64"],
     "homepage": "https://example.com/myplugin",
     "repository": "https://github.com/example/myplugin",
     "download_url": "https://example.com/myplugin-1.0.0.tar.gz",
     "checksum": "sha256:abc123..."
   }
   ```

3. **Submit:**
   - Fork https://github.com/ItsMehRAWRXD/rawrxd-marketplace
   - Add your manifest to `plugins/`
   - Submit pull request

### Distribution

**GitHub Releases:**

```yaml
# .github/workflows/release.yml
name: Release Plugin
on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build
        run: |
          mkdir build && cd build
          cmake ..
          cmake --build .
      
      - name: Release
        uses: softprops/action-gh-release@v1
        with:
          files: build/*.rawrxd-plugin
```

---

## Best Practices

### Performance

- Minimize work in hot paths
- Use caching where appropriate
- Avoid blocking operations
- Profile your plugin

### Security

- Validate all inputs
- Use sandboxing for untrusted operations
- Don't expose sensitive data
- Follow principle of least privilege

### Compatibility

- Test with multiple RawrXD versions
- Handle missing dependencies gracefully
- Document version requirements
- Use feature detection

### Documentation

- Provide clear README
- Include usage examples
- Document configuration options
- Add troubleshooting guide

### Error Handling

```cpp
bool MyPlugin::Initialize(PluginContext* context) {
    try {
        // Initialization code
        return true;
    } catch (const std::exception& e) {
        context->LogError(std::string("Initialization failed: ") + e.what());
        return false;
    }
}
```

### Resource Management

```cpp
class MyPlugin : public IPlugin {
private:
    std::unique_ptr<Resource> resource_;
    
public:
    bool Initialize(PluginContext* context) override {
        resource_ = std::make_unique<Resource>();
        return resource_->Initialize();
    }
    
    void Shutdown() override {
        resource_.reset();  // Automatic cleanup
    }
};
```

---

## Examples

### Example 1: Metrics Exporter

Exports inference metrics to Prometheus:

```cpp
class PrometheusExporterPlugin : public IPlugin {
    // Implementation...
};
```

### Example 2: Custom Tokenizer

Adds support for a new tokenization scheme:

```cpp
class CustomTokenizerPlugin : public IPlugin {
    // Implementation...
};
```

### Example 3: API Middleware

Adds authentication to API requests:

```cpp
class AuthMiddlewarePlugin : public IPlugin {
    // Implementation...
};
```

---

## Resources

- **Plugin Template:** https://github.com/ItsMehRAWRXD/rawrxd-plugin-template
- **API Documentation:** https://docs.rawrxd.ai/plugins
- **Example Plugins:** https://github.com/ItsMehRAWRXD/rawrxd-plugins
- **Community Forum:** https://forum.rawrxd.ai/c/plugins
- **Discord:** https://discord.gg/rawrxd

---

## Support

- **Issues:** https://github.com/ItsMehRAWRXD/RawrXD/issues
- **Email:** plugins@rawrxd.ai
- **Enterprise:** enterprise@rawrxd.ai

---

**Document Version:** 1.0.0  
**Last Updated:** 2026-07-13  
**RawrXD Version:** 1.0.0+
