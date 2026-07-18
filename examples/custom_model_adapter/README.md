# Custom Model Adapter Example

This example demonstrates how to create a custom model adapter for RawrXD that integrates a custom inference backend.

## What This Adapter Does

This adapter provides a custom model backend (`mycustom`) that can be used alongside RawrXD's built-in backends (CUDA, Vulkan, CPU).

## Building

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

## Installing

```bash
# Install to RawrXD plugin directory
rawrxd-cli plugin install ./plugins/MyModelAdapter.dll

# Or copy manually
cp ./plugins/MyModelAdapter.dll $RAWRXD_HOME/plugins/
```

## Using the Adapter

```cpp
// In your application
RawrXD::Config config;
config.model_path = "model.custom";
config.backend = "mycustom";  // Use your custom backend
config.device = "cuda";

auto session = RawrXD::CreateSession(config);
```

## Key Concepts

### Model Backend Interface

Your backend must implement `IModelBackend`:

```cpp
class MyModelBackend : public IModelBackend {
public:
    bool Initialize(const std::unordered_map<std::string, std::string>& config) override;
    void Shutdown() override;
    std::string Generate(const std::string& prompt, ...) override;
    void GenerateStream(const std::string& prompt, ...) override;
    void ClearContext() override;
    std::unordered_map<std::string, std::string> GetStats() override;
};
```

### Backend Definition

Register your backend with a definition:

```cpp
ModelBackendDefinition{
    "mycustom",                    // Backend name
    "My Custom Backend",           // Description
    {"custom", "onnx"},           // Supported formats
    true,                          // Supports GPU
    true,                          // Supports quantization
    true,                          // Supports streaming
    can_load_function,            // Can load check
    create_function               // Factory function
};
```

## Integration Steps

1. **Implement your model** - Replace `CustomModelImpl` with your actual model
2. **Build the adapter** - Compile as a shared library
3. **Install** - Copy to RawrXD plugins directory
4. **Configure** - Set backend to `mycustom` in your config
5. **Test** - Run inference through your custom backend

## Resources

- [Plugin Development Guide](../../docs/developer/PLUGIN_DEVELOPMENT_GUIDE.md)
- [RawrXD API Reference](../../docs/integration/API_REFERENCE_COMPLETE.md)
