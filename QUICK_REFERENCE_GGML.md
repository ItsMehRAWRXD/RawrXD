# GGML Quick Reference Card

**One-page reference for GGML integration with unified architecture**

---

## Essential Includes

```cpp
#include "agentic/Core.h"
#include "inference/InferenceEngine.h"
```

---

## 3-Step Setup

```cpp
// 1. Create Core
auto core = RawrXD::Agentic::Core::Create();
core->Initialize();

// 2. Create GGML Engine
auto inference = RawrXD::Inference::InferenceEngine::Create({
    .backendType = RawrXD::Inference::BackendType::GGML,
    .modelPath = "model.gguf"
});
inference->Initialize();

// 3. Connect
core->SetInferenceEngine(inference);
```

---

## Generate Text

```cpp
RawrXD::Agentic::Task task;
task.type = RawrXD::Agentic::TaskType::Inference;
task.inferenceParams.prompt = "Hello";
task.inferenceParams.maxTokens = 100;

auto future = core->SubmitTask(task);
auto result = future.get();

std::cout << result.output;  // Generated text
```

---

## Common Configurations

| Use Case | Config |
|----------|--------|
| Fastest | `{.quantization = Q4_0, .threads = 8}` |
| Best Quality | `{.quantization = Q8_0, .temperature = 0.7}` |
| Long Context | `{.maxContext = 8192, .kvCache = 1GB}` |
| Low Memory | `{.quantization = Q4_0, .memoryMap = true}` |

---

## Error Handling

```cpp
auto result = engine->LoadModel("model.gguf");
if (!result.success) {
    std::cerr << result.errorMessage;
    return;
}
```

---

## Performance Tips

1. Use Q4_0 quantization for 2x speedup
2. Enable memory mapping for large models
3. Set threads = physical cores (not logical)
4. Use batch processing for multiple prompts

---

## Model Conversion

```bash
# Convert PyTorch to GGUF
python convert.py --input model.pt --output model.gguf

# Quantize
python quantize.py --input model.gguf --output model-q4.gguf --type Q4_0
```

---

**Status**: ✅ Production Ready | **Docs**: Full guide in GGML_UNIFIED_INTEGRATION_GUIDE.md
