# RawrXD Vision Models Documentation

**Version:** v1.1.0  
**Phase:** V.3 Vision Models  
**Last Updated:** 2026-07-13

---

## Overview

RawrXD Vision Models (Phase V.3) adds multimodal capabilities to the inference engine, enabling image understanding and vision-language tasks. The vision system is designed as a modular pipeline that separates image encoding from language model inference.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Vision Pipeline Architecture                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────┐  │
│  │ Image Loader │───▶│ Image            │───▶│ Vision       │  │
│  │              │    │ Preprocessor     │    │ Encoder      │  │
│  └──────────────┘    └──────────────────┘    └──────────────┘  │
│         │                     │                     │         │
│         ▼                     ▼                     ▼         │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────┐  │
│  │ Format       │    │ Resize, Normalize│    │ CLIP/SigLIP  │  │
│  │ Detection    │    │ Patch Embedding  │    │ Transformer  │  │
│  └──────────────┘    └──────────────────┘    └──────────────┘  │
│                                                          │      │
│                                                          ▼      │
│                                               ┌──────────────┐  │
│                                               │ Embedding    │  │
│                                               │ Projector    │  │
│                                               └──────────────┘  │
│                                                       │         │
│                                                       ▼         │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────┐  │
│  │ Text Token   │◄───│ Multimodal       │◄───│ Vision       │  │
│  │ Embedding    │    │ Token Merger     │    │ Embeddings   │  │
│  └──────────────┘    └──────────────────┘    └──────────────┘  │
│         │                     │                                 │
│         └─────────────────────┘                                 │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Language Model Inference                     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. ImageLoader
**Files:** `include/rawrxd/vision/ImageLoader.hpp`, `src/vision/ImageLoader.cpp`

Loads images from various sources and formats:
- **Supported Formats:** PNG, JPEG, BMP, WebP
- **Sources:** File system, memory buffer, raw bytes
- **Features:** Format auto-detection, batch loading, progress callbacks

```cpp
ImageLoader loader;
ImageData image = loader.LoadFromFile("photo.jpg");
ImageData fromMemory = loader.LoadFromMemory(buffer);
```

### 2. ImagePreprocessor
**Files:** `include/rawrxd/vision/ImagePreprocessor.hpp`, `src/vision/ImagePreprocessor.cpp`

Preprocesses images for vision encoders:
- **Resizing:** Center crop, aspect ratio preservation
- **Normalization:** Per-channel mean/std normalization
- **Patch Embedding:** Converts image to patch sequences
- **Factory Methods:** Pre-configured for CLIP, SigLIP, LLaVA, Phi-3

```cpp
// CLIP preprocessing
auto preprocessor = PreprocessorFactory::CreateCLIPPreprocessor(224);
ImageTensor tensor = preprocessor.Preprocess(image);

// Custom preprocessing
PreprocessConfig config;
config.targetSize = 336;
config.mean = {0.5f, 0.5f, 0.5f};
config.std = {0.5f, 0.5f, 0.5f};
ImagePreprocessor preprocessor(config);
```

### 3. VisionEncoder
**Files:** `include/rawrxd/vision/VisionEncoder.hpp`, `src/vision/VisionEncoder.cpp`

Encodes images into feature embeddings:
- **CLIP:** OpenAI CLIP vision encoder
- **SigLIP:** Google SigLIP (gated activations)
- **Extensible:** Easy to add new encoder types

```cpp
// Create CLIP encoder
auto encoder = VisionEncoderFactory::CreateCLIP("base");
VisionEncoderOutput output = encoder->Encode(tensor);

// Get embeddings
std::vector<float> pooled = output.GetPooled();  // For classification
std::vector<float> sequence = output.GetSequence();  // For multimodal
```

### 4. EmbeddingProjector
**Files:** `include/rawrxd/vision/EmbeddingProjector.hpp`, `src/vision/EmbeddingProjector.cpp`

Projects vision embeddings to LLM input space:
- **Linear:** Simple matrix projection
- **MLP:** Multi-layer perceptron projection
- **Q-Former:** Query-based projection (for efficiency)

```cpp
ProjectionConfig config;
config.visionOutputDim = 768;
config.llmInputDim = 4096;
config.projectionType = "mlp";

EmbeddingProjector projector(config);
projector.LoadWeights("projector.gguf");
ProjectedEmbeddings projected = projector.Project(visionOutput);
```

### 5. VisionIntegration
**Files:** `include/rawrxd/vision/VisionIntegration.hpp`, `src/vision/VisionIntegration.cpp`

High-level integration with inference engine:
- **End-to-end pipeline:** Image → Embeddings → LLM
- **Caching:** Embedding cache for repeated images
- **Benchmarking:** Performance measurement

```cpp
VisionIntegrationConfig config;
config.encoderType = "clip";
config.encoderModelPath = "clip-vision.gguf";
config.projectorModelPath = "llava-projector.gguf";

VisionIntegration vision;
vision.Initialize(config);

// Process image
ProjectedEmbeddings embeddings = vision.ProcessImage("photo.jpg");

// Vision-enhanced generation
VisionInferenceRequest request;
request.text = "What do you see in this image?";
request.imagePaths = {"photo.jpg"};
request.useImages = true;

VisionInferenceResponse response = vision.Generate(request);
```

---

## Supported Vision Encoders

| Encoder | Image Size | Hidden Size | Layers | Best For |
|---------|------------|-------------|--------|----------|
| CLIP Base | 224×224 | 768 | 12 | General vision |
| CLIP Large | 224×224 | 1024 | 24 | Higher quality |
| SigLIP Base | 224×224 | 768 | 12 | Efficiency |
| LLaVA-1.5 | 336×336 | 1024 | 24 | Instruction following |
| Phi-3 Vision | 336×336 | 1024 | 24 | Small models |

---

## Usage Examples

### Basic Image Understanding

```cpp
#include "rawrxd/vision/VisionIntegration.hpp"

using namespace rawrxd::vision;

// Create vision integration
auto vision = VisionInferenceFactory::CreateCLIP(
    "clip-vision.gguf",
    "projector.gguf"
);

// Ask about an image
VisionInferenceRequest request;
request.text = "Describe this image in detail.";
request.imagePaths = {"landscape.jpg"};
request.useImages = true;
request.maxTokens = 256;

VisionInferenceResponse response = vision->Generate(request);
std::cout << response.text << std::endl;
```

### Multiple Images

```cpp
VisionInferenceRequest request;
request.text = "Compare these two images. What are the differences?";
request.imagePaths = {"image1.jpg", "image2.jpg"};
request.useImages = true;

auto response = vision->Generate(request);
```

### Benchmarking

```cpp
auto result = vision->Benchmark("test_image.jpg", "Describe this image");

std::cout << "Image Load: " << result.imageLoadTimeMs << " ms\n";
std::cout << "Preprocess: " << result.preprocessTimeMs << " ms\n";
std::cout << "Encode: " << result.encodeTimeMs << " ms\n";
std::cout << "Project: " << result.projectTimeMs << " ms\n";
std::cout << "Total Vision: " << result.totalVisionTimeMs << " ms\n";
```

### Streaming Generation

```cpp
vision->GenerateStreaming(request, [](const std::string& token, bool isComplete) {
    std::cout << token << std::flush;
    if (isComplete) {
        std::cout << "\n[Done]" << std::endl;
    }
});
```

---

## Performance Considerations

### Image Preprocessing
- **CPU-bound:** Resize and normalization happen on CPU
- **Time:** ~5-20ms for 224×224 images
- **Optimization:** Preprocess images and cache tensors

### Vision Encoding
- **GPU-accelerated:** CLIP/SigLIP encoders use GPU
- **Time:** ~10-50ms depending on model size
- **Batching:** Process multiple images together for efficiency

### Embedding Projection
- **Lightweight:** Simple matrix multiplication
- **Time:** ~1-5ms
- **Caching:** Cache projected embeddings for repeated images

### Memory Requirements

| Component | Memory (per image) |
|-----------|-------------------|
| Raw Image (224×224 RGB) | ~150 KB |
| Preprocessed Tensor | ~600 KB |
| Vision Embeddings | ~3 MB |
| Projected Embeddings | ~16 KB |

---

## Integration with Phase V.2

Vision models leverage the compatibility layer:

```cpp
// Architecture detection for vision models
CompatibilityIntegration compat;
compat.Initialize("llava-model.gguf");

// Vision integration uses detected configuration
VisionIntegration vision;
vision.Initialize(config);

// Telemetry tracks both vision and text
auto& telemetry = CompatibilityTelemetryManager::GetInstance();
telemetry.EmitModelLoad("clip-vision.gguf", "clip", loadTime);
```

---

## Validation

### Vision Compatibility Checker

```cpp
auto result = VisionCompatibilityChecker::CheckFullPipeline(
    "encoder.gguf",
    "projector.gguf"
);

if (result.compatible) {
    std::cout << "Vision pipeline is compatible!\n";
} else {
    for (const auto& error : result.errors) {
        std::cerr << "Error: " << error << "\n";
    }
}
```

### Test Suite

```bash
# Test vision pipeline
./rawrxd test --vision --encoder clip-vision.gguf --projector projector.gguf

# Benchmark vision components
./rawrxd benchmark --vision --image test.jpg

# Validate multimodal inference
./rawrxd test --multimodal --model llava.gguf --image photo.jpg
```

---

## Future Enhancements

### Phase V.3.1 (Current)
- ✅ CLIP vision encoder
- ✅ SigLIP vision encoder
- ✅ Linear/MLP projection
- ✅ Basic multimodal inference

### Phase V.3.2 (Planned)
- 🔄 Q-Former projection
- 🔄 Image token caching
- 🔄 Async image encoding

### Phase V.3.3 (Planned)
- ⏳ Video understanding
- ⏳ Multi-frame processing
- ⏳ Temporal attention

### Phase V.4 (Future)
- ⏳ Audio encoders
- ⏳ Speech-to-text
- ⏳ Multimodal fusion

---

## Troubleshooting

### Common Issues

**Issue:** "Failed to load image"
- **Cause:** Unsupported format or corrupted file
- **Solution:** Convert to PNG/JPEG, verify file integrity

**Issue:** "Vision encoder not initialized"
- **Cause:** Missing or incompatible GGUF weights
- **Solution:** Check GGUF file, verify architecture compatibility

**Issue:** "Embedding dimension mismatch"
- **Cause:** Projector output doesn't match LLM input
- **Solution:** Verify projector configuration matches LLM

**Issue:** Slow vision processing
- **Cause:** CPU-only preprocessing, no batching
- **Solution:** Enable GPU preprocessing, batch multiple images

---

## API Reference

See header files for complete API:
- `include/rawrxd/vision/ImageLoader.hpp`
- `include/rawrxd/vision/ImagePreprocessor.hpp`
- `include/rawrxd/vision/VisionEncoder.hpp`
- `include/rawrxd/vision/EmbeddingProjector.hpp`
- `include/rawrxd/vision/VisionIntegration.hpp`

---

**Vision Models Version:** 1.0.0  
**Compatible with:** RawrXD v1.1.0+
