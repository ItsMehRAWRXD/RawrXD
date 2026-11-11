#pragma once

#include "rawrxd/vision/ImagePreprocessor.hpp"
#include <string>
#include <vector>
#include <memory>

namespace rawrxd {
namespace vision {

// Forward declarations
class Tensor;
class ModelWeights;

// Vision encoder configuration
struct VisionEncoderConfig {
    // Architecture
    std::string modelType = "clip";  // clip, siglip, llava, phi3v
    int imageSize = 224;
    int patchSize = 14;
    int hiddenSize = 768;
    int numLayers = 12;
    int numHeads = 12;
    int intermediateSize = 3072;
    int numChannels = 3;
    
    // Normalization
    std::string layerNormType = "pre";  // pre, post
    float layerNormEps = 1e-5f;
    
    // Activation
    std::string activation = "gelu_quick";  // gelu, gelu_quick, silu
    
    // Special features
    bool usePositionEmbedding = true;
    bool useClassToken = true;
    bool useGatedActivation = false;  // For SigLIP
    
    // Get derived values
    int GetNumPatches() const {
        return (imageSize / patchSize) * (imageSize / patchSize);
    }
    
    int GetSequenceLength() const {
        return GetNumPatches() + (useClassToken ? 1 : 0);
    }
    
    int GetPatchDim() const {
        return patchSize * patchSize * numChannels;
    }
};

// Vision encoder output
struct VisionEncoderOutput {
    std::vector<float> embeddings;
    std::vector<float> patchEmbeddings;
    std::vector<float> classEmbedding;
    int numPatches = 0;
    int hiddenSize = 0;
    
    // Get pooled representation (class token or mean of patches)
    std::vector<float> GetPooled() const;
    
    // Get full sequence (for multimodal attention)
    const std::vector<float>& GetSequence() const { return embeddings; }
};

// Abstract vision encoder interface
class VisionEncoder {
public:
    VisionEncoder() = default;
    virtual ~VisionEncoder() = default;

    // Initialize encoder
    virtual bool Initialize(const VisionEncoderConfig& config) = 0;
    virtual bool LoadWeights(const std::string& ggufPath) = 0;
    
    // Encode image
    virtual VisionEncoderOutput Encode(const ImageTensor& image) = 0;
    
    // Encode batch
    virtual std::vector<VisionEncoderOutput> EncodeBatch(const std::vector<ImageTensor>& images) = 0;
    
    // Get configuration
    virtual const VisionEncoderConfig& GetConfig() const = 0;
    
    // Get output dimension
    virtual int GetOutputDim() const = 0;
    
    // Check if initialized
    virtual bool IsInitialized() const = 0;
    
    // Get last error
    virtual std::string GetLastError() const = 0;
};

// CLIP vision encoder implementation
class CLIPVisionEncoder : public VisionEncoder {
public:
    CLIPVisionEncoder();
    ~CLIPVisionEncoder() override = default;

    bool Initialize(const VisionEncoderConfig& config) override;
    bool LoadWeights(const std::string& ggufPath) override;
    VisionEncoderOutput Encode(const ImageTensor& image) override;
    std::vector<VisionEncoderOutput> EncodeBatch(const std::vector<ImageTensor>& images) override;
    const VisionEncoderConfig& GetConfig() const override { return config_; }
    int GetOutputDim() const override { return config_.hiddenSize; }
    bool IsInitialized() const override { return initialized_; }
    std::string GetLastError() const override { return lastError_; }

private:
    VisionEncoderConfig config_;
    bool initialized_ = false;
    std::string lastError_;
    std::unique_ptr<ModelWeights> weights_;
    
    // Internal encoding
    VisionEncoderOutput EncodeInternal(const ImageTensor& image);
    std::vector<float> PatchEmbedding(const ImageTensor& image);
    std::vector<float> AddPositionEmbeddings(const std::vector<float>& patches);
    std::vector<float> TransformerEncoder(const std::vector<float>& embeddings);
    std::vector<float> LayerNorm(const std::vector<float>& x);
    std::vector<float> MultiHeadAttention(const std::vector<float>& x);
    std::vector<float> MLP(const std::vector<float>& x);
};

// SigLIP vision encoder
class SigLIPVisionEncoder : public VisionEncoder {
public:
    SigLIPVisionEncoder();
    ~SigLIPVisionEncoder() override = default;

    bool Initialize(const VisionEncoderConfig& config) override;
    bool LoadWeights(const std::string& ggufPath) override;
    VisionEncoderOutput Encode(const ImageTensor& image) override;
    std::vector<VisionEncoderOutput> EncodeBatch(const std::vector<ImageTensor>& images) override;
    const VisionEncoderConfig& GetConfig() const override { return config_; }
    int GetOutputDim() const override { return config_.hiddenSize; }
    bool IsInitialized() const override { return initialized_; }
    std::string GetLastError() const override { return lastError_; }

private:
    VisionEncoderConfig config_;
    bool initialized_ = false;
    std::string lastError_;
    std::unique_ptr<ModelWeights> weights_;
};

// Vision encoder factory
class VisionEncoderFactory {
public:
    // Create encoder by type
    static std::unique_ptr<VisionEncoder> Create(const std::string& type);
    
    // Create CLIP encoder
    static std::unique_ptr<VisionEncoder> CreateCLIP(const std::string& variant = "base");
    
    // Create SigLIP encoder
    static std::unique_ptr<VisionEncoder> CreateSigLIP(const std::string& variant = "base");
    
    // Create encoder from GGUF
    static std::unique_ptr<VisionEncoder> CreateFromGGUF(const std::string& ggufPath);
    
    // Get supported encoder types
    static std::vector<std::string> GetSupportedTypes();
};

} // namespace vision
} // namespace rawrxd
