// ============================================================================
// MultiModalVision.hpp - Multi-Modal Vision Support for Model Inference
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Sovereign {

struct VisionConfig {
    uint32_t imageSize = 224;
    uint32_t patchSize = 14;
    uint32_t numChannels = 3;
    uint32_t hiddenDim = 1024;
    uint32_t numLayers = 24;
    uint32_t numHeads = 16;
    std::string encoderType = "vit"; // vit, siglip, clip
};

struct ImageData {
    uint32_t width;
    uint32_t height;
    uint32_t channels;
    std::vector<uint8_t> pixels;
};

struct VisionEmbedding {
    std::vector<float> embedding;
    uint64_t dim;
    uint32_t numPatches;
};

class MultiModalVision {
public:
    MultiModalVision();
    ~MultiModalVision();

    bool Initialize(const VisionConfig& config);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    VisionEmbedding EncodeImage(const ImageData& image);
    VisionEmbedding EncodeImagePath(const std::string& path);
    std::vector<VisionEmbedding> EncodeImages(const std::vector<ImageData>& images);

    bool SetEncoderWeights(const float* weights, uint64_t size);
    bool SetProjectionWeights(const float* weights, uint64_t size);

    uint64_t GetEmbeddingDim() const { return config_.hiddenDim; }
    uint32_t GetNumPatches(const ImageData& image) const;

    struct VisionStats {
        uint64_t totalImages;
        uint64_t totalTokens;
        double avgEncodeTimeMs;
    };
    VisionStats GetStats() const { return stats_; }

private:
    VisionConfig config_;
    VisionStats stats_;
    bool initialized_ = false;
    mutable std::mutex mutex_;
    
    std::vector<float> encoderWeights_;
    std::vector<float> projectionWeights_;
    
    std::vector<float> PatchEmbed(const ImageData& image) const;
    std::vector<float> PositionEmbed(const std::vector<float>& patches) const;
};

} // namespace Sovereign
