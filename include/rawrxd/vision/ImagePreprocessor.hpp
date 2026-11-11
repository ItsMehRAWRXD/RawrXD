#pragma once

#include "rawrxd/vision/ImageLoader.hpp"
#include <vector>
#include <memory>

namespace rawrxd {
namespace vision {

// Preprocessing configuration for vision models
struct PreprocessConfig {
    // Image dimensions
    int targetSize = 224;           // Target size (square)
    int patchSize = 14;             // Vision encoder patch size
    
    // Normalization
    std::vector<float> mean = {0.48145466f, 0.4578275f, 0.40821073f};  // CLIP defaults
    std::vector<float> std = {0.26862954f, 0.26130258f, 0.27577711f};
    
    // Augmentation
    bool randomCrop = false;
    bool randomFlip = false;
    bool normalize = true;
    
    // Special processing
    bool convertToRGB = true;
    bool centerCrop = true;
    
    // Get number of patches
    int GetNumPatches() const {
        return (targetSize / patchSize) * (targetSize / patchSize);
    }
    
    // Get sequence length (patches + class token)
    int GetSequenceLength() const {
        return GetNumPatches() + 1;
    }
};

// Preprocessed image tensor
struct ImageTensor {
    std::vector<float> data;
    int width = 0;
    int height = 0;
    int channels = 0;
    int numPatches = 0;
    
    // Get pointer to data
    const float* GetData() const { return data.data(); }
    float* GetData() { return data.data(); }
    
    // Get size
    size_t GetSize() const { return data.size(); }
};

// Image preprocessor for vision encoders
class ImagePreprocessor {
public:
    ImagePreprocessor();
    explicit ImagePreprocessor(const PreprocessConfig& config);
    ~ImagePreprocessor() = default;

    // Set configuration
    void SetConfig(const PreprocessConfig& config) { config_ = config; }
    const PreprocessConfig& GetConfig() const { return config_; }
    
    // Preprocess single image
    ImageTensor Preprocess(const ImageData& image);
    
    // Preprocess from file
    ImageTensor PreprocessFile(const std::string& path);
    
    // Preprocess batch
    std::vector<ImageTensor> PreprocessBatch(const std::vector<ImageData>& images);
    
    // Get expected input shape
    std::vector<int> GetInputShape() const {
        return {1, config_.targetSize, config_.targetSize, 3};
    }
    
    // Get patch grid size
    std::pair<int, int> GetPatchGridSize() const {
        int gridSize = config_.targetSize / config_.patchSize;
        return {gridSize, gridSize};
    }

private:
    PreprocessConfig config_;
    
    // Internal processing steps
    ImageData ResizeAndCrop(const ImageData& image);
    ImageData ConvertToRGB(const ImageData& image);
    ImageTensor Normalize(const ImageData& image);
    ImageTensor CreatePatchEmbeddings(const ImageTensor& normalized);
    
    // Utility functions
    std::vector<float> ComputeMean(const ImageData& image);
    std::vector<float> ComputeStd(const ImageData& image);
};

// Preprocessor factory for different vision encoders
class PreprocessorFactory {
public:
    // Create preprocessor for CLIP
    static ImagePreprocessor CreateCLIPPreprocessor(int imageSize = 224);
    
    // Create preprocessor for SigLIP
    static ImagePreprocessor CreateSigLIPPreprocessor(int imageSize = 224);
    
    // Create preprocessor for LLaVA
    static ImagePreprocessor CreateLLaVAPreprocessor(int imageSize = 336);
    
    // Create preprocessor for Phi-3 Vision
    static ImagePreprocessor CreatePhi3VisionPreprocessor(int imageSize = 336);
    
    // Create custom preprocessor
    static ImagePreprocessor CreateCustom(const PreprocessConfig& config);
};

} // namespace vision
} // namespace rawrxd
