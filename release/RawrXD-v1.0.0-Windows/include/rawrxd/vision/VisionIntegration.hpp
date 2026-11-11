#pragma once

#include "rawrxd/vision/ImageLoader.hpp"
#include "rawrxd/vision/ImagePreprocessor.hpp"
#include "rawrxd/vision/VisionEncoder.hpp"
#include "rawrxd/vision/EmbeddingProjector.hpp"
#include "rawrxd/inference/InferenceEngine.hpp"
#include <memory>
#include <functional>

namespace rawrxd {
namespace vision {

// Vision integration configuration
struct VisionIntegrationConfig {
    // Encoder settings
    std::string encoderType = "clip";
    std::string encoderModelPath;
    VisionEncoderConfig encoderConfig;
    
    // Preprocessing settings
    PreprocessConfig preprocessConfig;
    
    // Projection settings
    ProjectionConfig projectionConfig;
    std::string projectorModelPath;
    
    // Integration settings
    int maxImages = 1;              // Max images per prompt
    std::string imageToken = "<image>";  // Token to replace with vision embeddings
    int visionTokenStartId = -1;    // Special token ID for vision start
    int visionTokenEndId = -1;      // Special token ID for vision end
    
    // Performance
    bool cacheEmbeddings = true;    // Cache vision embeddings
    bool asyncEncoding = false;     // Encode images asynchronously
};

// Vision-enhanced inference request
struct VisionInferenceRequest {
    std::string text;                           // Text prompt
    std::vector<std::string> imagePaths;          // Paths to images
    std::vector<ImageData> imageData;           // Or direct image data
    bool useImages = false;
    
    // Generation parameters
    int maxTokens = 512;
    float temperature = 0.7f;
    float topP = 0.9f;
    int topK = 40;
};

// Vision-enhanced inference response
struct VisionInferenceResponse {
    std::string text;                           // Generated text
    std::vector<float> visionEmbeddings;        // Vision embeddings used
    int numVisionTokens = 0;
    int numTextTokens = 0;
    float inferenceTimeMs = 0.0f;
    bool success = false;
    std::string errorMessage;
};

// Main vision integration class
class VisionIntegration {
public:
    VisionIntegration();
    ~VisionIntegration();

    // Initialize vision pipeline
    bool Initialize(const VisionIntegrationConfig& config);
    
    // Check if initialized
    bool IsInitialized() const { return initialized_; }
    
    // Process image and get embeddings
    ProjectedEmbeddings ProcessImage(const std::string& imagePath);
    ProjectedEmbeddings ProcessImage(const ImageData& image);
    
    // Process multiple images
    std::vector<ProjectedEmbeddings> ProcessImages(const std::vector<std::string>& imagePaths);
    
    // Create multimodal input for inference
    MultimodalTokens CreateMultimodalInput(
        const std::string& text,
        const std::vector<ProjectedEmbeddings>& visionEmbeddings);
    
    // Vision-enhanced inference
    VisionInferenceResponse Generate(const VisionInferenceRequest& request);
    
    // Streaming generation with vision
    using VisionTokenCallback = std::function<void(const std::string& token, bool isComplete)>;
    bool GenerateStreaming(const VisionInferenceRequest& request, VisionTokenCallback callback);
    
    // Get configuration
    const VisionIntegrationConfig& GetConfig() const { return config_; }
    
    // Get components
    ImageLoader* GetImageLoader() { return imageLoader_.get(); }
    ImagePreprocessor* GetPreprocessor() { return preprocessor_.get(); }
    VisionEncoder* GetEncoder() { return encoder_.get(); }
    EmbeddingProjector* GetProjector() { return projector_.get(); }
    
    // Get last error
    std::string GetLastError() const { return lastError_; }
    
    // Benchmarking
    struct BenchmarkResult {
        float imageLoadTimeMs = 0.0f;
        float preprocessTimeMs = 0.0f;
        float encodeTimeMs = 0.0f;
        float projectTimeMs = 0.0f;
        float totalVisionTimeMs = 0.0f;
        float inferenceTimeMs = 0.0f;
        int outputTokens = 0;
        float tokensPerSecond = 0.0f;
    };
    BenchmarkResult Benchmark(const std::string& imagePath, const std::string& prompt);

private:
    VisionIntegrationConfig config_;
    bool initialized_ = false;
    std::string lastError_;
    
    // Pipeline components
    std::unique_ptr<ImageLoader> imageLoader_;
    std::unique_ptr<ImagePreprocessor> preprocessor_;
    std::unique_ptr<VisionEncoder> encoder_;
    std::unique_ptr<EmbeddingProjector> projector_;
    
    // Embedding cache
    std::unordered_map<std::string, ProjectedEmbeddings> embeddingCache_;
    
    // Internal methods
    bool InitializeComponents();
    ProjectedEmbeddings ProcessImageInternal(const ImageData& image);
    std::string ReplaceImageTokens(const std::string& text, int numImages);
};

// Factory for creating vision-integrated inference
class VisionInferenceFactory {
public:
    // Create vision integration with default settings
    static std::unique_ptr<VisionIntegration> CreateDefault(
        const std::string& encoderPath,
        const std::string& projectorPath);
    
    // Create with custom configuration
    static std::unique_ptr<VisionIntegration> Create(
        const VisionIntegrationConfig& config);
    
    // Create CLIP-based vision integration
    static std::unique_ptr<VisionIntegration> CreateCLIP(
        const std::string& clipModelPath,
        const std::string& projectorPath);
    
    // Create SigLIP-based vision integration
    static std::unique_ptr<VisionIntegration> CreateSigLIP(
        const std::string& siglipModelPath,
        const std::string& projectorPath);
};

// Vision model compatibility checker
class VisionCompatibilityChecker {
public:
    struct CheckResult {
        bool compatible = false;
        std::string encoderType;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
        std::vector<std::string> recommendations;
    };
    
    static CheckResult CheckEncoder(const std::string& ggufPath);
    static CheckResult CheckProjector(const std::string& ggufPath);
    static CheckResult CheckFullPipeline(
        const std::string& encoderPath,
        const std::string& projectorPath);
};

} // namespace vision
} // namespace rawrxd
