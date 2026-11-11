// Phase M.2/5: Multi-Modal Support - Vision
// RawrXD Vision Processor - Image understanding capabilities

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <variant>

namespace RawrXD {
namespace Multimodal {

// Image formats
enum class ImageFormat {
    RGB,           // 3 channels, 8-bit
    RGBA,          // 4 channels, 8-bit
    BGR,           // 3 channels, 8-bit (OpenCV style)
    BGRA,          // 4 channels, 8-bit
    GRAYSCALE,     // 1 channel, 8-bit
    FLOAT_RGB,     // 3 channels, 32-bit float
    FLOAT_RGBA     // 4 channels, 32-bit float
};

// Image data container
struct Image {
    std::vector<uint8_t> data;
    uint32_t width;
    uint32_t height;
    ImageFormat format;
    std::string source;  // URL, file path, or "base64"
    
    // Helper methods
    size_t GetChannels() const;
    size_t GetBytesPerPixel() const;
    size_t GetDataSize() const { return data.size(); }
    bool IsValid() const { return width > 0 && height > 0 && !data.empty(); }
    
    // Convert to model input format
    std::vector<float> ToFloatTensor() const;
    std::vector<float> Normalize(float mean[3], float std[3]) const;
};

// Vision encoding options
struct VisionEncodeOptions {
    uint32_t target_width = 224;           // Target width for resize
    uint32_t target_height = 224;          // Target height for resize
    ImageFormat target_format = ImageFormat::RGB;
    bool maintain_aspect_ratio = true;     // Use letterboxing
    std::string interpolation = "bilinear"; // Resize interpolation
    bool normalize = true;                 // Apply normalization
    float mean[3] = {0.48145466f, 0.4578275f, 0.40821073f};  // CLIP defaults
    float std[3] = {0.26862954f, 0.26130258f, 0.27577711f};
    uint32_t patch_size = 14;              // Vision transformer patch size
};

// Vision model types
enum class VisionModelType {
    CLIP_VIT_BASE,         // CLIP ViT-B/14
    CLIP_VIT_LARGE,        // CLIP ViT-L/14
    CLIP_VIT_HUGE,         // CLIP ViT-H/14
    LLAVA_7B,              // LLaVA 7B
    LLAVA_13B,             // LLaVA 13B
    BAKLLAVA,              // BakLLaVA
    MOONDREAM,             // Moondream (small)
    CUSTOM                 // Custom vision model
};

// Vision encoder output
struct VisionEmbedding {
    std::vector<float> embeddings;       // Image embeddings
    std::vector<uint32_t> image_tokens; // Tokenized representation
    uint32_t num_patches;                 // Number of image patches
    float processing_time_ms;             // Processing time
    bool success;
    std::string error_message;
};

// Vision processor interface
class IVisionProcessor {
public:
    virtual ~IVisionProcessor() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& model_path, VisionModelType type) = 0;
    virtual void Shutdown() = 0;
    
    // Image encoding
    virtual VisionEmbedding EncodeImage(const Image& image) = 0;
    virtual VisionEmbedding EncodeImage(const Image& image, const VisionEncodeOptions& options) = 0;
    
    // Batch processing
    virtual std::vector<VisionEmbedding> EncodeImages(const std::vector<Image>& images) = 0;
    virtual std::vector<VisionEmbedding> EncodeImages(const std::vector<Image>& images, 
                                                          const VisionEncodeOptions& options) = 0;
    
    // Image preprocessing
    virtual Image PreprocessImage(const Image& input, const VisionEncodeOptions& options) = 0;
    
    // Utility functions
    virtual Image LoadImage(const std::string& path) = 0;
    virtual Image LoadImageFromBase64(const std::string& base64) = 0;
    virtual Image LoadImageFromURL(const std::string& url) = 0;
    virtual bool SaveImage(const Image& image, const std::string& path) = 0;
    
    // Information
    virtual VisionModelType GetModelType() const = 0;
    virtual std::string GetModelVersion() const = 0;
    virtual uint32_t GetEmbeddingDimension() const = 0;
    virtual bool IsInitialized() const = 0;
    
    // Memory management
    virtual size_t GetMemoryUsage() const = 0;
    virtual void ClearCache() = 0;
};

// Vision-Language model interface (for models like LLaVA)
class IVisionLanguageModel {
public:
    virtual ~IVisionLanguageModel() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& model_path) = 0;
    virtual void Shutdown() = 0;
    
    // Multi-modal inference
    struct MultimodalRequest {
        std::string text_prompt;
        std::vector<Image> images;
        uint32_t max_tokens = 512;
        float temperature = 0.7f;
        std::string stop_sequence;
    };
    
    struct MultimodalResponse {
        std::string generated_text;
        std::vector<float> logits;
        uint32_t tokens_generated;
        float processing_time_ms;
        bool success;
        std::string error_message;
    };
    
    virtual MultimodalResponse Generate(const MultimodalRequest& request) = 0;
    
    // Streaming generation
    using TokenCallback = std::function<bool(const std::string& token)>;
    virtual bool GenerateStreaming(const MultimodalRequest& request, TokenCallback callback) = 0;
    
    // Information
    virtual bool IsInitialized() const = 0;
    virtual size_t GetMemoryUsage() const = 0;
};

// Vision processor factory
class VisionProcessorFactory {
public:
    static std::unique_ptr<IVisionProcessor> CreateProcessor(VisionModelType type);
    static std::unique_ptr<IVisionLanguageModel> CreateVisionLanguageModel(const std::string& model_type);
    static bool IsModelAvailable(VisionModelType type);
    static std::vector<VisionModelType> GetAvailableModels();
};

// Image utilities
class ImageUtils {
public:
    // Format conversion
    static Image ConvertFormat(const Image& input, ImageFormat target_format);
    
    // Resizing
    static Image Resize(const Image& input, uint32_t width, uint32_t height, 
                        const std::string& interpolation = "bilinear");
    
    // Letterboxing (maintain aspect ratio)
    static Image Letterbox(const Image& input, uint32_t target_width, uint32_t target_height,
                           const uint8_t fill_color[3] = nullptr);
    
    // Center crop
    static Image CenterCrop(const Image& input, uint32_t crop_width, uint32_t crop_height);
    
    // Normalization
    static std::vector<float> Normalize(const Image& input, 
                                            const float mean[3], 
                                            const float std[3]);
    
    // Augmentation
    static Image HorizontalFlip(const Image& input);
    static Image Rotate(const Image& input, float degrees);
    static Image AdjustBrightness(const Image& input, float factor);
    static Image AdjustContrast(const Image& input, float factor);
    
    // Validation
    static bool ValidateImage(const Image& image);
    static bool IsSupportedFormat(ImageFormat format);
    
    // Information
    static std::string FormatToString(ImageFormat format);
    static size_t GetFormatChannels(ImageFormat format);
    static size_t GetFormatBytesPerChannel(ImageFormat format);
};

// Vision configuration
struct VisionConfig {
    bool enabled = false;
    VisionModelType default_model = VisionModelType::CLIP_VIT_BASE;
    std::string model_path;
    uint32_t max_image_size = 4096;      // Max dimension
    uint32_t batch_size = 4;
    bool use_gpu = true;
    uint32_t gpu_device = 0;
    uint32_t num_threads = 4;
    bool cache_embeddings = true;
    size_t cache_size_mb = 512;
};

// Global vision configuration
extern VisionConfig g_vision_config;

// Initialize vision subsystem
bool InitializeVision(const VisionConfig& config);
void ShutdownVision();
bool IsVisionEnabled();

} // namespace Multimodal
} // namespace RawrXD
