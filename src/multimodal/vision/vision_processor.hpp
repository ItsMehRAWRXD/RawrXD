// RawrXD Vision Processor
// Phase AS: Multi-Modal Support

#pragma once

#include <vector>
#include <string>
#include <memory>
#include <functional>

namespace rawrxd {
namespace multimodal {

// Image format
enum class ImageFormat {
    RGB,
    RGBA,
    BGR,
    BGRA,
    GRAYSCALE,
    YUV
};

// Image data
struct Image {
    std::vector<uint8_t> data;
    int width;
    int height;
    int channels;
    ImageFormat format;
    
    Image() : width(0), height(0), channels(0), format(ImageFormat::RGB) {}
};

// Vision task types
enum class VisionTask {
    CLASSIFICATION,
    OBJECT_DETECTION,
    SEGMENTATION,
    OCR,
    CAPTIONING,
    VISUAL_QUESTION_ANSWERING,
    IMAGE_EMBEDDING
};

// Detection result
struct Detection {
    std::string label;
    float confidence;
    float x, y, width, height;  // Bounding box
    std::vector<std::pair<int, int>> mask;  // Segmentation mask (optional)
};

// OCR result
struct OCRResult {
    std::string text;
    float confidence;
    float x, y, width, height;  // Bounding box
};

// Vision output
struct VisionOutput {
    std::string caption;
    std::vector<Detection> detections;
    std::vector<OCRResult> ocr_results;
    std::vector<float> embedding;
    std::string answer;  // For VQA
    
    VisionOutput() = default;
};

// Vision configuration
struct VisionConfig {
    std::string model_path;
    std::string device;  // cpu, cuda, etc.
    int max_image_size;
    float confidence_threshold;
    float nms_threshold;
    bool enable_ocr;
    bool enable_segmentation;
    
    VisionConfig()
        : device("cpu")
        , max_image_size(1024)
        , confidence_threshold(0.5f)
        , nms_threshold(0.4f)
        , enable_ocr(true)
        , enable_segmentation(false) {}
};

// Forward declarations
class VisionProcessor;
class ImageEncoder;
class ObjectDetector;
class OCREngine;

/**
 * VisionProcessor - Multi-modal vision processing
 */
class VisionProcessor {
public:
    VisionProcessor();
    ~VisionProcessor();
    
    // Initialize
    bool initialize(const VisionConfig& config);
    void shutdown();
    
    // Image loading
    Image loadImage(const std::string& path);
    Image loadImageFromBuffer(const std::vector<uint8_t>& buffer);
    Image decodeBase64(const std::string& base64);
    
    // Processing
    VisionOutput process(const Image& image, VisionTask task);
    VisionOutput process(const Image& image, const std::string& prompt);  // For VQA
    
    // Batch processing
    std::vector<VisionOutput> processBatch(const std::vector<Image>& images, VisionTask task);
    
    // Specific tasks
    std::string generateCaption(const Image& image);
    std::vector<Detection> detectObjects(const Image& image);
    std::vector<OCRResult> extractText(const Image& image);
    std::vector<float> encodeImage(const Image& image);
    std::string answerQuestion(const Image& image, const std::string& question);
    
    // Utilities
    Image resize(const Image& image, int max_size);
    Image convertFormat(const Image& image, ImageFormat target_format);
    std::vector<uint8_t> encodeToBuffer(const Image& image, const std::string& format);
    std::string encodeToBase64(const Image& image, const std::string& format);
    
    // Status
    bool isInitialized() const;
    std::string getDevice() const;
    
private:
    VisionConfig config_;
    bool initialized_;
    
    std::unique_ptr<ImageEncoder> image_encoder_;
    std::unique_ptr<ObjectDetector> object_detector_;
    std::unique_ptr<OCREngine> ocr_engine_;
    
    // Internal methods
    bool preprocess(Image& image);
    VisionOutput runInference(const Image& image, VisionTask task);
};

/**
 * ImageEncoder - Encode images to embeddings
 */
class ImageEncoder {
public:
    ImageEncoder();
    ~ImageEncoder();
    
    bool initialize(const std::string& model_path, const std::string& device);
    std::vector<float> encode(const Image& image);
    std::vector<std::vector<float>> encodeBatch(const std::vector<Image>& images);
    
private:
    std::string model_path_;
    std::string device_;
    bool initialized_;
};

/**
 * ObjectDetector - Detect objects in images
 */
class ObjectDetector {
public:
    ObjectDetector();
    ~ObjectDetector();
    
    bool initialize(const std::string& model_path, const std::string& device);
    std::vector<Detection> detect(const Image& image, float confidence_threshold);
    std::vector<Detection> detectWithMasks(const Image& image, float confidence_threshold);
    
private:
    std::string model_path_;
    std::string device_;
    bool initialized_;
    
    std::vector<Detection> applyNMS(std::vector<Detection>& detections, float threshold);
};

/**
 * OCREngine - Optical Character Recognition
 */
class OCREngine {
public:
    OCREngine();
    ~OCREngine();
    
    bool initialize(const std::string& model_path, const std::string& device);
    std::vector<OCRResult> recognize(const Image& image);
    std::string recognizeText(const Image& image);
    
private:
    std::string model_path_;
    std::string device_;
    bool initialized_;
};

// Global accessor
VisionProcessor* getVisionProcessor();
void setVisionProcessor(std::unique_ptr<VisionProcessor> processor);

// Utility functions
std::string imageFormatToString(ImageFormat format);
ImageFormat stringToImageFormat(const std::string& str);
int getChannelsForFormat(ImageFormat format);

} // namespace multimodal
} // namespace rawrxd
