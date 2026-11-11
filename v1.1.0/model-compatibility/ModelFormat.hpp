// RawrXD Sovereign v1.1.0 - Model Compatibility Framework
// ModelFormat.hpp - Model format definitions

#pragma once

#include <string>
#include <vector>
#include <optional>

namespace RawrXD {
namespace ModelCompatibility {

// Supported model formats
enum class ModelFormat {
    UNKNOWN,        // Unknown or unsupported format
    GGUF,           // GGUF format (llama.cpp)
    ONNX,           // ONNX format
    TENSORRT,       // TensorRT engine
    PYTORCH,        // PyTorch checkpoint
    SAFETENSORS,    // Safetensors format
    CUSTOM          // Custom/proprietary format
};

// Format information
struct FormatInfo {
    ModelFormat format;
    std::string name;
    std::string description;
    std::vector<std::string> extensions;
    std::vector<uint8_t> magic_bytes;
    bool readable;      // Can read from this format
    bool writable;      // Can write to this format
    bool requires_gpu;  // Requires GPU for inference
    
    FormatInfo() : format(ModelFormat::UNKNOWN), readable(false), writable(false), requires_gpu(false) {}
};

// Format utilities
namespace ModelFormatUtils {
    // Get format info
    FormatInfo GetFormatInfo(ModelFormat format);
    
    // Convert format to string
    std::string FormatToString(ModelFormat format);
    
    // Parse format from string
    ModelFormat StringToFormat(const std::string& str);
    
    // Detect format from file extension
    ModelFormat DetectFromExtension(const std::string& path);
    
    // Detect format from file content (magic bytes)
    ModelFormat DetectFromContent(const std::vector<uint8_t>& header);
    
    // Get all supported formats
    std::vector<FormatInfo> GetAllFormats();
    
    // Get formats by capability
    std::vector<FormatInfo> GetReadableFormats();
    std::vector<FormatInfo> GetWritableFormats();
    std::vector<FormatInfo> GetGPUFormats();
    
    // Check if format is supported
    bool IsFormatSupported(ModelFormat format);
    bool IsFormatSupported(const std::string& extension);
}

// Format detection result
struct FormatDetectionResult {
    ModelFormat format;
    float confidence;  // 0.0 - 1.0
    std::string reason;
    
    FormatDetectionResult() : format(ModelFormat::UNKNOWN), confidence(0.0f) {}
};

// Format detector
class FormatDetector {
public:
    FormatDetector();
    ~FormatDetector();
    
    // Detect format from file
    FormatDetectionResult Detect(const std::string& path);
    
    // Detect from file content
    FormatDetectionResult DetectFromData(const std::vector<uint8_t>& data);
    
    // Add custom detection rule
    void AddDetectionRule(ModelFormat format, 
                          const std::vector<std::string>& extensions,
                          const std::vector<uint8_t>& magic);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Format conversion info
struct ConversionPath {
    ModelFormat source;
    ModelFormat target;
    bool direct;           // Direct conversion available
    std::vector<ModelFormat> intermediate;  // Intermediate formats if not direct
    bool lossless;         // Lossless conversion
    std::string notes;     // Additional notes
    
    ConversionPath() : source(ModelFormat::UNKNOWN), target(ModelFormat::UNKNOWN), 
                       direct(false), lossless(false) {}
};

// Conversion utilities
namespace ConversionUtils {
    // Check if conversion is possible
    bool CanConvert(ModelFormat from, ModelFormat to);
    
    // Get conversion path
    std::optional<ConversionPath> GetConversionPath(ModelFormat from, ModelFormat to);
    
    // Get all possible conversions from a format
    std::vector<ConversionPath> GetPossibleConversions(ModelFormat from);
    
    // Estimate conversion quality
    float EstimateConversionQuality(ModelFormat from, ModelFormat to);
}

} // namespace ModelCompatibility
} // namespace RawrXD
