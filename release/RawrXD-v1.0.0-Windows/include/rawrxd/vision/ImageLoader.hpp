#pragma once

#include <string>
#include <vector>
#include <memory>

namespace rawrxd {
namespace vision {

// Supported image formats
enum class ImageFormat {
    UNKNOWN,
    PNG,
    JPEG,
    BMP,
    WEBP,
    RAW
};

// Image data container
struct ImageData {
    std::vector<uint8_t> data;
    int width = 0;
    int height = 0;
    int channels = 0;
    ImageFormat format = ImageFormat::UNKNOWN;
    
    bool IsValid() const {
        return width > 0 && height > 0 && channels > 0 && !data.empty();
    }
    
    size_t GetSize() const {
        return static_cast<size_t>(width) * height * channels;
    }
};

// Image loading options
struct ImageLoadOptions {
    int targetWidth = 0;      // 0 = keep original
    int targetHeight = 0;     // 0 = keep original
    int targetChannels = 3;   // Default RGB
    bool maintainAspectRatio = true;
    bool normalize = true;    // Normalize to [0, 1] or [-1, 1]
};

// Image loader interface
class ImageLoader {
public:
    ImageLoader();
    ~ImageLoader() = default;

    // Load image from file
    ImageData LoadFromFile(const std::string& path, const ImageLoadOptions& options = ImageLoadOptions());
    
    // Load image from memory buffer
    ImageData LoadFromMemory(const std::vector<uint8_t>& buffer, const ImageLoadOptions& options = ImageLoadOptions());
    
    // Load image from raw bytes
    ImageData LoadFromRaw(const uint8_t* data, size_t size, const ImageLoadOptions& options = ImageLoadOptions());
    
    // Get last error
    std::string GetLastError() const { return lastError_; }
    
    // Check if format is supported
    static bool IsFormatSupported(ImageFormat format);
    static bool IsFormatSupported(const std::string& extension);
    
    // Get supported formats
    static std::vector<std::string> GetSupportedFormats();

private:
    std::string lastError_;
    
    // Internal helpers
    ImageFormat DetectFormat(const std::string& path);
    ImageFormat DetectFormatFromBuffer(const std::vector<uint8_t>& buffer);
    ImageData DecodePNG(const std::vector<uint8_t>& buffer, const ImageLoadOptions& options);
    ImageData DecodeJPEG(const std::vector<uint8_t>& buffer, const ImageLoadOptions& options);
    ImageData DecodeBMP(const std::vector<uint8_t>& buffer, const ImageLoadOptions& options);
    ImageData ResizeImage(const ImageData& source, int targetWidth, int targetHeight, bool maintainAspect);
};

// Batch image loader
class BatchImageLoader {
public:
    // Load multiple images
    std::vector<ImageData> LoadBatch(const std::vector<std::string>& paths, 
                                       const ImageLoadOptions& options = ImageLoadOptions());
    
    // Load with progress callback
    using ProgressCallback = std::function<void(int current, int total, const std::string& path)>;
    std::vector<ImageData> LoadBatch(const std::vector<std::string>& paths,
                                       ProgressCallback callback,
                                       const ImageLoadOptions& options = ImageLoadOptions());
};

} // namespace vision
} // namespace rawrxd
