#include "rawrxd/vision/ImageLoader.hpp"
#include <fstream>
#include <algorithm>
#include <cstring>

namespace rawrxd {
namespace vision {

ImageLoader::ImageLoader() = default;

ImageData ImageLoader::LoadFromFile(const std::string& path, const ImageLoadOptions& options) {
    // Read file into buffer
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        lastError_ = "Failed to open file: " + path;
        return ImageData();
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    file.close();
    
    return LoadFromMemory(buffer, options);
}

ImageData ImageLoader::LoadFromMemory(const std::vector<uint8_t>& buffer, const ImageLoadOptions& options) {
    if (buffer.empty()) {
        lastError_ = "Empty buffer";
        return ImageData();
    }
    
    ImageFormat format = DetectFormatFromBuffer(buffer);
    
    switch (format) {
        case ImageFormat::PNG:
            return DecodePNG(buffer, options);
        case ImageFormat::JPEG:
            return DecodeJPEG(buffer, options);
        case ImageFormat::BMP:
            return DecodeBMP(buffer, options);
        default:
            lastError_ = "Unsupported image format";
            return ImageData();
    }
}

ImageData ImageLoader::LoadFromRaw(const uint8_t* data, size_t size, const ImageLoadOptions& options) {
    std::vector<uint8_t> buffer(data, data + size);
    return LoadFromMemory(buffer, options);
}

ImageFormat ImageLoader::DetectFormat(const std::string& path) {
    size_t dotPos = path.find_last_of('.');
    if (dotPos == std::string::npos) {
        return ImageFormat::UNKNOWN;
    }
    
    std::string ext = path.substr(dotPos + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    
    if (ext == "png") return ImageFormat::PNG;
    if (ext == "jpg" || ext == "jpeg") return ImageFormat::JPEG;
    if (ext == "bmp") return ImageFormat::BMP;
    if (ext == "webp") return ImageFormat::WEBP;
    
    return ImageFormat::UNKNOWN;
}

ImageFormat ImageLoader::DetectFormatFromBuffer(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 4) {
        return ImageFormat::UNKNOWN;
    }
    
    // PNG signature: 89 50 4E 47
    if (buffer[0] == 0x89 && buffer[1] == 0x50 && buffer[2] == 0x4E && buffer[3] == 0x47) {
        return ImageFormat::PNG;
    }
    
    // JPEG signature: FF D8 FF
    if (buffer[0] == 0xFF && buffer[1] == 0xD8 && buffer[2] == 0xFF) {
        return ImageFormat::JPEG;
    }
    
    // BMP signature: BM
    if (buffer[0] == 0x42 && buffer[1] == 0x4D) {
        return ImageFormat::BMP;
    }
    
    // WebP signature: RIFF....WEBP
    if (buffer.size() >= 12 && buffer[0] == 0x52 && buffer[1] == 0x49 && 
        buffer[2] == 0x46 && buffer[3] == 0x46 &&
        buffer[8] == 0x57 && buffer[9] == 0x45 && buffer[10] == 0x42 && buffer[11] == 0x50) {
        return ImageFormat::WEBP;
    }
    
    return ImageFormat::UNKNOWN;
}

ImageData ImageLoader::DecodePNG(const std::vector<uint8_t>& buffer, const ImageLoadOptions& options) {
    // Placeholder - would use libpng or similar
    // For now, return empty data
    lastError_ = "PNG decoding not yet implemented";
    return ImageData();
}

ImageData ImageLoader::DecodeJPEG(const std::vector<uint8_t>& buffer, const ImageLoadOptions& options) {
    // Placeholder - would use libjpeg-turbo or similar
    lastError_ = "JPEG decoding not yet implemented";
    return ImageData();
}

ImageData ImageLoader::DecodeBMP(const std::vector<uint8_t>& buffer, const ImageLoadOptions& options) {
    // BMP is simple enough to implement basic support
    if (buffer.size() < 54) {
        lastError_ = "Invalid BMP file";
        return ImageData();
    }
    
    // BMP header parsing
    int width = *reinterpret_cast<const int*>(&buffer[18]);
    int height = *reinterpret_cast<const int*>(&buffer[22]);
    short bpp = *reinterpret_cast<const short*>(&buffer[28]);
    int offset = *reinterpret_cast<const int*>(&buffer[10]);
    
    ImageData image;
    image.width = width;
    image.height = std::abs(height);
    image.channels = bpp / 8;
    image.format = ImageFormat::BMP;
    
    // Read pixel data
    int rowSize = ((width * image.channels + 3) / 4) * 4;  // Padded to 4 bytes
    image.data.resize(width * image.height * image.channels);
    
    for (int y = 0; y < image.height; ++y) {
        int srcY = height > 0 ? (image.height - 1 - y) : y;  // BMP is bottom-up
        int srcOffset = offset + srcY * rowSize;
        int dstOffset = y * width * image.channels;
        
        for (int x = 0; x < width * image.channels; ++x) {
            image.data[dstOffset + x] = buffer[srcOffset + x];
        }
    }
    
    // Apply resize if needed
    if (options.targetWidth > 0 && options.targetHeight > 0) {
        return ResizeImage(image, options.targetWidth, options.targetHeight, options.maintainAspectRatio);
    }
    
    return image;
}

ImageData ImageLoader::ResizeImage(const ImageData& source, int targetWidth, int targetHeight, bool maintainAspect) {
    // Simple bilinear resize
    ImageData result;
    result.width = targetWidth;
    result.height = targetHeight;
    result.channels = source.channels;
    result.format = source.format;
    result.data.resize(targetWidth * targetHeight * source.channels);
    
    float xRatio = static_cast<float>(source.width) / targetWidth;
    float yRatio = static_cast<float>(source.height) / targetHeight;
    
    for (int y = 0; y < targetHeight; ++y) {
        for (int x = 0; x < targetWidth; ++x) {
            float srcX = x * xRatio;
            float srcY = y * yRatio;
            
            int x0 = static_cast<int>(srcX);
            int y0 = static_cast<int>(srcY);
            int x1 = std::min(x0 + 1, source.width - 1);
            int y1 = std::min(y0 + 1, source.height - 1);
            
            float fx = srcX - x0;
            float fy = srcY - y0;
            
            for (int c = 0; c < source.channels; ++c) {
                float v00 = source.data[(y0 * source.width + x0) * source.channels + c];
                float v01 = source.data[(y0 * source.width + x1) * source.channels + c];
                float v10 = source.data[(y1 * source.width + x0) * source.channels + c];
                float v11 = source.data[(y1 * source.width + x1) * source.channels + c];
                
                float v0 = v00 * (1 - fx) + v01 * fx;
                float v1 = v10 * (1 - fx) + v11 * fx;
                float v = v0 * (1 - fy) + v1 * fy;
                
                result.data[(y * targetWidth + x) * source.channels + c] = static_cast<uint8_t>(v);
            }
        }
    }
    
    return result;
}

bool ImageLoader::IsFormatSupported(ImageFormat format) {
    return format == ImageFormat::PNG || 
           format == ImageFormat::JPEG || 
           format == ImageFormat::BMP;
}

bool ImageLoader::IsFormatSupported(const std::string& extension) {
    std::string ext = extension;
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return ext == "png" || ext == "jpg" || ext == "jpeg" || ext == "bmp";
}

std::vector<std::string> ImageLoader::GetSupportedFormats() {
    return {"png", "jpg", "jpeg", "bmp"};
}

// BatchImageLoader implementation
std::vector<ImageData> BatchImageLoader::LoadBatch(const std::vector<std::string>& paths, 
                                                    const ImageLoadOptions& options) {
    std::vector<ImageData> results;
    results.reserve(paths.size());
    
    ImageLoader loader;
    for (const auto& path : paths) {
        results.push_back(loader.LoadFromFile(path, options));
    }
    
    return results;
}

std::vector<ImageData> BatchImageLoader::LoadBatch(const std::vector<std::string>& paths,
                                                  ProgressCallback callback,
                                                  const ImageLoadOptions& options) {
    std::vector<ImageData> results;
    results.reserve(paths.size());
    
    ImageLoader loader;
    for (size_t i = 0; i < paths.size(); ++i) {
        results.push_back(loader.LoadFromFile(paths[i], options));
        if (callback) {
            callback(static_cast<int>(i) + 1, static_cast<int>(paths.size()), paths[i]);
        }
    }
    
    return results;
}

} // namespace vision
} // namespace rawrxd
