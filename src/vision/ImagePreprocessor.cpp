#include "rawrxd/vision/ImagePreprocessor.hpp"
#include <cmath>
#include <algorithm>

namespace rawrxd {
namespace vision {

ImagePreprocessor::ImagePreprocessor() = default;

ImagePreprocessor::ImagePreprocessor(const PreprocessConfig& config) : config_(config) {}

ImageTensor ImagePreprocessor::Preprocess(const ImageData& image) {
    if (!image.IsValid()) {
        return ImageTensor();
    }
    
    // Step 1: Resize and crop
    ImageData resized = ResizeAndCrop(image);
    
    // Step 2: Convert to RGB if needed
    if (config_.convertToRGB && resized.channels != 3) {
        resized = ConvertToRGB(resized);
    }
    
    // Step 3: Normalize
    ImageTensor tensor = Normalize(resized);
    
    tensor.width = resized.width;
    tensor.height = resized.height;
    tensor.channels = resized.channels;
    tensor.numPatches = config_.GetNumPatches();
    
    return tensor;
}

ImageTensor ImagePreprocessor::PreprocessFile(const std::string& path) {
    ImageLoader loader;
    ImageLoadOptions options;
    options.targetWidth = config_.targetSize;
    options.targetHeight = config_.targetSize;
    options.targetChannels = 3;
    options.maintainAspectRatio = true;
    
    ImageData image = loader.LoadFromFile(path, options);
    return Preprocess(image);
}

std::vector<ImageTensor> ImagePreprocessor::PreprocessBatch(const std::vector<ImageData>& images) {
    std::vector<ImageTensor> results;
    results.reserve(images.size());
    
    for (const auto& image : images) {
        results.push_back(Preprocess(image));
    }
    
    return results;
}

ImageData ImagePreprocessor::ResizeAndCrop(const ImageData& image) {
    ImageData result;
    result.channels = image.channels;
    result.format = image.format;
    
    if (config_.centerCrop) {
        // Center crop to maintain aspect ratio
        int cropSize = std::min(image.width, image.height);
        int cropX = (image.width - cropSize) / 2;
        int cropY = (image.height - cropSize) / 2;
        
        // Crop first
        ImageData cropped;
        cropped.width = cropSize;
        cropped.height = cropSize;
        cropped.channels = image.channels;
        cropped.format = image.format;
        cropped.data.resize(cropSize * cropSize * image.channels);
        
        for (int y = 0; y < cropSize; ++y) {
            for (int x = 0; x < cropSize; ++x) {
                int srcIdx = ((cropY + y) * image.width + (cropX + x)) * image.channels;
                int dstIdx = (y * cropSize + x) * image.channels;
                for (int c = 0; c < image.channels; ++c) {
                    cropped.data[dstIdx + c] = image.data[srcIdx + c];
                }
            }
        }
        
        // Then resize to target
        result.width = config_.targetSize;
        result.height = config_.targetSize;
        result.data.resize(result.width * result.height * image.channels);
        
        // Simple bilinear resize
        float xRatio = static_cast<float>(cropSize) / config_.targetSize;
        float yRatio = static_cast<float>(cropSize) / config_.targetSize;
        
        for (int y = 0; y < config_.targetSize; ++y) {
            for (int x = 0; x < config_.targetSize; ++x) {
                float srcX = x * xRatio;
                float srcY = y * yRatio;
                
                int x0 = static_cast<int>(srcX);
                int y0 = static_cast<int>(srcY);
                int x1 = std::min(x0 + 1, cropSize - 1);
                int y1 = std::min(y0 + 1, cropSize - 1);
                
                float fx = srcX - x0;
                float fy = srcY - y0;
                
                for (int c = 0; c < image.channels; ++c) {
                    float v00 = cropped.data[(y0 * cropSize + x0) * image.channels + c];
                    float v01 = cropped.data[(y0 * cropSize + x1) * image.channels + c];
                    float v10 = cropped.data[(y1 * cropSize + x0) * image.channels + c];
                    float v11 = cropped.data[(y1 * cropSize + x1) * image.channels + c];
                    
                    float v0 = v00 * (1 - fx) + v01 * fx;
                    float v1 = v10 * (1 - fx) + v11 * fx;
                    float v = v0 * (1 - fy) + v1 * fy;
                    
                    result.data[(y * config_.targetSize + x) * image.channels + c] = static_cast<uint8_t>(v);
                }
            }
        }
    } else {
        // Direct resize
        result.width = config_.targetSize;
        result.height = config_.targetSize;
        result.data.resize(result.width * result.height * image.channels);
        
        float xRatio = static_cast<float>(image.width) / config_.targetSize;
        float yRatio = static_cast<float>(image.height) / config_.targetSize;
        
        for (int y = 0; y < config_.targetSize; ++y) {
            for (int x = 0; x < config_.targetSize; ++x) {
                int srcX = static_cast<int>(x * xRatio);
                int srcY = static_cast<int>(y * yRatio);
                srcX = std::min(srcX, image.width - 1);
                srcY = std::min(srcY, image.height - 1);
                
                int srcIdx = (srcY * image.width + srcX) * image.channels;
                int dstIdx = (y * config_.targetSize + x) * image.channels;
                
                for (int c = 0; c < image.channels; ++c) {
                    result.data[dstIdx + c] = image.data[srcIdx + c];
                }
            }
        }
    }
    
    return result;
}

ImageData ImagePreprocessor::ConvertToRGB(const ImageData& image) {
    if (image.channels == 3) {
        return image;
    }
    
    ImageData result;
    result.width = image.width;
    result.height = image.height;
    result.channels = 3;
    result.format = image.format;
    result.data.resize(image.width * image.height * 3);
    
    if (image.channels == 4) {
        // RGBA to RGB
        for (int i = 0; i < image.width * image.height; ++i) {
            result.data[i * 3 + 0] = image.data[i * 4 + 0];
            result.data[i * 3 + 1] = image.data[i * 4 + 1];
            result.data[i * 3 + 2] = image.data[i * 4 + 2];
        }
    } else if (image.channels == 1) {
        // Grayscale to RGB
        for (int i = 0; i < image.width * image.height; ++i) {
            result.data[i * 3 + 0] = image.data[i];
            result.data[i * 3 + 1] = image.data[i];
            result.data[i * 3 + 2] = image.data[i];
        }
    }
    
    return result;
}

ImageTensor ImagePreprocessor::Normalize(const ImageData& image) {
    ImageTensor tensor;
    tensor.width = image.width;
    tensor.height = image.height;
    tensor.channels = image.channels;
    tensor.numPatches = config_.GetNumPatches();
    
    // Convert uint8 to float and normalize
    tensor.data.resize(image.width * image.height * image.channels);
    
    for (int i = 0; i < image.width * image.height; ++i) {
        for (int c = 0; c < image.channels; ++c) {
            // Normalize to [0, 1] then apply mean/std
            float pixel = static_cast<float>(image.data[i * image.channels + c]) / 255.0f;
            
            if (config_.normalize) {
                pixel = (pixel - config_.mean[c]) / config_.std[c];
            }
            
            tensor.data[i * image.channels + c] = pixel;
        }
    }
    
    return tensor;
}

// PreprocessorFactory implementation
ImagePreprocessor PreprocessorFactory::CreateCLIPPreprocessor(int imageSize) {
    PreprocessConfig config;
    config.targetSize = imageSize;
    config.patchSize = 14;
    config.mean = {0.48145466f, 0.4578275f, 0.40821073f};
    config.std = {0.26862954f, 0.26130258f, 0.27577711f};
    config.normalize = true;
    config.centerCrop = true;
    config.convertToRGB = true;
    
    return ImagePreprocessor(config);
}

ImagePreprocessor PreprocessorFactory::CreateSigLIPPreprocessor(int imageSize) {
    PreprocessConfig config;
    config.targetSize = imageSize;
    config.patchSize = 14;
    config.mean = {0.5f, 0.5f, 0.5f};
    config.std = {0.5f, 0.5f, 0.5f};
    config.normalize = true;
    config.centerCrop = true;
    config.convertToRGB = true;
    
    return ImagePreprocessor(config);
}

ImagePreprocessor PreprocessorFactory::CreateLLaVAPreprocessor(int imageSize) {
    PreprocessConfig config;
    config.targetSize = imageSize;
    config.patchSize = 14;
    config.mean = {0.48145466f, 0.4578275f, 0.40821073f};
    config.std = {0.26862954f, 0.26130258f, 0.27577711f};
    config.normalize = true;
    config.centerCrop = true;
    config.convertToRGB = true;
    
    return ImagePreprocessor(config);
}

ImagePreprocessor PreprocessorFactory::CreatePhi3VisionPreprocessor(int imageSize) {
    PreprocessConfig config;
    config.targetSize = imageSize;
    config.patchSize = 14;
    config.mean = {0.48145466f, 0.4578275f, 0.40821073f};
    config.std = {0.26862954f, 0.26130258f, 0.27577711f};
    config.normalize = true;
    config.centerCrop = true;
    config.convertToRGB = true;
    
    return ImagePreprocessor(config);
}

ImagePreprocessor PreprocessorFactory::CreateCustom(const PreprocessConfig& config) {
    return ImagePreprocessor(config);
}

} // namespace vision
} // namespace rawrxd
