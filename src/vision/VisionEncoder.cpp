#include "rawrxd/vision/VisionEncoder.hpp"
#include <cmath>
#include <algorithm>

namespace rawrxd {
namespace vision {

// VisionEncoderOutput implementation
std::vector<float> VisionEncoderOutput::GetPooled() const {
    if (!classEmbedding.empty()) {
        return classEmbedding;
    }
    
    // Return mean of patch embeddings
    std::vector<float> mean(hiddenSize, 0.0f);
    int numPatches = patchEmbeddings.size() / hiddenSize;
    
    for (int i = 0; i < numPatches; ++i) {
        for (int j = 0; j < hiddenSize; ++j) {
            mean[j] += patchEmbeddings[i * hiddenSize + j];
        }
    }
    
    for (int j = 0; j < hiddenSize; ++j) {
        mean[j] /= numPatches;
    }
    
    return mean;
}

// CLIPVisionEncoder implementation
CLIPVisionEncoder::CLIPVisionEncoder() = default;

bool CLIPVisionEncoder::Initialize(const VisionEncoderConfig& config) {
    config_ = config;
    
    // Validate configuration
    if (config_.imageSize <= 0 || config_.patchSize <= 0) {
        lastError_ = "Invalid image or patch size";
        return false;
    }
    
    if (config_.hiddenSize <= 0 || config_.numLayers <= 0) {
        lastError_ = "Invalid hidden size or layer count";
        return false;
    }
    
    initialized_ = true;
    return true;
}

bool CLIPVisionEncoder::LoadWeights(const std::string& ggufPath) {
    if (!initialized_) {
        lastError_ = "Encoder not initialized";
        return false;
    }
    
    // Would load weights from GGUF file
    // Placeholder implementation
    lastError_ = "Weight loading not yet implemented";
    return false;
}

VisionEncoderOutput CLIPVisionEncoder::Encode(const ImageTensor& image) {
    if (!initialized_) {
        VisionEncoderOutput output;
        return output;
    }
    
    return EncodeInternal(image);
}

std::vector<VisionEncoderOutput> CLIPVisionEncoder::EncodeBatch(const std::vector<ImageTensor>& images) {
    std::vector<VisionEncoderOutput> outputs;
    outputs.reserve(images.size());
    
    for (const auto& image : images) {
        outputs.push_back(Encode(image));
    }
    
    return outputs;
}

VisionEncoderOutput CLIPVisionEncoder::EncodeInternal(const ImageTensor& image) {
    VisionEncoderOutput output;
    output.hiddenSize = config_.hiddenSize;
    
    // Step 1: Patch embedding
    std::vector<float> patches = PatchEmbedding(image);
    
    // Step 2: Add position embeddings
    std::vector<float> embeddings = AddPositionEmbeddings(patches);
    
    // Step 3: Transformer encoding
    output.embeddings = TransformerEncoder(embeddings);
    
    // Extract class token and patch embeddings
    if (config_.useClassToken && !output.embeddings.empty()) {
        output.classEmbedding.assign(output.embeddings.begin(), 
                                     output.embeddings.begin() + config_.hiddenSize);
    }
    
    int numPatches = config_.GetNumPatches();
    int patchStart = config_.useClassToken ? config_.hiddenSize : 0;
    output.patchEmbeddings.assign(output.embeddings.begin() + patchStart,
                                  output.embeddings.end());
    output.numPatches = numPatches;
    
    return output;
}

std::vector<float> CLIPVisionEncoder::PatchEmbedding(const ImageTensor& image) {
    int numPatches = config_.GetNumPatches();
    int patchDim = config_.GetPatchDim();
    
    std::vector<float> patches(numPatches * patchDim);
    
    int patchesPerRow = config_.imageSize / config_.patchSize;
    
    for (int py = 0; py < patchesPerRow; ++py) {
        for (int px = 0; px < patchesPerRow; ++px) {
            int patchIdx = py * patchesPerRow + px;
            
            // Extract patch
            for (int y = 0; y < config_.patchSize; ++y) {
                for (int x = 0; x < config_.patchSize; ++x) {
                    int imgY = py * config_.patchSize + y;
                    int imgX = px * config_.patchSize + x;
                    int pixelIdx = (imgY * image.width + imgX) * image.channels;
                    
                    for (int c = 0; c < image.channels; ++c) {
                        int patchOffset = patchIdx * patchDim + (y * config_.patchSize + x) * image.channels + c;
                        patches[patchOffset] = image.data[pixelIdx + c];
                    }
                }
            }
        }
    }
    
    return patches;
}

std::vector<float> CLIPVisionEncoder::AddPositionEmbeddings(const std::vector<float>& patches) {
    int numTokens = config_.GetSequenceLength();
    std::vector<float> embeddings(numTokens * config_.hiddenSize, 0.0f);
    
    // Add class token if used
    if (config_.useClassToken) {
        // Class token is at position 0 (already zero-initialized)
        // In real implementation, would add learned class token embedding
    }
    
    // Add patch embeddings (simplified - would use learned projection)
    int patchStart = config_.useClassToken ? config_.hiddenSize : 0;
    int numPatches = config_.GetNumPatches();
    int patchDim = config_.GetPatchDim();
    
    for (int i = 0; i < numPatches && i < numPatches; ++i) {
        // Simplified: just copy first hiddenSize elements
        for (int j = 0; j < config_.hiddenSize && j < patchDim; ++j) {
            embeddings[patchStart + i * config_.hiddenSize + j] = patches[i * patchDim + j];
        }
    }
    
    // Add position embeddings (simplified)
    if (config_.usePositionEmbedding) {
        // Would add learned position embeddings
    }
    
    return embeddings;
}

std::vector<float> CLIPVisionEncoder::TransformerEncoder(const std::vector<float>& embeddings) {
    std::vector<float> output = embeddings;
    
    // Apply transformer layers
    for (int layer = 0; layer < config_.numLayers; ++layer) {
        // Layer norm
        std::vector<float> normed = LayerNorm(output);
        
        // Multi-head attention
        std::vector<float> attn = MultiHeadAttention(normed);
        
        // Residual connection
        for (size_t i = 0; i < output.size(); ++i) {
            output[i] += attn[i];
        }
        
        // Layer norm
        normed = LayerNorm(output);
        
        // MLP
        std::vector<float> mlp = MLP(normed);
        
        // Residual connection
        for (size_t i = 0; i < output.size(); ++i) {
            output[i] += mlp[i];
        }
    }
    
    // Final layer norm
    output = LayerNorm(output);
    
    return output;
}

std::vector<float> CLIPVisionEncoder::LayerNorm(const std::vector<float>& x) {
    int numTokens = x.size() / config_.hiddenSize;
    std::vector<float> output(x.size());
    
    for (int i = 0; i < numTokens; ++i) {
        // Compute mean
        float mean = 0.0f;
        for (int j = 0; j < config_.hiddenSize; ++j) {
            mean += x[i * config_.hiddenSize + j];
        }
        mean /= config_.hiddenSize;
        
        // Compute variance
        float var = 0.0f;
        for (int j = 0; j < config_.hiddenSize; ++j) {
            float diff = x[i * config_.hiddenSize + j] - mean;
            var += diff * diff;
        }
        var /= config_.hiddenSize;
        
        // Normalize
        float invStd = 1.0f / std::sqrt(var + config_.layerNormEps);
        for (int j = 0; j < config_.hiddenSize; ++j) {
            output[i * config_.hiddenSize + j] = (x[i * config_.hiddenSize + j] - mean) * invStd;
        }
    }
    
    return output;
}

std::vector<float> CLIPVisionEncoder::MultiHeadAttention(const std::vector<float>& x) {
    // Simplified attention - would use actual weight matrices
    int numTokens = x.size() / config_.hiddenSize;
    std::vector<float> output(x.size(), 0.0f);
    
    int headDim = config_.hiddenSize / config_.numHeads;
    
    for (int h = 0; h < config_.numHeads; ++h) {
        // Compute attention scores (simplified)
        for (int i = 0; i < numTokens; ++i) {
            for (int j = 0; j < numTokens; ++j) {
                float score = 0.0f;
                for (int d = 0; d < headDim; ++d) {
                    score += x[i * config_.hiddenSize + h * headDim + d] * 
                             x[j * config_.hiddenSize + h * headDim + d];
                }
                // Would apply softmax and weighted sum
            }
        }
    }
    
    return output;
}

std::vector<float> CLIPVisionEncoder::MLP(const std::vector<float>& x) {
    int numTokens = x.size() / config_.hiddenSize;
    std::vector<float> output(x.size(), 0.0f);
    
    // Simplified MLP - would use actual weight matrices
    for (int i = 0; i < numTokens; ++i) {
        for (int j = 0; j < config_.hiddenSize; ++j) {
            // Would apply: fc1 -> activation -> fc2
            output[i * config_.hiddenSize + j] = x[i * config_.hiddenSize + j];
        }
    }
    
    return output;
}

// SigLIPVisionEncoder implementation
SigLIPVisionEncoder::SigLIPVisionEncoder() = default;

bool SigLIPVisionEncoder::Initialize(const VisionEncoderConfig& config) {
    config_ = config;
    config_.useGatedActivation = true;  // SigLIP uses gated activation
    initialized_ = true;
    return true;
}

bool SigLIPVisionEncoder::LoadWeights(const std::string& ggufPath) {
    lastError_ = "Weight loading not yet implemented";
    return false;
}

VisionEncoderOutput SigLIPVisionEncoder::Encode(const ImageTensor& image) {
    VisionEncoderOutput output;
    // Similar to CLIP but with gated activations
    return output;
}

std::vector<VisionEncoderOutput> SigLIPVisionEncoder::EncodeBatch(const std::vector<ImageTensor>& images) {
    std::vector<VisionEncoderOutput> outputs;
    for (const auto& img : images) {
        outputs.push_back(Encode(img));
    }
    return outputs;
}

// VisionEncoderFactory implementation
std::unique_ptr<VisionEncoder> VisionEncoderFactory::Create(const std::string& type) {
    if (type == "clip" || type == "CLIP") {
        return std::make_unique<CLIPVisionEncoder>();
    } else if (type == "siglip" || type == "SigLIP") {
        return std::make_unique<SigLIPVisionEncoder>();
    }
    return nullptr;
}

std::unique_ptr<VisionEncoder> VisionEncoderFactory::CreateCLIP(const std::string& variant) {
    auto encoder = std::make_unique<CLIPVisionEncoder>();
    
    VisionEncoderConfig config;
    config.modelType = "clip";
    
    if (variant == "base") {
        config.imageSize = 224;
        config.patchSize = 14;
        config.hiddenSize = 768;
        config.numLayers = 12;
        config.numHeads = 12;
        config.intermediateSize = 3072;
    } else if (variant == "large") {
        config.imageSize = 224;
        config.patchSize = 14;
        config.hiddenSize = 1024;
        config.numLayers = 24;
        config.numHeads = 16;
        config.intermediateSize = 4096;
    }
    
    encoder->Initialize(config);
    return encoder;
}

std::unique_ptr<VisionEncoder> VisionEncoderFactory::CreateSigLIP(const std::string& variant) {
    auto encoder = std::make_unique<SigLIPVisionEncoder>();
    
    VisionEncoderConfig config;
    config.modelType = "siglip";
    config.imageSize = 224;
    config.patchSize = 14;
    config.hiddenSize = 768;
    config.numLayers = 12;
    config.numHeads = 12;
    config.intermediateSize = 3072;
    config.useGatedActivation = true;
    
    encoder->Initialize(config);
    return encoder;
}

std::unique_ptr<VisionEncoder> VisionEncoderFactory::CreateFromGGUF(const std::string& ggufPath) {
    // Would detect encoder type from GGUF metadata
    auto encoder = std::make_unique<CLIPVisionEncoder>();
    if (encoder->LoadWeights(ggufPath)) {
        return encoder;
    }
    return nullptr;
}

std::vector<std::string> VisionEncoderFactory::GetSupportedTypes() {
    return {"clip", "siglip"};
}

} // namespace vision
} // namespace rawrxd
