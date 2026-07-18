#include "rawrxd/vision/VisionIntegration.hpp"
#include <chrono>
#include <algorithm>

namespace rawrxd {
namespace vision {

VisionIntegration::VisionIntegration() = default;

VisionIntegration::~VisionIntegration() = default;

bool VisionIntegration::Initialize(const VisionIntegrationConfig& config) {
    config_ = config;
    
    if (!InitializeComponents()) {
        return false;
    }
    
    return true;
}

bool VisionIntegration::InitializeComponents() {
    // Initialize image loader
    imageLoader_ = std::make_unique<ImageLoader>();
    
    // Initialize preprocessor
    preprocessor_ = std::make_unique<ImagePreprocessor>(config_.preprocessConfig);
    
    // Initialize encoder
    encoder_ = VisionEncoderFactory::Create(config_.encoderType);
    if (!encoder_) {
        lastError_ = "Failed to create vision encoder: " + config_.encoderType;
        return false;
    }
    
    if (!encoder_->Initialize(config_.encoderConfig)) {
        lastError_ = "Failed to initialize encoder: " + encoder_->GetLastError();
        return false;
    }
    
    if (!config_.encoderModelPath.empty()) {
        if (!encoder_->LoadWeights(config_.encoderModelPath)) {
            lastError_ = "Failed to load encoder weights: " + encoder_->GetLastError();
            return false;
        }
    }
    
    // Initialize projector
    projector_ = std::make_unique<EmbeddingProjector>(config_.projectionConfig);
    if (!config_.projectorModelPath.empty()) {
        if (!projector_->LoadWeights(config_.projectorModelPath)) {
            lastError_ = "Failed to load projector weights";
            return false;
        }
    }
    
    initialized_ = true;
    return true;
}

ProjectedEmbeddings VisionIntegration::ProcessImage(const std::string& imagePath) {
    if (!initialized_) {
        return ProjectedEmbeddings();
    }
    
    // Check cache
    if (config_.cacheEmbeddings) {
        auto it = embeddingCache_.find(imagePath);
        if (it != embeddingCache_.end()) {
            return it->second;
        }
    }
    
    // Load image
    ImageData image = imageLoader_->LoadFromFile(imagePath);
    if (!image.IsValid()) {
        return ProjectedEmbeddings();
    }
    
    ProjectedEmbeddings result = ProcessImageInternal(image);
    
    // Cache result
    if (config_.cacheEmbeddings) {
        embeddingCache_[imagePath] = result;
    }
    
    return result;
}

ProjectedEmbeddings VisionIntegration::ProcessImage(const ImageData& image) {
    if (!initialized_ || !image.IsValid()) {
        return ProjectedEmbeddings();
    }
    
    return ProcessImageInternal(image);
}

std::vector<ProjectedEmbeddings> VisionIntegration::ProcessImages(const std::vector<std::string>& imagePaths) {
    std::vector<ProjectedEmbeddings> results;
    results.reserve(imagePaths.size());
    
    for (const auto& path : imagePaths) {
        results.push_back(ProcessImage(path));
    }
    
    return results;
}

ProjectedEmbeddings VisionIntegration::ProcessImageInternal(const ImageData& image) {
    // Preprocess
    ImageTensor tensor = preprocessor_->Preprocess(image);
    
    // Encode
    VisionEncoderOutput encoded = encoder_->Encode(tensor);
    
    // Project
    ProjectedEmbeddings projected = projector_->Project(encoded);
    
    return projected;
}

MultimodalTokens VisionIntegration::CreateMultimodalInput(
    const std::string& text,
    const std::vector<ProjectedEmbeddings>& visionEmbeddings) {
    
    MultimodalTokens result;
    
    // Replace image tokens in text
    std::string processedText = ReplaceImageTokens(text, static_cast<int>(visionEmbeddings.size()));
    
    // Tokenize text (would use actual tokenizer)
    // For now, create dummy tokenization
    result.tokenIds.clear();
    result.isVisionToken.clear();
    
    // Merge vision embeddings
    int visionIdx = 0;
    for (const auto& emb : visionEmbeddings) {
        // Add vision tokens
        for (int i = 0; i < emb.GetTokenCount(); ++i) {
            result.tokenIds.push_back(-1);  // Vision token marker
            result.isVisionToken.push_back(true);
        }
        
        // Append embeddings
        result.embeddings.insert(result.embeddings.end(), 
                                 emb.GetData(), 
                                 emb.GetData() + emb.GetTokenCount() * emb.GetDim());
        visionIdx++;
    }
    
    result.numVisionTokens = visionIdx * (visionEmbeddings.empty() ? 0 : visionEmbeddings[0].GetTokenCount());
    result.numTextTokens = static_cast<int>(result.tokenIds.size()) - result.numVisionTokens;
    
    return result;
}

VisionInferenceResponse VisionIntegration::Generate(const VisionInferenceRequest& request) {
    VisionInferenceResponse response;
    
    if (!initialized_) {
        response.errorMessage = "Vision integration not initialized";
        return response;
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Process images
    std::vector<ProjectedEmbeddings> visionEmbeddings;
    if (request.useImages) {
        for (const auto& path : request.imagePaths) {
            visionEmbeddings.push_back(ProcessImage(path));
        }
        for (const auto& img : request.imageData) {
            visionEmbeddings.push_back(ProcessImageInternal(img));
        }
    }
    
    // Create multimodal input
    MultimodalTokens tokens = CreateMultimodalInput(request.text, visionEmbeddings);
    
    // Run inference (would integrate with actual inference engine)
    // Placeholder: just return success
    response.text = "Vision-enhanced generation would happen here";
    response.numVisionTokens = tokens.numVisionTokens;
    response.numTextTokens = tokens.numTextTokens;
    response.success = true;
    
    auto end = std::chrono::high_resolution_clock::now();
    response.inferenceTimeMs = std::chrono::duration<float, std::milli>(end - start).count();
    
    return response;
}

bool VisionIntegration::GenerateStreaming(const VisionInferenceRequest& request, 
                                        VisionTokenCallback callback) {
    // Similar to Generate but with streaming
    // Placeholder implementation
    if (callback) {
        callback("Vision streaming not yet implemented", true);
    }
    return false;
}

std::string VisionIntegration::ReplaceImageTokens(const std::string& text, int numImages) {
    std::string result = text;
    size_t pos = 0;
    
    for (int i = 0; i < numImages; ++i) {
        pos = result.find(config_.imageToken, pos);
        if (pos == std::string::npos) {
            break;
        }
        // Replace with special token IDs
        if (config_.visionTokenStartId >= 0) {
            result.replace(pos, config_.imageToken.length(), 
                          "<vision_start>");
        }
        pos += config_.imageToken.length();
    }
    
    return result;
}

VisionIntegration::BenchmarkResult VisionIntegration::Benchmark(const std::string& imagePath, 
                                                               const std::string& prompt) {
    BenchmarkResult result;
    
    if (!initialized_) {
        return result;
    }
    
    // Benchmark image loading
    auto start = std::chrono::high_resolution_clock::now();
    ImageData image = imageLoader_->LoadFromFile(imagePath);
    auto end = std::chrono::high_resolution_clock::now();
    result.imageLoadTimeMs = std::chrono::duration<float, std::milli>(end - start).count();
    
    if (!image.IsValid()) {
        return result;
    }
    
    // Benchmark preprocessing
    start = std::chrono::high_resolution_clock::now();
    ImageTensor tensor = preprocessor_->Preprocess(image);
    end = std::chrono::high_resolution_clock::now();
    result.preprocessTimeMs = std::chrono::duration<float, std::milli>(end - start).count();
    
    // Benchmark encoding
    start = std::chrono::high_resolution_clock::now();
    VisionEncoderOutput encoded = encoder_->Encode(tensor);
    end = std::chrono::high_resolution_clock::now();
    result.encodeTimeMs = std::chrono::duration<float, std::milli>(end - start).count();
    
    // Benchmark projection
    start = std::chrono::high_resolution_clock::now();
    ProjectedEmbeddings projected = projector_->Project(encoded);
    end = std::chrono::high_resolution_clock::now();
    result.projectTimeMs = std::chrono::duration<float, std::milli>(end - start).count();
    
    result.totalVisionTimeMs = result.imageLoadTimeMs + result.preprocessTimeMs + 
                               result.encodeTimeMs + result.projectTimeMs;
    
    return result;
}

// VisionInferenceFactory implementation
std::unique_ptr<VisionIntegration> VisionInferenceFactory::CreateDefault(
    const std::string& encoderPath,
    const std::string& projectorPath) {
    
    VisionIntegrationConfig config;
    config.encoderModelPath = encoderPath;
    config.projectorModelPath = projectorPath;
    
    auto integration = std::make_unique<VisionIntegration>();
    if (!integration->Initialize(config)) {
        return nullptr;
    }
    
    return integration;
}

std::unique_ptr<VisionIntegration> VisionInferenceFactory::Create(
    const VisionIntegrationConfig& config) {
    
    auto integration = std::make_unique<VisionIntegration>();
    if (!integration->Initialize(config)) {
        return nullptr;
    }
    
    return integration;
}

std::unique_ptr<VisionIntegration> VisionInferenceFactory::CreateCLIP(
    const std::string& clipModelPath,
    const std::string& projectorPath) {
    
    VisionIntegrationConfig config;
    config.encoderType = "clip";
    config.encoderModelPath = clipModelPath;
    config.projectorModelPath = projectorPath;
    config.preprocessConfig = PreprocessorFactory::CreateCLIPPreprocessor().GetConfig();
    
    return Create(config);
}

std::unique_ptr<VisionIntegration> VisionInferenceFactory::CreateSigLIP(
    const std::string& siglipModelPath,
    const std::string& projectorPath) {
    
    VisionIntegrationConfig config;
    config.encoderType = "siglip";
    config.encoderModelPath = siglipModelPath;
    config.projectorModelPath = projectorPath;
    config.preprocessConfig = PreprocessorFactory::CreateSigLIPPreprocessor().GetConfig();
    
    return Create(config);
}

// VisionCompatibilityChecker implementation
VisionCompatibilityChecker::CheckResult VisionCompatibilityChecker::CheckEncoder(
    const std::string& ggufPath) {
    
    CheckResult result;
    
    // Would check GGUF metadata for vision encoder compatibility
    // Placeholder implementation
    result.compatible = true;
    result.encoderType = "clip";
    
    return result;
}

VisionCompatibilityChecker::CheckResult VisionCompatibilityChecker::CheckProjector(
    const std::string& ggufPath) {
    
    CheckResult result;
    result.compatible = true;
    
    return result;
}

VisionCompatibilityChecker::CheckResult VisionCompatibilityChecker::CheckFullPipeline(
    const std::string& encoderPath,
    const std::string& projectorPath) {
    
    CheckResult result;
    
    auto encoderCheck = CheckEncoder(encoderPath);
    auto projectorCheck = CheckProjector(projectorPath);
    
    result.compatible = encoderCheck.compatible && projectorCheck.compatible;
    result.encoderType = encoderCheck.encoderType;
    
    if (!encoderCheck.compatible) {
        result.errors.push_back("Encoder compatibility check failed");
    }
    if (!projectorCheck.compatible) {
        result.errors.push_back("Projector compatibility check failed");
    }
    
    return result;
}

} // namespace vision
} // namespace rawrxd
