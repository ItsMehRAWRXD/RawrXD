#include "rawrxd/vision/EmbeddingProjector.hpp"
#include <cmath>
#include <algorithm>

namespace rawrxd {
namespace vision {

EmbeddingProjector::EmbeddingProjector() = default;

EmbeddingProjector::EmbeddingProjector(const ProjectionConfig& config) {
    Initialize(config);
}

bool EmbeddingProjector::Initialize(const ProjectionConfig& config) {
    config_ = config;
    
    // Validate configuration
    if (config_.visionOutputDim <= 0 || config_.llmInputDim <= 0) {
        lastError_ = "Invalid dimensions";
        return false;
    }
    
    initialized_ = true;
    return true;
}

bool EmbeddingProjector::LoadWeights(const std::string& ggufPath) {
    if (!initialized_) {
        lastError_ = "Projector not initialized";
        return false;
    }
    
    // Would load weights from GGUF
    // Placeholder - allocate dummy weights
    projectionWeights_.resize(config_.visionOutputDim * config_.llmInputDim);
    projectionBias_.resize(config_.llmInputDim);
    
    // Initialize with identity-like mapping
    for (int i = 0; i < config_.visionOutputDim && i < config_.llmInputDim; ++i) {
        projectionWeights_[i * config_.llmInputDim + i] = 1.0f;
    }
    
    if (config_.useLayerNorm) {
        layerNormWeight_.resize(config_.llmInputDim, 1.0f);
        layerNormBias_.resize(config_.llmInputDim, 0.0f);
    }
    
    return true;
}

ProjectedEmbeddings EmbeddingProjector::Project(const VisionEncoderOutput& visionOutput) {
    if (!initialized_) {
        return ProjectedEmbeddings();
    }
    
    switch (config_.projectionType[0]) {
        case 'm':  // mlp
            return MLPProject(visionOutput);
        case 'q':  // qformer
            return QFormerProject(visionOutput);
        default:
            return LinearProject(visionOutput);
    }
}

std::vector<ProjectedEmbeddings> EmbeddingProjector::ProjectBatch(
    const std::vector<VisionEncoderOutput>& visionOutputs) {
    
    std::vector<ProjectedEmbeddings> results;
    results.reserve(visionOutputs.size());
    
    for (const auto& output : visionOutputs) {
        results.push_back(Project(output));
    }
    
    return results;
}

ProjectedEmbeddings EmbeddingProjector::LinearProject(const VisionEncoderOutput& visionOutput) {
    ProjectedEmbeddings result;
    result.llmDim = config_.llmInputDim;
    
    // Get vision embeddings (use pooled or full sequence)
    std::vector<float> visionEmb = visionOutput.GetPooled();
    if (visionEmb.empty()) {
        // Use mean of patch embeddings
        visionEmb = visionOutput.GetPooled();
    }
    
    int numTokens = config_.projectionType == "qformer" ? config_.numQueries : 1;
    result.numVisionTokens = numTokens;
    result.embeddings.resize(numTokens * config_.llmInputDim);
    
    // Linear projection: Y = X @ W + b
    for (int t = 0; t < numTokens; ++t) {
        for (int i = 0; i < config_.llmInputDim; ++i) {
            float sum = projectionBias_[i];
            for (int j = 0; j < config_.visionOutputDim && j < static_cast<int>(visionEmb.size()); ++j) {
                sum += visionEmb[j] * projectionWeights_[j * config_.llmInputDim + i];
            }
            result.embeddings[t * config_.llmInputDim + i] = sum;
        }
    }
    
    // Apply layer norm if configured
    if (config_.useLayerNorm) {
        result.embeddings = ApplyLayerNorm(result.embeddings);
    }
    
    return result;
}

ProjectedEmbeddings EmbeddingProjector::MLPProject(const VisionEncoderOutput& visionOutput) {
    ProjectedEmbeddings result;
    result.llmDim = config_.llmInputDim;
    result.numVisionTokens = 1;
    
    std::vector<float> visionEmb = visionOutput.GetPooled();
    
    // MLP with hidden layer
    std::vector<float> hidden(config_.hiddenDim);
    
    // First linear layer
    for (int i = 0; i < config_.hiddenDim; ++i) {
        float sum = 0.0f;
        for (int j = 0; j < config_.visionOutputDim && j < static_cast<int>(visionEmb.size()); ++j) {
            sum += visionEmb[j] * projectionWeights_[j * config_.hiddenDim + i];
        }
        hidden[i] = sum;
    }
    
    // Activation
    hidden = ApplyActivation(hidden);
    
    // Second linear layer
    result.embeddings.resize(config_.llmInputDim);
    for (int i = 0; i < config_.llmInputDim; ++i) {
        float sum = projectionBias_[i];
        for (int j = 0; j < config_.hiddenDim; ++j) {
            sum += hidden[j] * projectionWeights_[j * config_.llmInputDim + i];
        }
        result.embeddings[i] = sum;
    }
    
    if (config_.useLayerNorm) {
        result.embeddings = ApplyLayerNorm(result.embeddings);
    }
    
    return result;
}

ProjectedEmbeddings EmbeddingProjector::QFormerProject(const VisionEncoderOutput& visionOutput) {
    // Q-Former style projection with learnable queries
    ProjectedEmbeddings result;
    result.llmDim = config_.llmInputDim;
    result.numVisionTokens = config_.numQueries;
    result.embeddings.resize(config_.numQueries * config_.llmInputDim);
    
    // Simplified Q-Former: just replicate vision embedding
    std::vector<float> visionEmb = visionOutput.GetPooled();
    
    for (int q = 0; q < config_.numQueries; ++q) {
        for (int i = 0; i < config_.llmInputDim && i < static_cast<int>(visionEmb.size()); ++i) {
            result.embeddings[q * config_.llmInputDim + i] = visionEmb[i];
        }
    }
    
    return result;
}

std::vector<float> EmbeddingProjector::ApplyLayerNorm(const std::vector<float>& x) {
    if (!config_.useLayerNorm || layerNormWeight_.empty()) {
        return x;
    }
    
    std::vector<float> output(x.size());
    int numTokens = x.size() / config_.llmInputDim;
    
    for (int t = 0; t < numTokens; ++t) {
        // Compute mean
        float mean = 0.0f;
        for (int i = 0; i < config_.llmInputDim; ++i) {
            mean += x[t * config_.llmInputDim + i];
        }
        mean /= config_.llmInputDim;
        
        // Compute variance
        float var = 0.0f;
        for (int i = 0; i < config_.llmInputDim; ++i) {
            float diff = x[t * config_.llmInputDim + i] - mean;
            var += diff * diff;
        }
        var /= config_.llmInputDim;
        
        // Normalize and scale
        float invStd = 1.0f / std::sqrt(var + config_.layerNormEps);
        for (int i = 0; i < config_.llmInputDim; ++i) {
            output[t * config_.llmInputDim + i] = 
                (x[t * config_.llmInputDim + i] - mean) * invStd * layerNormWeight_[i] + layerNormBias_[i];
        }
    }
    
    return output;
}

std::vector<float> EmbeddingProjector::ApplyActivation(const std::vector<float>& x) {
    std::vector<float> output(x.size());
    
    if (config_.activation == "gelu") {
        for (size_t i = 0; i < x.size(); ++i) {
            // Approximate GELU
            float cdf = 0.5f * (1.0f + std::tanh(0.7978845608f * (x[i] + 0.044715f * x[i] * x[i] * x[i])));
            output[i] = x[i] * cdf;
        }
    } else if (config_.activation == "relu") {
        for (size_t i = 0; i < x.size(); ++i) {
            output[i] = std::max(0.0f, x[i]);
        }
    } else {
        // Default: no activation
        output = x;
    }
    
    return output;
}

// TokenMerger implementation
MultimodalTokens TokenMerger::Merge(
    const ProjectedEmbeddings& visionEmbeddings,
    const std::vector<int>& textTokenIds,
    const std::vector<float>& textEmbeddings,
    int visionStartIdx) {
    
    MultimodalTokens result;
    result.numVisionTokens = visionEmbeddings.GetTokenCount();
    result.numTextTokens = static_cast<int>(textTokenIds.size());
    
    // Insert vision embeddings at specified position
    int totalTokens = result.numTextTokens + result.numVisionTokens;
    result.tokenIds.resize(totalTokens);
    result.embeddings.resize(totalTokens * visionEmbeddings.GetDim());
    result.isVisionToken.resize(totalTokens, false);
    
    // Copy text tokens before vision
    for (int i = 0; i < visionStartIdx && i < result.numTextTokens; ++i) {
        result.tokenIds[i] = textTokenIds[i];
        // Would copy text embeddings
    }
    
    // Insert vision tokens
    for (int i = 0; i < result.numVisionTokens; ++i) {
        int pos = visionStartIdx + i;
        result.tokenIds[pos] = -1;  // Special marker for vision tokens
        result.isVisionToken[pos] = true;
        
        // Copy vision embeddings
        for (int d = 0; d < visionEmbeddings.GetDim(); ++d) {
            result.embeddings[pos * visionEmbeddings.GetDim() + d] = 
                visionEmbeddings.GetData()[i * visionEmbeddings.GetDim() + d];
        }
    }
    
    // Copy remaining text tokens
    for (int i = visionStartIdx; i < result.numTextTokens; ++i) {
        int pos = result.numVisionTokens + i;
        result.tokenIds[pos] = textTokenIds[i];
    }
    
    return result;
}

MultimodalTokens TokenMerger::MergeWithSpecialTokens(
    const ProjectedEmbeddings& visionEmbeddings,
    const std::vector<int>& textTokenIds,
    int visionStartTokenId,
    int visionEndTokenId) {
    
    MultimodalTokens result;
    result.numVisionTokens = visionEmbeddings.GetTokenCount();
    result.numTextTokens = static_cast<int>(textTokenIds.size());
    
    // Find position of vision token marker
    int visionStartIdx = -1;
    for (size_t i = 0; i < textTokenIds.size(); ++i) {
        if (textTokenIds[i] == visionStartTokenId) {
            visionStartIdx = static_cast<int>(i);
            break;
        }
    }
    
    if (visionStartIdx < 0) {
        // No vision token found, append at end
        visionStartIdx = result.numTextTokens;
    }
    
    // Use standard merge
    std::vector<float> dummyTextEmbeddings;
    return Merge(visionEmbeddings, textTokenIds, dummyTextEmbeddings, visionStartIdx);
}

std::vector<int> MultimodalTokens::GetVisionTokenPositions() const {
    std::vector<int> positions;
    for (size_t i = 0; i < isVisionToken.size(); ++i) {
        if (isVisionToken[i]) {
            positions.push_back(static_cast<int>(i));
        }
    }
    return positions;
}

std::vector<int> MultimodalTokens::GetTextTokenPositions() const {
    std::vector<int> positions;
    for (size_t i = 0; i < isVisionToken.size(); ++i) {
        if (!isVisionToken[i]) {
            positions.push_back(static_cast<int>(i));
        }
    }
    return positions;
}

} // namespace vision
} // namespace rawrxd
