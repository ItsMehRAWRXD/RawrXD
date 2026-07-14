#pragma once

#include "rawrxd/vision/VisionEncoder.hpp"
#include <vector>
#include <memory>

namespace rawrxd {
namespace vision {

// Projection configuration
struct ProjectionConfig {
    int visionOutputDim = 768;      // Vision encoder output dimension
    int llmInputDim = 4096;         // Language model input dimension
    int projectionDim = 4096;       // Intermediate projection dimension (optional)
    
    // Projection type
    std::string projectionType = "linear";  // linear, mlp, qformer
    
    // For MLP projection
    int hiddenDim = 4096;
    int numLayers = 1;
    std::string activation = "gelu";
    
    // For Q-Former style projection
    int numQueries = 32;            // Number of learnable queries
    int numQFormerLayers = 2;       // Number of Q-Former layers
    
    // Normalization
    bool useLayerNorm = true;
    float layerNormEps = 1e-5f;
};

// Projected embeddings ready for LLM
struct ProjectedEmbeddings {
    std::vector<float> embeddings;      // Projected embeddings
    int numVisionTokens = 0;            // Number of vision tokens
    int llmDim = 0;                     // LLM input dimension
    
    // Get token count
    int GetTokenCount() const { return numVisionTokens; }
    
    // Get embedding dimension
    int GetDim() const { return llmDim; }
    
    // Get raw data pointer
    const float* GetData() const { return embeddings.data(); }
    float* GetData() { return embeddings.data(); }
};

// Embedding projector interface
class EmbeddingProjector {
public:
    EmbeddingProjector();
    explicit EmbeddingProjector(const ProjectionConfig& config);
    ~EmbeddingProjector() = default;

    // Initialize projector
    bool Initialize(const ProjectionConfig& config);
    bool LoadWeights(const std::string& ggufPath);
    
    // Project vision embeddings to LLM space
    ProjectedEmbeddings Project(const VisionEncoderOutput& visionOutput);
    
    // Project batch
    std::vector<ProjectedEmbeddings> ProjectBatch(
        const std::vector<VisionEncoderOutput>& visionOutputs);
    
    // Get configuration
    const ProjectionConfig& GetConfig() const { return config_; }
    
    // Check if initialized
    bool IsInitialized() const { return initialized_; }
    
    // Get last error
    std::string GetLastError() const { return lastError_; }

private:
    ProjectionConfig config_;
    bool initialized_ = false;
    std::string lastError_;
    
    // Weight matrices (loaded from GGUF)
    std::vector<float> projectionWeights_;
    std::vector<float> projectionBias_;
    std::vector<float> layerNormWeight_;
    std::vector<float> layerNormBias_;
    
    // Internal projection methods
    ProjectedEmbeddings LinearProject(const VisionEncoderOutput& visionOutput);
    ProjectedEmbeddings MLPProject(const VisionEncoderOutput& visionOutput);
    ProjectedEmbeddings QFormerProject(const VisionEncoderOutput& visionOutput);
    
    // Utilities
    std::vector<float> ApplyLayerNorm(const std::vector<float>& x);
    std::vector<float> ApplyActivation(const std::vector<float>& x);
};

// Multi-modal token structure
struct MultimodalTokens {
    std::vector<int> tokenIds;              // Token IDs
    std::vector<float> embeddings;          // Embeddings (for vision tokens)
    std::vector<bool> isVisionToken;        // Mask indicating vision tokens
    int numVisionTokens = 0;
    int numTextTokens = 0;
    
    // Get total token count
    int GetTotalTokens() const { return tokenIds.size(); }
    
    // Get vision token positions
    std::vector<int> GetVisionTokenPositions() const;
    
    // Get text token positions
    std::vector<int> GetTextTokenPositions() const;
};

// Token merger for combining vision and text
class TokenMerger {
public:
    // Merge vision embeddings with text tokens
    static MultimodalTokens Merge(
        const ProjectedEmbeddings& visionEmbeddings,
        const std::vector<int>& textTokenIds,
        const std::vector<float>& textEmbeddings,
        int visionStartIdx = 0);  // Where to insert vision tokens
    
    // Create with special vision tokens
    static MultimodalTokens MergeWithSpecialTokens(
        const ProjectedEmbeddings& visionEmbeddings,
        const std::vector<int>& textTokenIds,
        int visionStartTokenId,
        int visionEndTokenId);
};

} // namespace vision
} // namespace rawrxd
