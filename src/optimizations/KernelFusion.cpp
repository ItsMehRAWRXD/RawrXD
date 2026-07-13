#include "rawrxd/optimizations/KernelFusion.hpp"
#include <algorithm>
#include <math>

namespace rawrxd {
namespace optimizations {

// LinearGeluFusion implementation
LinearGeluFusion::LinearGeluFusion() = default;

LinearGeluFusion::~LinearGeluFusion() = default;

bool LinearGeluFusion::Initialize(const FusionConfig& config) {
    config_ = config;
    initialized_ = true;
    return true;
}

bool LinearGeluFusion::Execute(const std::vector<float*>& inputs,
                                float* output,
                                const std::vector<int>& inputSizes,
                                int outputSize) {
    if (!initialized_ || inputs.size() < 2) return false;
    
    const float* input = inputs[0];
    const float* weight = inputs[1];
    const float* bias = inputs.size() > 2 ? inputs[2] : nullptr;
    
    int batchSize = inputSizes[0];
    int inFeatures = inputSizes[1];
    int outFeatures = outputSize / batchSize;
    
    ExecuteCPU(input, weight, bias, output, batchSize, inFeatures, outFeatures);
    return true;
}

void LinearGeluFusion::ExecuteCPU(const float* input, const float* weight, const float* bias,
                                   float* output, int batchSize, int inFeatures, int outFeatures) {
    for (int b = 0; b < batchSize; ++b) {
        for (int o = 0; o < outFeatures; ++o) {
            float sum = bias ? bias[o] : 0.0f;
            
            // Linear computation
            for (int i = 0; i < inFeatures; ++i) {
                sum += input[b * inFeatures + i] * weight[o * inFeatures + i];
            }
            
            // GELU activation (approximation)
            // GELU(x) = 0.5 * x * (1 + tanh(sqrt(2/pi) * (x + 0.044715 * x^3)))
            float x = sum;
            float x3 = x * x * x;
            float inner = GELU_COEF_1 * (x + GELU_COEF_0 * x3);
            float tanhVal = std::tanh(inner);
            output[b * outFeatures + o] = 0.5f * x * (1.0f + tanhVal);
        }
    }
}

void LinearGeluFusion::ExecuteGPU(const float* input, const float* weight, const float* bias,
                                   float* output, int batchSize, int inFeatures, int outFeatures) {
    // GPU implementation would use CUDA kernels
    // For now, fall back to CPU
    ExecuteCPU(input, weight, bias, output, batchSize, inFeatures, outFeatures);
}

// QKVProjectionFusion implementation
QKVProjectionFusion::QKVProjectionFusion() = default;

QKVProjectionFusion::~QKVProjectionFusion() = default;

bool QKVProjectionFusion::Initialize(const FusionConfig& config) {
    config_ = config;
    initialized_ = true;
    return true;
}

bool QKVProjectionFusion::Execute(const std::vector<float*>& inputs,
                                   float* output,
                                   const std::vector<int>& inputSizes,
                                   int outputSize) {
    if (!initialized_ || inputs.size() < 4) return false;
    
    const float* input = inputs[0];
    const float* wq = inputs[1];
    const float* wk = inputs[2];
    const float* wv = inputs[3];
    
    int batchSize = inputSizes[0];
    int seqLen = inputSizes[1];
    int hiddenSize = inputSizes[2];
    int numHeads = 32; // Should be passed as parameter
    int headDim = hiddenSize / numHeads;
    
    float* q = output;
    float* k = output + batchSize * seqLen * hiddenSize;
    float* v = output + 2 * batchSize * seqLen * hiddenSize;
    
    ExecuteCPU(input, wq, wk, wv, q, k, v, batchSize, seqLen, hiddenSize, numHeads, headDim);
    return true;
}

void QKVProjectionFusion::ExecuteCPU(const float* input, const float* wq, const float* wk, const float* wv,
                                      float* q, float* k, float* v,
                                      int batchSize, int seqLen, int hiddenSize, int numHeads, int headDim) {
    for (int b = 0; b < batchSize; ++b) {
        for (int s = 0; s < seqLen; ++s) {
            for (int h = 0; h < numHeads; ++h) {
                for (int d = 0; d < headDim; ++d) {
                    int outIdx = ((b * seqLen + s) * numHeads + h) * headDim + d;
                    
                    // Q projection
                    float qSum = 0.0f;
                    for (int i = 0; i < hiddenSize; ++i) {
                        int inIdx = (b * seqLen + s) * hiddenSize + i;
                        int wIdx = ((h * headDim + d) * hiddenSize + i);
                        qSum += input[inIdx] * wq[wIdx];
                    }
                    q[outIdx] = qSum;
                    
                    // K projection
                    float kSum = 0.0f;
                    for (int i = 0; i < hiddenSize; ++i) {
                        int inIdx = (b * seqLen + s) * hiddenSize + i;
                        int wIdx = ((h * headDim + d) * hiddenSize + i);
                        kSum += input[inIdx] * wk[wIdx];
                    }
                    k[outIdx] = kSum;
                    
                    // V projection
                    float vSum = 0.0f;
                    for (int i = 0; i < hiddenSize; ++i) {
                        int inIdx = (b * seqLen + s) * hiddenSize + i;
                        int wIdx = ((h * headDim + d) * hiddenSize + i);
                        vSum += input[inIdx] * wv[wIdx];
                    }
                    v[outIdx] = vSum;
                }
            }
        }
    }
}

// AttentionSoftmaxVFusion implementation
AttentionSoftmaxVFusion::AttentionSoftmaxVFusion() = default;

AttentionSoftmaxVFusion::~AttentionSoftmaxVFusion() = default;

bool AttentionSoftmaxVFusion::Initialize(const FusionConfig& config) {
    config_ = config;
    initialized_ = true;
    return true;
}

bool AttentionSoftmaxVFusion::Execute(const std::vector<float*>& inputs,
                                       float* output,
                                       const std::vector<int>& inputSizes,
                                       int outputSize) {
    if (!initialized_ || inputs.size() < 3) return false;
    
    const float* query = inputs[0];
    const float* key = inputs[1];
    const float* value = inputs[2];
    float* softmaxLse = inputs.size() > 3 ? inputs[3] : nullptr;
    
    int batchSize = inputSizes[0];
    int numHeads = inputSizes[1];
    int seqLen = inputSizes[2];
    int headDim = inputSizes[3];
    
    ForwardCPU(query, key, value, output, softmaxLse,
               batchSize, numHeads, seqLen, seqLen, headDim);
    return true;
}

void AttentionSoftmaxVFusion::ForwardCPU(const float* query, const float* key, const float* value,
                                          float* output, float* softmaxLse,
                                          int batchSize, int numHeads, int seqLenQ, int seqLenKV, int headDim) {
    float scale = 1.0f / std::sqrt(static_cast<float>(headDim));
    
    for (int b = 0; b < batchSize; ++b) {
        for (int h = 0; h < numHeads; ++h) {
            for (int sq = 0; sq < seqLenQ; ++sq) {
                // Compute attention scores
                std::vector<float> scores(seqLenKV);
                float maxScore = -std::numeric_limits<float>::infinity();
                
                for (int skv = 0; skv < seqLenKV; ++skv) {
                    float dot = 0.0f;
                    for (int d = 0; d < headDim; ++d) {
                        int qIdx = ((b * numHeads + h) * seqLenQ + sq) * headDim + d;
                        int kIdx = ((b * numHeads + h) * seqLenKV + skv) * headDim + d;
                        dot += query[qIdx] * key[kIdx];
                    }
                    scores[skv] = dot * scale;
                    maxScore = std::max(maxScore, scores[skv]);
                }
                
                // Softmax
                float sumExp = 0.0f;
                for (int skv = 0; skv < seqLenKV; ++skv) {
                    scores[skv] = std::exp(scores[skv] - maxScore);
                    sumExp += scores[skv];
                }
                for (int skv = 0; skv < seqLenKV; ++skv) {
                    scores[skv] /= sumExp;
                }
                
                // Weighted sum of values
                for (int d = 0; d < headDim; ++d) {
                    float sum = 0.0f;
                    for (int skv = 0; skv < seqLenKV; ++skv) {
                        int vIdx = ((b * numHeads + h) * seqLenKV + skv) * headDim + d;
                        sum += scores[skv] * value[vIdx];
                    }
                    int outIdx = ((b * numHeads + h) * seqLenQ + sq) * headDim + d;
                    output[outIdx] = sum;
                }
                
                // Store log-sum-exp for backward
                if (softmaxLse) {
                    int lseIdx = ((b * numHeads + h) * seqLenQ + sq);
                    softmaxLse[lseIdx] = maxScore + std::log(sumExp);
                }
            }
        }
    }
}

// ResidualLayerNormFusion implementation
ResidualLayerNormFusion::ResidualLayerNormFusion() = default;

ResidualLayerNormFusion::~ResidualLayerNormFusion() = default;

bool ResidualLayerNormFusion::Initialize(const FusionConfig& config) {
    config_ = config;
    initialized_ = true;
    return true;
}

bool ResidualLayerNormFusion::Execute(const std::vector<float*>& inputs,
                                       float* output,
                                       const std::vector<int>& inputSizes,
                                       int outputSize) {
    if (!initialized_ || inputs.size() < 2) return false;
    
    const float* residual = inputs[0];
    const float* x = inputs[1];
    const float* gamma = inputs.size() > 2 ? inputs[2] : nullptr;
    const float* beta = inputs.size() > 3 ? inputs[3] : nullptr;
    
    int batchSize = inputSizes[0];
    int hiddenSize = inputSizes[1];
    
    // Allocate temporary buffers for mean and rstd
    std::vector<float> mean(batchSize);
    std::vector<float> rstd(batchSize);
    
    ExecuteCPU(residual, x, gamma, beta, output, mean.data(), rstd.data(), batchSize, hiddenSize);
    return true;
}

void ResidualLayerNormFusion::ExecuteCPU(const float* residual, const float* x,
                                          const float* gamma, const float* beta,
                                          float* output, float* mean, float* rstd,
                                          int batchSize, int hiddenSize) {
    for (int b = 0; b < batchSize; ++b) {
        // Compute mean
        float sum = 0.0f;
        for (int h = 0; h < hiddenSize; ++h) {
            sum += x[b * hiddenSize + h];
        }
        mean[b] = sum / hiddenSize;
        
        // Compute variance and rstd
        float varSum = 0.0f;
        for (int h = 0; h < hiddenSize; ++h) {
            float diff = x[b * hiddenSize + h] - mean[b];
            varSum += diff * diff;
        }
        float variance = varSum / hiddenSize;
        rstd[b] = 1.0f / std::sqrt(variance + epsilon_);
        
        // Normalize, scale, shift, and add residual
        for (int h = 0; h < hiddenSize; ++h) {
            float normalized = (x[b * hiddenSize + h] - mean[b]) * rstd[b];
            float scaled = gamma ? normalized * gamma[h] : normalized;
            float shifted = beta ? scaled + beta[h] : scaled;
            output[b * hiddenSize + h] = residual[b * hiddenSize + h] + shifted;
        }
    }
}

// FFNUpGateFusion implementation
FFNUpGateFusion::FFNUpGateFusion() = default;

FFNUpGateFusion::~FFNUpGateFusion() = default;

bool FFNUpGateFusion::Initialize(const FusionConfig& config) {
    config_ = config;
    initialized_ = true;
    return true;
}

bool FFNUpGateFusion::Execute(const std::vector<float*>& inputs,
                               float* output,
                               const std::vector<int>& inputSizes,
                               int outputSize) {
    if (!initialized_ || inputs.size() < 3) return false;
    
    const float* x = inputs[0];
    const float* w_up = inputs[1];
    const float* w_gate = inputs[2];
    
    int batchSize = inputSizes[0];
    int hiddenSize = inputSizes[1];
    int intermediateSize = outputSize / batchSize;
    
    ExecuteCPU(x, w_up, w_gate, output, batchSize, hiddenSize, intermediateSize);
    return true;
}

void FFNUpGateFusion::ExecuteCPU(const float* x, const float* w_up, const float* w_gate,
                                  float* output, int batchSize, int hiddenSize, int intermediateSize) {
    // SwiGLU: Swish(x @ W_gate) * (x @ W_up)
    for (int b = 0; b < batchSize; ++b) {
        for (int i = 0; i < intermediateSize; ++i) {
            // Compute up projection
            float upSum = 0.0f;
            for (int h = 0; h < hiddenSize; ++h) {
                upSum += x[b * hiddenSize + h] * w_up[i * hiddenSize + h];
            }
            
            // Compute gate projection with Swish
            float gateSum = 0.0f;
            for (int h = 0; h < hiddenSize; ++h) {
                gateSum += x[b * hiddenSize + h] * w_gate[i * hiddenSize + h];
            }
            // Swish activation: x * sigmoid(x)
            float swish = gateSum * (1.0f / (1.0f + std::exp(-gateSum)));
            
            // Element-wise multiply
            output[b * intermediateSize + i] = swish * upSum;
        }
    }
}

// RMSNormFusion implementation
RMSNormFusion::RMSNormFusion() = default;

RMSNormFusion::~RMSNormFusion() = default;

bool RMSNormFusion::Initialize(const FusionConfig& config) {
    config_ = config;
    initialized_ = true;
    return true;
}

bool RMSNormFusion::Execute(const std::vector<float*>& inputs,
                             float* output,
                             const std::vector<int>& inputSizes,
                             int outputSize) {
    if (!initialized_ || inputs.size() < 2) return false;
    
    const float* x = inputs[0];
    const float* weight = inputs[1];
    
    int batchSize = inputSizes[0];
    int hiddenSize = inputSizes[1];
    
    std::vector<float> rms(batchSize);
    ExecuteCPU(x, weight, output, rms.data(), batchSize, hiddenSize);
    return true;
}

void RMSNormFusion::ExecuteCPU(const float* x, const float* weight,
                                float* output, float* rms,
                                int batchSize, int hiddenSize) {
    for (int b = 0; b < batchSize; ++b) {
        // Compute RMS
        float sumSquares = 0.0f;
        for (int h = 0; h < hiddenSize; ++h) {
            sumSquares += x[b * hiddenSize + h] * x[b * hiddenSize + h];
        }
        rms[b] = std::sqrt(sumSquares / hiddenSize + epsilon_);
        
        // Normalize and scale
        for (int h = 0; h < hiddenSize; ++h) {
            output[b * hiddenSize + h] = x[b * hiddenSize + h] / rms[b] * weight[h];
        }
    }
}

// FusionRegistry implementation
FusionRegistry& FusionRegistry::GetInstance() {
    static FusionRegistry instance;
    return instance;
}

void FusionRegistry::RegisterPattern(FusionPattern pattern,
                                      std::function<std::unique_ptr<FusedOperation>()> factory) {
    std::lock_guard<std::mutex> lock(mutex_);
    factories_[pattern] = factory;
}

std::unique_ptr<FusedOperation> FusionRegistry::CreateOperation(FusionPattern pattern) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = factories_.find(pattern);
    if (it != factories_.end()) {
        return it->second();
    }
    return nullptr;
}

bool FusionRegistry::IsPatternAvailable(FusionPattern pattern) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return factories_.find(pattern) != factories_.end();
}

std::vector<FusionPattern> FusionRegistry::GetAvailablePatterns() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FusionPattern> patterns;
    for (const auto& pair : factories_) {
        patterns.push_back(pair.first);
    }
    return patterns;
}

std::vector<FusionPattern> FusionRegistry::DetectFusionOpportunities(
    const std::vector<std::string>& operationSequence) const {
    
    std::vector<FusionPattern> opportunities;
    
    // Simple pattern matching
    for (size_t i = 0; i < operationSequence.size(); ++i) {
        if (i + 1 < operationSequence.size()) {
            if (operationSequence[i] == "Linear" && operationSequence[i + 1] == "GELU") {
                opportunities.push_back(FusionPattern::LINEAR_GELU);
            }
            if (operationSequence[i] == "Linear" && operationSequence[i + 1] == "SiLU") {
                opportunities.push_back(FusionPattern::LINEAR_SILU);
            }
            if (operationSequence[i] == "Residual" && operationSequence[i + 1] == "LayerNorm") {
                opportunities.push_back(FusionPattern::RESIDUAL_LAYERNORM);
            }
        }
    }
    
    return opportunities;
}

// FusionPass implementation
FusionPass::Stats FusionPass::stats_;

bool FusionPass::ApplyFusion(ModelGraph& graph) {
    stats_ = Stats();
    bool modified = false;
    
    // Iterate through graph and apply fusions
    for (int i = 0; i < graph.GetNumNodes(); ++i) {
        if (TryFuseLinearActivation(graph, i)) {
            modified = true;
            stats_.patternsApplied++;
        }
        if (TryFuseQKVProjection(graph, i)) {
            modified = true;
            stats_.patternsApplied++;
        }
        if (TryFuseAttention(graph, i)) {
            modified = true;
            stats_.patternsApplied++;
        }
        if (TryFuseResidualLayerNorm(graph, i)) {
            modified = true;
            stats_.patternsApplied++;
        }
        if (TryFuseFFNUpGate(graph, i)) {
            modified = true;
            stats_.patternsApplied++;
        }
    }
    
    return modified;
}

FusionPass::Stats FusionPass::GetStats() {
    return stats_;
}

bool FusionPass::TryFuseLinearActivation(ModelGraph& graph, int nodeIdx) {
    // Check if current node is Linear and next is activation
    // If so, fuse them
    return false; // Placeholder
}

bool FusionPass::TryFuseQKVProjection(ModelGraph& graph, int nodeIdx) {
    // Check for Q, K, V projection pattern
    return false; // Placeholder
}

bool FusionPass::TryFuseAttention(ModelGraph& graph, int nodeIdx) {
    // Check for attention pattern
    return false; // Placeholder
}

bool FusionPass::TryFuseResidualLayerNorm(ModelGraph& graph, int nodeIdx) {
    // Check for residual + layernorm pattern
    return false; // Placeholder
}

bool FusionPass::TryFuseFFNUpGate(ModelGraph& graph, int nodeIdx) {
    // Check for FFN up + gate pattern
    return false; // Placeholder
}

} // namespace optimizations
} // namespace rawrxd
