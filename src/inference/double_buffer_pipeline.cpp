#include "inference/double_buffer_pipeline.hpp"
#include <algorithm>
#include <math>
#include <random>
#include <chrono>

namespace RawrXD {
namespace Inference {

// ============================================================================
// TokenSampler Implementation
// ============================================================================

TokenSampler::TokenSampler() = default;

TokenSampler::~TokenSampler() {
    stop();
}

void TokenSampler::start() {
    if (running_.exchange(true)) return;
    
    samplingThread_ = std::thread(&TokenSampler::samplingThreadFunc, this);
}

void TokenSampler::stop() {
    if (!running_.exchange(false)) return;
    
    queueCV_.notify_all();
    if (samplingThread_.joinable()) {
        samplingThread_.join();
    }
}

bool TokenSampler::submit(SamplingRequest&& request) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    
    if (requestQueue_.size() >= 64) {
        return false; // Queue full
    }
    
    requestQueue_.push(std::move(request));
    queueCV_.notify_one();
    return true;
}

void TokenSampler::samplingThreadFunc() {
    while (running_.load()) {
        SamplingRequest request;
        
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCV_.wait(lock, [this] { 
                return !requestQueue_.empty() || !running_.load(); 
            });
            
            if (!running_.load() && requestQueue_.empty()) break;
            if (requestQueue_.empty()) continue;
            
            request = std::move(requestQueue_.front());
            requestQueue_.pop();
        }
        
        // Perform sampling
        int32_t token = sampleToken(request.logits, 
                                     request.temperature > 0 ? request.temperature : defaultTemp_,
                                     request.topP > 0 ? request.topP : defaultTopP_,
                                     request.topK > 0 ? request.topK : defaultTopK_);
        
        // Callback with result
        if (request.callback) {
            request.callback(token);
        }
    }
}

int32_t TokenSampler::sampleToken(const std::vector<float>& logits,
                                   float temperature, float topP, int topK) {
    if (logits.empty()) return 0;
    
    // Make mutable copy for transformations
    std::vector<float> probs = logits;
    
    // Apply temperature
    applyTemperature(probs, temperature);
    
    // Softmax
    float maxLogit = *std::max_element(probs.begin(), probs.end());
    float sum = 0.0f;
    for (auto& p : probs) {
        p = std::exp(p - maxLogit);
        sum += p;
    }
    for (auto& p : probs) {
        p /= sum;
    }
    
    // Apply top-k
    if (topK > 0 && topK < static_cast<int>(probs.size())) {
        applyTopK(probs, topK);
    }
    
    // Apply top-p (nucleus)
    if (topP < 1.0f) {
        applyTopP(probs, topP);
    }
    
    // Renormalize after filtering
    sum = 0.0f;
    for (const auto& p : probs) {
        sum += p;
    }
    if (sum > 0) {
        for (auto& p : probs) {
            p /= sum;
        }
    }
    
    // Sample
    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    float r = dist(gen);
    
    float cumsum = 0.0f;
    for (size_t i = 0; i < probs.size(); ++i) {
        cumsum += probs[i];
        if (r <= cumsum) {
            return static_cast<int32_t>(i);
        }
    }
    
    return static_cast<int32_t>(probs.size() - 1);
}

void TokenSampler::applyTemperature(std::vector<float>& logits, float temp) {
    if (temp <= 0.0f || temp == 1.0f) return;
    
    float invTemp = 1.0f / temp;
    for (auto& l : logits) {
        l *= invTemp;
    }
}

void TokenSampler::applyTopP(std::vector<float>& probs, float topP) {
    // Sort by probability descending
    std::vector<size_t> indices(probs.size());
    std::iota(indices.begin(), indices.end(), 0);
    
    std::sort(indices.begin(), indices.end(),
              [&probs](size_t a, size_t b) { return probs[a] > probs[b]; });
    
    // Cumulative sum
    float cumsum = 0.0f;
    size_t cutoff = probs.size();
    for (size_t i = 0; i < indices.size(); ++i) {
        cumsum += probs[indices[i]];
        if (cumsum >= topP) {
            cutoff = i + 1;
            break;
        }
    }
    
    // Zero out tokens beyond cutoff
    std::vector<bool> keep(probs.size(), false);
    for (size_t i = 0; i < cutoff; ++i) {
        keep[indices[i]] = true;
    }
    
    for (size_t i = 0; i < probs.size(); ++i) {
        if (!keep[i]) probs[i] = 0.0f;
    }
}

void TokenSampler::applyTopK(std::vector<float>& probs, int k) {
    if (k <= 0 || k >= static_cast<int>(probs.size())) return;
    
    // Find k-th largest probability
    std::vector<float> sorted = probs;
    std::nth_element(sorted.begin(), sorted.begin() + k, sorted.end(), 
                     std::greater<float>());
    float threshold = sorted[k];
    
    // Zero out probabilities below threshold
    for (auto& p : probs) {
        if (p < threshold) p = 0.0f;
    }
}

// ============================================================================
// DoubleBufferTokenPipeline Implementation
// ============================================================================

DoubleBufferTokenPipeline::DoubleBufferTokenPipeline() = default;

DoubleBufferTokenPipeline::~DoubleBufferTokenPipeline() {
    shutdown();
}

bool DoubleBufferTokenPipeline::initialize() {
    if (running_.exchange(true)) return true;
    
    sampler_.start();
    pipelineThread_ = std::thread(&DoubleBufferTokenPipeline::pipelineThreadFunc, this);
    
    return true;
}

void DoubleBufferTokenPipeline::shutdown() {
    if (!running_.exchange(false)) return;
    
    sampler_.stop();
    
    if (pipelineThread_.joinable()) {
        pipelineThread_.join();
    }
}

void DoubleBufferTokenPipeline::submitLogits(std::vector<float>&& logits,
                                              uint32_t sequenceId) {
    if (!running_.load()) return;
    
    auto now = std::chrono::high_resolution_clock::now();
    lastSubmitTime_ = now;
    
    // Submit to background sampler
    SamplingRequest request;
    request.logits = std::move(logits);
    request.sequenceId = sequenceId;
    request.callback = [this, sequenceId](int32_t token) {
        processSamplingResult(token, sequenceId);
    };
    
    if (!sampler_.submit(std::move(request))) {
        // Queue full - increment dropped counter
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.tokensDropped++;
    }
    
    // Also notify via callback for monitoring
    if (logitsCallback_) {
        logitsCallback_(request.logits);
    }
}

void DoubleBufferTokenPipeline::processSamplingResult(int32_t token, 
                                                       uint32_t seqId) {
    TokenBatch batch;
    batch.tokenIds.push_back(token);
    batch.sequenceId = seqId;
    batch.timestampUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    batch.isDraft = false;
    
    // Try to push to queue (non-blocking)
    if (!tokenQueue_.push(std::move(batch))) {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.tokensDropped++;
    } else {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.tokensGenerated++;
    }
    
    // Notify callback
    if (tokenCallback_) {
        tokenCallback_(token, seqId);
    }
}

bool DoubleBufferTokenPipeline::getNextBatch(TokenBatch& batch) {
    return tokenQueue_.pop(batch);
}

void DoubleBufferTokenPipeline::pipelineThreadFunc() {
    // This thread monitors pipeline health and handles any
    // async coordination between GPU and CPU
    
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        
        // Could add pipeline stall detection here
        // Could add automatic batching of multiple tokens
    }
}

DoubleBufferTokenPipeline::Stats DoubleBufferTokenPipeline::getStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void DoubleBufferTokenPipeline::resetStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_ = Stats{};
}

} // namespace Inference
} // namespace RawrXD
