#pragma once
#include <cstdint>
#include <vector>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <thread>
#include <functional>
#include <atomic>

namespace RawrXD {
namespace Inference {

// ============================================================================
// DOUBLE-BUFFER TOKEN PIPELINE — Eliminates CPU/GPU sync bubbles
// ============================================================================
// Problem: CPU sampling blocks GPU execution between tokens
// Solution: CPU prepares token N+1 while GPU executes token N
// Architecture: Lock-free SPSC queue + background sampling thread
// ============================================================================

struct TokenBatch {
    std::vector<int32_t> tokenIds;
    std::vector<float> logits;
    uint32_t sequenceId;
    uint64_t timestampUs;
    bool isDraft;  // For speculative decoding
};

// ============================================================================
// Lock-Free SPSC Queue — Single producer, single consumer
// ============================================================================
template<typename T, size_t Capacity>
class LockFreeSPSCQueue {
public:
    LockFreeSPSCQueue() : head_(0), tail_(0) {
        buffer_.resize(Capacity);
    }
    
    // Producer only
    bool push(T&& item) {
        const size_t currentTail = tail_.load(std::memory_order_relaxed);
        const size_t nextTail = (currentTail + 1) % Capacity;
        
        if (nextTail == head_.load(std::memory_order_acquire)) {
            return false; // Full
        }
        
        buffer_[currentTail] = std::move(item);
        tail_.store(nextTail, std::memory_order_release);
        return true;
    }
    
    // Consumer only
    bool pop(T& item) {
        const size_t currentHead = head_.load(std::memory_order_relaxed);
        
        if (currentHead == tail_.load(std::memory_order_acquire)) {
            return false; // Empty
        }
        
        item = std::move(buffer_[currentHead]);
        head_.store((currentHead + 1) % Capacity, std::memory_order_release);
        return true;
    }
    
    // Consumer only — non-blocking check
    bool empty() const {
        return head_.load(std::memory_order_relaxed) == 
               tail_.load(std::memory_order_relaxed);
    }
    
    size_t size() const {
        const size_t h = head_.load(std::memory_order_relaxed);
        const size_t t = tail_.load(std::memory_order_relaxed);
        return (t >= h) ? (t - h) : (Capacity - h + t);
    }

private:
    std::vector<T> buffer_;
    alignas(64) std::atomic<size_t> head_;
    alignas(64) std::atomic<size_t> tail_;
};

// ============================================================================
// Sampling Request — Background thread work unit
// ============================================================================
struct SamplingRequest {
    std::vector<float> logits;
    float temperature;
    float topP;
    int topK;
    uint32_t sequenceId;
    std::function<void(int32_t)> callback;  // Called with sampled token
};

// ============================================================================
// Token Sampler — Background sampling thread
// ============================================================================
class TokenSampler {
public:
    TokenSampler();
    ~TokenSampler();
    
    // Start/stop background sampling thread
    void start();
    void stop();
    bool isRunning() const { return running_.load(); }
    
    // Submit sampling request (non-blocking)
    bool submit(SamplingRequest&& request);
    
    // Set sampling parameters
    void setDefaultTemperature(float temp) { defaultTemp_ = temp; }
    void setDefaultTopP(float topP) { defaultTopP_ = topP; }
    void setDefaultTopK(int topK) { defaultTopK_ = topK; }

private:
    void samplingThreadFunc();
    int32_t sampleToken(const std::vector<float>& logits, 
                        float temperature, float topP, int topK);
    void applyTemperature(std::vector<float>& logits, float temp);
    void applyTopP(std::vector<float>& logits, float topP);
    void applyTopK(std::vector<float>& logits, int k);
    
    std::thread samplingThread_;
    std::atomic<bool> running_{false};
    
    // Request queue (MPSC for multiple sequences, consumed by one thread)
    std::queue<SamplingRequest> requestQueue_;
    std::mutex queueMutex_;
    std::condition_variable queueCV_;
    
    // Default parameters
    float defaultTemp_ = 0.8f;
    float defaultTopP_ = 0.9f;
    int defaultTopK_ = 40;
};

// ============================================================================
// Double-Buffer Command List — GPU command preparation overlap
// ============================================================================
struct CommandListBuffer {
    static constexpr size_t NUM_BUFFERS = 2;
    
    struct Buffer {
        std::vector<uint8_t> commands;  // Serialized GPU commands
        std::atomic<bool> ready{false};
        std::atomic<bool> inUse{false};
    };
    
    std::array<Buffer, NUM_BUFFERS> buffers;
    std::atomic<size_t> writeIdx{0};
    std::atomic<size_t> readIdx{0};
    
    // Producer: Get buffer for writing
    Buffer* acquireWriteBuffer() {
        size_t idx = writeIdx.load(std::memory_order_relaxed);
        Buffer& buf = buffers[idx];
        
        if (buf.inUse.load(std::memory_order_acquire)) {
            // Buffer still in use, try next
            idx = (idx + 1) % NUM_BUFFERS;
            buf = buffers[idx];
            if (buf.inUse.load(std::memory_order_acquire)) {
                return nullptr; // Both buffers busy
            }
        }
        
        buf.ready.store(false, std::memory_order_relaxed);
        return &buf;
    }
    
    // Producer: Mark buffer ready for GPU
    void commitWriteBuffer() {
        size_t idx = writeIdx.load(std::memory_order_relaxed);
        buffers[idx].ready.store(true, std::memory_order_release);
        writeIdx.store((idx + 1) % NUM_BUFFERS, std::memory_order_release);
    }
    
    // Consumer (GPU thread): Get buffer for execution
    Buffer* acquireReadBuffer() {
        size_t idx = readIdx.load(std::memory_order_relaxed);
        Buffer& buf = buffers[idx];
        
        if (!buf.ready.load(std::memory_order_acquire)) {
            return nullptr; // No buffer ready
        }
        
        buf.inUse.store(true, std::memory_order_release);
        return &buf;
    }
    
    // Consumer: Release buffer after execution
    void releaseReadBuffer() {
        size_t idx = readIdx.load(std::memory_order_relaxed);
        buffers[idx].inUse.store(false, std::memory_order_release);
        buffers[idx].ready.store(false, std::memory_order_relaxed);
        readIdx.store((idx + 1) % NUM_BUFFERS, std::memory_order_release);
    }
};

// ============================================================================
// Double-Buffer Pipeline — Main orchestrator
// ============================================================================
class DoubleBufferTokenPipeline {
public:
    using TokenGeneratedCallback = std::function<void(int32_t token, uint32_t seqId)>;
    using LogitsReadyCallback = std::function<void(const std::vector<float>& logits)>;
    
    DoubleBufferTokenPipeline();
    ~DoubleBufferTokenPipeline();
    
    // Initialize pipeline
    bool initialize();
    void shutdown();
    
    // Submit logits for sampling (called by GPU thread)
    void submitLogits(std::vector<float>&& logits, uint32_t sequenceId);
    
    // Get next token batch for GPU execution (non-blocking)
    bool getNextBatch(TokenBatch& batch);
    
    // Set callbacks
    void setTokenCallback(TokenGeneratedCallback cb) { tokenCallback_ = cb; }
    void setLogitsCallback(LogitsReadyCallback cb) { logitsCallback_ = cb; }
    
    // Statistics
    struct Stats {
        uint64_t tokensGenerated = 0;
        uint64_t tokensDropped = 0;  // Queue full
        double avgLatencyUs = 0.0;
        double maxLatencyUs = 0.0;
    };
    Stats getStats() const;
    void resetStats();
    
    // Pipeline state
    bool isRunning() const { return running_.load(); }
    size_t pendingTokens() const { return tokenQueue_.size(); }

private:
    void pipelineThreadFunc();
    void processSamplingResult(int32_t token, uint32_t seqId);
    
    // Components
    TokenSampler sampler_;
    
    // Token queue: sampled tokens ready for GPU
    LockFreeSPSCQueue<TokenBatch, 16> tokenQueue_;
    
    // Callbacks
    TokenGeneratedCallback tokenCallback_;
    LogitsReadyCallback logitsCallback_;
    
    // Pipeline thread
    std::thread pipelineThread_;
    std::atomic<bool> running_{false};
    
    // Statistics
    mutable std::mutex statsMutex_;
    Stats stats_;
    
    // Latency tracking
    std::chrono::high_resolution_clock::time_point lastSubmitTime_;
};

// ============================================================================
// Integration with StreamingInferenceEngine
// ============================================================================
class StreamingInferenceEngine;

class PipelineIntegration {
public:
    // Attach pipeline to inference engine
    static void attach(StreamingInferenceEngine* engine, 
                       DoubleBufferTokenPipeline* pipeline);
    
    // Detach
    static void detach(StreamingInferenceEngine* engine);
    
    // Check if pipeline is active
    static bool isPipelined(StreamingInferenceEngine* engine);
};

} // namespace Inference
} // namespace RawrXD
