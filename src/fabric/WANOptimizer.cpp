#include "WANOptimizer.h"
#include "FabricMessages.h"
#include <Windows.h>
#include <zlib.h>
#include <iostream>

namespace RawrXD {
namespace Fabric {

// ============================================================================
// WANOptimizer Implementation
// ============================================================================

WANOptimizer::WANOptimizer()
    : transport_(nullptr)
    , initialized_(false)
    , shutdown_(false) {
}

WANOptimizer::~WANOptimizer() {
    Shutdown();
}

bool WANOptimizer::Configure(const WANConfig& config) {
    config_ = config;
    return true;
}

bool WANOptimizer::Initialize(FabricTransport* transport) {
    if (initialized_) {
        return false;
    }
    
    transport_ = transport;
    
    // Start batching thread
    shutdown_ = false;
    batchThread_ = std::thread(&WANOptimizer::BatchLoop, this);
    
    initialized_ = true;
    return true;
}

void WANOptimizer::Shutdown() {
    if (!initialized_) {
        return;
    }
    
    // Flush any pending batches
    FlushBatch();
    
    shutdown_ = true;
    
    if (batchThread_.joinable()) {
        batchThread_.join();
    }
    
    initialized_ = false;
}

bool WANOptimizer::QueueMessage(const FabricMessage& msg) {
    if (!initialized_) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(batchMutex_);
    
    if (currentBatch_.empty()) {
        batchStartTime_ = std::chrono::steady_clock::now();
    }
    
    currentBatch_.push_back(msg);
    messagesBatched_.fetch_add(1, std::memory_order_relaxed);
    
    // Check if batch should be flushed
    if (ShouldFlushBatch()) {
        FlushBatch();
    }
    
    return true;
}

bool WANOptimizer::FlushBatch() {
    std::lock_guard<std::mutex> lock(batchMutex_);
    
    if (currentBatch_.empty()) {
        return true;
    }
    
    SendBatch(currentBatch_);
    currentBatch_.clear();
    
    return true;
}

WANOptimizer::Stats WANOptimizer::GetStats() const {
    Stats stats;
    stats.messagesBatched = messagesBatched_.load(std::memory_order_relaxed);
    stats.messagesSent = messagesSent_.load(std::memory_order_relaxed);
    stats.bytesCompressed = bytesCompressed_.load(std::memory_order_relaxed);
    stats.bytesUncompressed = bytesUncompressed_.load(std::memory_order_relaxed);
    stats.currentWindow = congestionWindow_.load(std::memory_order_relaxed);
    stats.estimatedBandwidthMbps = lastBandwidthEstimate_.load(std::memory_order_relaxed) / (1024.0 * 1024.0);
    
    if (stats.bytesUncompressed > 0) {
        stats.compressionRatio = 1.0 - (static_cast<double>(stats.bytesCompressed) / 
                                         static_cast<double>(stats.bytesUncompressed));
    } else {
        stats.compressionRatio = 0.0;
    }
    
    if (stats.messagesSent > 0) {
        stats.avgBatchSize = static_cast<double>(stats.messagesBatched) / stats.messagesSent;
    } else {
        stats.avgBatchSize = 0.0;
    }
    
    return stats;
}

void WANOptimizer::OnAck(uint32_t sequence) {
    // TCP-like congestion control
    uint32_t cwnd = congestionWindow_.load(std::memory_order_relaxed);
    uint32_t ssthresh = ssthresh_.load(std::memory_order_relaxed);
    
    if (cwnd < ssthresh) {
        // Slow start: exponential growth
        congestionWindow_.fetch_add(1, std::memory_order_relaxed);
    } else {
        // Congestion avoidance: linear growth
        static thread_local int ackCount = 0;
        if (++ackCount >= cwnd) {
            congestionWindow_.fetch_add(1, std::memory_order_relaxed);
            ackCount = 0;
        }
    }
    
    // Update bandwidth estimate
    bytesAcked_.fetch_add(sizeof(FabricMessage), std::memory_order_relaxed);
}

void WANOptimizer::OnLoss(uint32_t sequence) {
    // Multiplicative decrease
    uint32_t cwnd = congestionWindow_.load(std::memory_order_relaxed);
    uint32_t newSsthresh = std::max(cwnd / 2, config_.minWindow);
    
    ssthresh_.store(newSsthresh, std::memory_order_relaxed);
    congestionWindow_.store(config_.minWindow, std::memory_order_relaxed);
}

void WANOptimizer::UpdateRTT(uint32_t rttMs) {
    // Exponential moving average
    uint32_t current = rttMs_.load(std::memory_order_relaxed);
    uint32_t newRtt = (current * 7 + rttMs) / 8;
    rttMs_.store(newRtt, std::memory_order_relaxed);
}

// ============================================================================
// Worker Thread
// ============================================================================

void WANOptimizer::BatchLoop() {
    while (!shutdown_) {
        // Check if batch needs to be flushed due to timeout
        {
            std::lock_guard<std::mutex> lock(batchMutex_);
            if (!currentBatch_.empty()) {
                auto elapsed = std::chrono::steady_clock::now() - batchStartTime_;
                if (elapsed > std::chrono::milliseconds(config_.batchMaxDelayMs)) {
                    SendBatch(currentBatch_);
                    currentBatch_.clear();
                }
            }
        }
        
        // Update bandwidth estimate
        static auto lastEstimateTime = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - lastEstimateTime).count();
        
        if (elapsed >= config_.bandwidthEstimationIntervalMs) {
            uint64_t acked = bytesAcked_.exchange(0, std::memory_order_relaxed);
            uint64_t bandwidth = (acked * 8) / (elapsed / 1000.0);  // bits per second
            lastBandwidthEstimate_.store(bandwidth, std::memory_order_relaxed);
            lastEstimateTime = now;
        }
        
        Sleep(1);
    }
}

// ============================================================================
// Compression
// ============================================================================

bool WANOptimizer::CompressBatch(const std::vector<FabricMessage>>& batch,
                                  std::vector<uint8_t>& output) {
    if (batch.empty()) {
        return false;
    }
    
    // Serialize batch
    size_t totalSize = batch.size() * sizeof(FabricMessage);
    std::vector<uint8_t> serialized(totalSize);
    
    uint8_t* ptr = serialized.data();
    for (const auto& msg : batch) {
        memcpy(ptr, &msg, sizeof(FabricMessage));
        ptr += sizeof(FabricMessage);
    }
    
    // Compress with zlib
    uLongf compressedSize = compressBound(static_cast<uLong>(totalSize));
    output.resize(compressedSize);
    
    int result = compress2(
        output.data(), &compressedSize,
        serialized.data(), static_cast<uLong>(totalSize),
        config_.compressionLevel
    );
    
    if (result != Z_OK) {
        return false;
    }
    
    output.resize(compressedSize);
    
    // Update stats
    bytesUncompressed_.fetch_add(totalSize, std::memory_order_relaxed);
    bytesCompressed_.fetch_add(compressedSize, std::memory_order_relaxed);
    
    return true;
}

bool WANOptimizer::DecompressBatch(const void* data, size_t len, 
                                    size_t originalSize,
                                    std::vector<FabricMessage>& output) {
    std::vector<uint8_t> decompressed(originalSize);
    
    uLongf destLen = static_cast<uLongf>(originalSize);
    int result = uncompress(
        decompressed.data(), &destLen,
        static_cast<const Bytef*>(data), static_cast<uLong>(len)
    );
    
    if (result != Z_OK) {
        return false;
    }
    
    // Deserialize
    size_t msgCount = destLen / sizeof(FabricMessage);
    output.resize(msgCount);
    
    for (size_t i = 0; i < msgCount; i++) {
        memcpy(&output[i], &decompressed[i * sizeof(FabricMessage)], 
               sizeof(FabricMessage));
    }
    
    return true;
}

// ============================================================================
// Helpers
// ============================================================================

bool WANOptimizer::ShouldFlushBatch() const {
    if (currentBatch_.size() >= config_.batchMaxSize) {
        return true;
    }
    
    auto elapsed = std::chrono::steady_clock::now() - batchStartTime_;
    if (elapsed > std::chrono::milliseconds(config_.batchMaxDelayMs)) {
        return true;
    }
    
    return false;
}

void WANOptimizer::SendBatch(const std::vector<FabricMessage>& batch) {
    if (!transport_ || batch.empty()) {
        return;
    }
    
    // Check if compression is beneficial
    size_t totalSize = batch.size() * sizeof(FabricMessage);
    bool shouldCompress = config_.enableCompression && 
                          totalSize > config_.compressionThreshold;
    
    if (shouldCompress) {
        std::vector<uint8_t> compressed;
        if (CompressBatch(batch, compressed)) {
            double ratio = 1.0 - (static_cast<double>(compressed.size()) / totalSize);
            
            // Only use compression if it helps (>10% reduction)
            if (ratio > 0.1) {
                // Send compressed batch
                // In production: would use special message type
                // For now: send first message as indicator
                if (!batch.empty()) {
                    transport_->Broadcast(batch[0]);
                }
            } else {
                // Compression not beneficial, send uncompressed
                for (const auto& msg : batch) {
                    transport_->Broadcast(msg);
                }
            }
        }
    } else {
        // Send uncompressed
        for (const auto& msg : batch) {
            transport_->Broadcast(msg);
        }
    }
    
    messagesSent_.fetch_add(batch.size(), std::memory_order_relaxed);
}

uint64_t WANOptimizer::GetTimestampUs() const {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (count.QuadPart * 1000000) / freq.QuadPart;
}

} // namespace Fabric
} // namespace RawrXD
