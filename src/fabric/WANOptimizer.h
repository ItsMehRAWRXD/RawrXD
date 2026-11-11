#pragma once

#include "FabricTransport.h"
#include <cstdint>
#include <vector>
#include <queue>
#include <mutex>
#include <chrono>

namespace RawrXD {
namespace Fabric {

// ============================================================================
// WAN Optimizer - Compression, Batching, and Congestion Control
// 
// Optimizes fabric communication over wide-area networks:
// - Message batching to reduce overhead
// - Compression for large payloads
// - Adaptive congestion control
// - Bandwidth estimation
// ============================================================================

struct WANConfig {
    // Batching
    bool enableBatching = true;
    uint32_t batchMaxSize = 64;           // Max messages per batch
    uint32_t batchMaxDelayMs = 5;         // Max delay before sending
    
    // Compression
    bool enableCompression = true;
    uint32_t compressionThreshold = 256;  // Compress messages > this size
    int compressionLevel = 6;             // 1-9 (higher = better ratio, slower)
    
    // Congestion control
    bool enableCongestionControl = true;
    uint32_t initialWindow = 16;          // Initial congestion window
    uint32_t minWindow = 1;               // Minimum window
    uint32_t maxWindow = 1024;            // Maximum window
    
    // Bandwidth estimation
    uint32_t bandwidthEstimationIntervalMs = 1000;
};

struct BatchHeader {
    uint32_t magic;           // 0x57414E42 "WANB"
    uint32_t messageCount;    // Number of messages in batch
    uint32_t compressedSize;  // 0 = uncompressed
    uint32_t originalSize;    // Size before compression
    uint64_t timestamp;       // Batch creation time
};

struct MessageBatch {
    BatchHeader header;
    std::vector<uint8_t> data;
    std::chrono::steady_clock::time_point creationTime;
};

// ============================================================================
// WAN Optimizer
// ============================================================================
class WANOptimizer {
public:
    WANOptimizer();
    ~WANOptimizer();
    
    // Configuration
    bool Configure(const WANConfig& config);
    
    // Lifecycle
    bool Initialize(FabricTransport* transport);
    void Shutdown();
    
    // Message operations
    bool QueueMessage(const FabricMessage& msg);
    bool FlushBatch();  // Force send current batch
    
    // Statistics
    struct Stats {
        uint64_t messagesBatched;
        uint64_t messagesSent;
        uint64_t bytesCompressed;
        uint64_t bytesUncompressed;
        double compressionRatio;
        double avgBatchSize;
        uint32_t currentWindow;
        double estimatedBandwidthMbps;
    };
    Stats GetStats() const;
    
    // Congestion control
    void OnAck(uint32_t sequence);
    void OnLoss(uint32_t sequence);
    void UpdateRTT(uint32_t rttMs);
    
private:
    WANConfig config_;
    FabricTransport* transport_;
    bool initialized_;
    bool shutdown_;
    
    // Batching
    std::mutex batchMutex_;
    std::vector<FabricMessage> currentBatch_;
    std::chrono::steady_clock::time_point batchStartTime_;
    
    // Compression
    std::vector<uint8_t> compressBuffer_;
    bool CompressBatch(const std::vector<FabricMessage>& batch, 
                       std::vector<uint8_t>& output);
    bool DecompressBatch(const void* data, size_t len, size_t originalSize,
                         std::vector<FabricMessage>& output);
    
    // Congestion control (simplified TCP-like)
    std::atomic<uint32_t> congestionWindow_{16};
    std::atomic<uint32_t> ssthresh_{1024};
    std::atomic<uint32_t> rttMs_{50};
    
    // Bandwidth estimation
    alignas(64) std::atomic<uint64_t> bytesSent_{0};
    alignas(64) std::atomic<uint64_t> bytesAcked_{0};
    alignas(64) std::atomic<uint64_t> lastBandwidthEstimate_{0};
    
    // Statistics
    alignas(64) std::atomic<uint64_t> messagesBatched_{0};
    alignas(64) std::atomic<uint64_t> messagesSent_{0};
    alignas(64) std::atomic<uint64_t> bytesCompressed_{0};
    alignas(64) std::atomic<uint64_t> bytesUncompressed_{0};
    
    // Worker thread
    std::thread batchThread_;
    void BatchLoop();
    
    // Helpers
    bool ShouldFlushBatch() const;
    void SendBatch(const std::vector<FabricMessage>& batch);
    uint64_t GetTimestampUs() const;
};

} // namespace Fabric
} // namespace RawrXD
