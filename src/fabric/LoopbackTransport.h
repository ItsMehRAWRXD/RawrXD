#pragma once

#include "FabricTransport.h"
#include "TensorResidency.h"
#include <Windows.h>
#include <vector>
#include <atomic>
#include <memory>

namespace RawrXD {
namespace Fabric {

// ============================================================================
// Loopback Transport - Shared Memory Ring Buffer for Local Testing
// 
// Simulates distributed fabric on single node using lock-free ring buffers.
// Zero-copy between "nodes" on same machine.
// ============================================================================

// Ring buffer entry
struct alignas(128) RingBufferEntry {
    std::atomic<uint64_t> sequence;     // Sequence number for ordering
    FabricMessage message;
    std::atomic<bool> ready;            // Writer signals ready
    
    RingBufferEntry() : sequence(0), ready(false) {}
};

// Per-node ring buffer
struct NodeRingBuffer {
    static constexpr size_t RING_SIZE = 1024;  // Must be power of 2
    
    alignas(64) std::atomic<uint64_t> writeIdx{0};
    alignas(64) std::atomic<uint64_t> readIdx{0};
    alignas(64) RingBufferEntry entries[RING_SIZE];
    
    HANDLE hEvent;  // Signal for new messages
    
    NodeRingBuffer();
    ~NodeRingBuffer();
    
    bool Write(const FabricMessage& msg, uint64_t sequence);
    bool Read(FabricMessage& msg, uint64_t& sequence);
    bool IsEmpty() const;
    size_t GetAvailable() const;
};

// ============================================================================
// Loopback Transport Implementation
// ============================================================================
class LoopbackTransport : public FabricTransport {
public:
    LoopbackTransport();
    ~LoopbackTransport() override;
    
    // FabricTransport interface
    bool Initialize(uint32_t nodeId) override;
    void Shutdown() override;
    
    bool ConnectToNode(uint32_t nodeId, const char* address) override;
    void DisconnectNode(uint32_t nodeId) override;
    bool IsConnected(uint32_t nodeId) override;
    
    bool Send(uint32_t dstNodeId, const FabricMessage& msg) override;
    bool Broadcast(const FabricMessage& msg) override;
    
    void SetMessageHandler(MessageHandler handler) override;
    void SetErrorHandler(ErrorHandler handler) override;
    
    uint64_t GetBytesSent() const override;
    uint64_t GetBytesReceived() const override;
    uint64_t GetMessagesSent() const override;
    uint64_t GetMessagesReceived() const override;
    uint32_t GetLatencyUs() const override;
    
    const char* GetTransportName() const override { return "Loopback"; }
    
    // Loopback-specific
    void SimulateLatency(uint32_t latencyUs);  // Add artificial delay
    void SimulatePacketLoss(double probability);  // 0.0-1.0
    
private:
    uint32_t localNodeId_;
    bool initialized_;
    bool shutdown_;
    
    // Connected nodes (nodeId -> ring buffer)
    std::unordered_map<uint32_t, std::unique_ptr<NodeRingBuffer>> peers_;
    std::shared_mutex peersMutex_;
    
    // Statistics
    alignas(64) std::atomic<uint64_t> bytesSent_{0};
    alignas(64) std::atomic<uint64_t> bytesReceived_{0};
    alignas(64) std::atomic<uint64_t> messagesSent_{0};
    alignas(64) std::atomic<uint64_t> messagesReceived_{0};
    
    // Simulation parameters
    uint32_t simulatedLatencyUs_;
    double packetLossProbability_;
    
    // Handlers
    MessageHandler messageHandler_;
    ErrorHandler errorHandler_;
    
    // Worker thread for receiving
    HANDLE hReceiveThread_;
    static DWORD WINAPI ReceiveThreadProc(LPVOID param);
    void ReceiveLoop();
    
    // Sequence counter
    std::atomic<uint32_t> sequenceCounter_{0};
    
    // Helper
    uint32_t CalculateCRC32(const void* data, size_t len);
};

} // namespace Fabric
} // namespace RawrXD
