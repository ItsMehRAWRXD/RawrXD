#include "LoopbackTransport.h"
#include <cstring>
#include <random>

namespace RawrXD {
namespace Fabric {

// ============================================================================
// NodeRingBuffer Implementation
// ============================================================================
NodeRingBuffer::NodeRingBuffer() {
    hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

NodeRingBuffer::~NodeRingBuffer() {
    if (hEvent) {
        CloseHandle(hEvent);
    }
}

bool NodeRingBuffer::Write(const FabricMessage& msg, uint64_t sequence) {
    uint64_t writeIdx = this->writeIdx.load(std::memory_order_relaxed);
    uint64_t readIdx = this->readIdx.load(std::memory_order_acquire);
    
    // Check if full
    if (writeIdx - readIdx >= RING_SIZE) {
        return false;  // Ring full
    }
    
    size_t idx = writeIdx & (RING_SIZE - 1);
    
    // Wait for entry to be consumed
    while (entries[idx].ready.load(std::memory_order_acquire)) {
        _mm_pause();
        readIdx = this->readIdx.load(std::memory_order_acquire);
        if (writeIdx - readIdx >= RING_SIZE) {
            return false;
        }
    }
    
    // Write entry
    entries[idx].message = msg;
    entries[idx].sequence.store(sequence, std::memory_order_relaxed);
    entries[idx].ready.store(true, std::memory_order_release);
    
    // Advance write index
    this->writeIdx.store(writeIdx + 1, std::memory_order_release);
    
    // Signal receiver
    SetEvent(hEvent);
    
    return true;
}

bool NodeRingBuffer::Read(FabricMessage& msg, uint64_t& sequence) {
    uint64_t readIdx = this->readIdx.load(std::memory_order_relaxed);
    uint64_t writeIdx = this->writeIdx.load(std::memory_order_acquire);
    
    // Check if empty
    if (readIdx >= writeIdx) {
        return false;
    }
    
    size_t idx = readIdx & (RING_SIZE - 1);
    
    // Wait for entry to be ready
    while (!entries[idx].ready.load(std::memory_order_acquire)) {
        _mm_pause();
    }
    
    // Read entry
    msg = entries[idx].message;
    sequence = entries[idx].sequence.load(std::memory_order_relaxed);
    entries[idx].ready.store(false, std::memory_order_release);
    
    // Advance read index
    this->readIdx.store(readIdx + 1, std::memory_order_release);
    
    return true;
}

bool NodeRingBuffer::IsEmpty() const {
    return readIdx.load(std::memory_order_acquire) >= 
           writeIdx.load(std::memory_order_acquire);
}

size_t NodeRingBuffer::GetAvailable() const {
    uint64_t writeIdx = this->writeIdx.load(std::memory_order_acquire);
    uint64_t readIdx = this->readIdx.load(std::memory_order_acquire);
    return writeIdx - readIdx;
}

// ============================================================================
// LoopbackTransport Implementation
// ============================================================================
LoopbackTransport::LoopbackTransport()
    : localNodeId_(0)
    , initialized_(false)
    , shutdown_(false)
    , hReceiveThread_(nullptr)
    , simulatedLatencyUs_(0)
    , packetLossProbability_(0.0)
    , messageHandler_(nullptr)
    , errorHandler_(nullptr) {
}

LoopbackTransport::~LoopbackTransport() {
    Shutdown();
}

bool LoopbackTransport::Initialize(uint32_t nodeId) {
    if (initialized_) {
        return false;
    }
    
    localNodeId_ = nodeId;
    shutdown_ = false;
    
    // Start receive thread
    hReceiveThread_ = CreateThread(
        nullptr, 0,
        ReceiveThreadProc,
        this,
        0, nullptr
    );
    
    if (!hReceiveThread_) {
        return false;
    }
    
    initialized_ = true;
    return true;
}

void LoopbackTransport::Shutdown() {
    if (!initialized_) {
        return;
    }
    
    shutdown_ = true;
    
    // Signal all peer events to wake receive thread
    {
        std::shared_lock<std::shared_mutex> lock(peersMutex_);
        for (auto& [nodeId, peer] : peers_) {
            if (peer && peer->hEvent) {
                SetEvent(peer->hEvent);
            }
        }
    }
    
    // Wait for receive thread
    if (hReceiveThread_) {
        WaitForSingleObject(hReceiveThread_, 5000);
        CloseHandle(hReceiveThread_);
        hReceiveThread_ = nullptr;
    }
    
    // Clear peers
    {
        std::unique_lock<std::shared_mutex> lock(peersMutex_);
        peers_.clear();
    }
    
    initialized_ = false;
}

bool LoopbackTransport::ConnectToNode(uint32_t nodeId, const char* address) {
    std::unique_lock<std::shared_mutex> lock(peersMutex_);
    
    if (peers_.find(nodeId) != peers_.end()) {
        return false;  // Already connected
    }
    
    // Create ring buffer for this peer
    auto peer = std::make_unique<NodeRingBuffer>();
    peers_[nodeId] = std::move(peer);
    
    return true;
}

void LoopbackTransport::DisconnectNode(uint32_t nodeId) {
    std::unique_lock<std::shared_mutex> lock(peersMutex_);
    peers_.erase(nodeId);
}

bool LoopbackTransport::IsConnected(uint32_t nodeId) {
    std::shared_lock<std::shared_mutex> lock(peersMutex_);
    return peers_.find(nodeId) != peers_.end();
}

bool LoopbackTransport::Send(uint32_t dstNodeId, const FabricMessage& msg) {
    if (!initialized_ || shutdown_) {
        return false;
    }
    
    // Simulate packet loss
    if (packetLossProbability_ > 0.0) {
        static thread_local std::mt19937 gen(GetCurrentThreadId());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        if (dis(gen) < packetLossProbability_) {
            return false;  // Packet "lost"
        }
    }
    
    // Simulate latency
    if (simulatedLatencyUs_ > 0) {
        Sleep(simulatedLatencyUs_ / 1000);
    }
    
    std::shared_lock<std::shared_mutex> lock(peersMutex_);
    
    auto it = peers_.find(dstNodeId);
    if (it == peers_.end() || !it->second) {
        if (errorHandler_) {
            errorHandler_(dstNodeId, "Node not connected");
        }
        return false;
    }
    
    // Create mutable copy and set header
    FabricMessage msgCopy = msg;
    msgCopy.header.srcNodeId = localNodeId_;
    msgCopy.header.dstNodeId = dstNodeId;
    msgCopy.header.timestamp = GetTickCount64() * 1000;  // μs
    msgCopy.header.sequence = sequenceCounter_.fetch_add(1, std::memory_order_relaxed);
    
    // Calculate checksum
    msgCopy.header.checksum = CalculateCRC32(
        &msgCopy.payload, 
        msgCopy.header.payloadSize
    );
    
    // Write to ring buffer
    if (!it->second->Write(msgCopy, msgCopy.header.sequence)) {
        if (errorHandler_) {
            errorHandler_(dstNodeId, "Ring buffer full");
        }
        return false;
    }
    
    // Update stats
    messagesSent_.fetch_add(1, std::memory_order_relaxed);
    bytesSent_.fetch_add(sizeof(FabricMessage), std::memory_order_relaxed);
    
    return true;
}

bool LoopbackTransport::Broadcast(const FabricMessage& msg) {
    std::shared_lock<std::shared_mutex> lock(peersMutex_);
    
    bool allSent = true;
    for (const auto& [nodeId, peer] : peers_) {
        if (!Send(nodeId, msg)) {
            allSent = false;
        }
    }
    
    return allSent;
}

void LoopbackTransport::SetMessageHandler(MessageHandler handler) {
    messageHandler_ = handler;
}

void LoopbackTransport::SetErrorHandler(ErrorHandler handler) {
    errorHandler_ = handler;
}

uint64_t LoopbackTransport::GetBytesSent() const {
    return bytesSent_.load(std::memory_order_relaxed);
}

uint64_t LoopbackTransport::GetBytesReceived() const {
    return bytesReceived_.load(std::memory_order_relaxed);
}

uint64_t LoopbackTransport::GetMessagesSent() const {
    return messagesSent_.load(std::memory_order_relaxed);
}

uint64_t LoopbackTransport::GetMessagesReceived() const {
    return messagesReceived_.load(std::memory_order_relaxed);
}

uint32_t LoopbackTransport::GetLatencyUs() const {
    // For loopback, latency is just simulated latency
    return simulatedLatencyUs_;
}

void LoopbackTransport::SimulateLatency(uint32_t latencyUs) {
    simulatedLatencyUs_ = latencyUs;
}

void LoopbackTransport::SimulatePacketLoss(double probability) {
    packetLossProbability_ = probability;
}

DWORD WINAPI LoopbackTransport::ReceiveThreadProc(LPVOID param) {
    auto* transport = static_cast<LoopbackTransport*>(param);
    transport->ReceiveLoop();
    return 0;
}

void LoopbackTransport::ReceiveLoop() {
    // Build array of events to wait on
    std::vector<HANDLE> events;
    std::vector<uint32_t> nodeIds;
    
    while (!shutdown_) {
        events.clear();
        nodeIds.clear();
        
        // Collect peer events
        {
            std::shared_lock<std::shared_mutex> lock(peersMutex_);
            for (auto& [nodeId, peer] : peers_) {
                if (peer && peer->hEvent) {
                    events.push_back(peer->hEvent);
                    nodeIds.push_back(nodeId);
                }
            }
        }
        
        if (events.empty()) {
            Sleep(1);  // No peers yet
            continue;
        }
        
        // Wait for any peer to have data
        DWORD waitResult = WaitForMultipleObjects(
            static_cast<DWORD>(events.size()),
            events.data(),
            FALSE,  // Wait for any
            100     // 100ms timeout
        );
        
        if (waitResult == WAIT_TIMEOUT || waitResult == WAIT_FAILED) {
            continue;
        }
        
        // Check all peers for messages (not just the signaled one)
        {
            std::shared_lock<std::shared_mutex> lock(peersMutex_);
            
            for (auto& [nodeId, peer] : peers_) {
                if (!peer) continue;
                
                FabricMessage msg;
                uint64_t sequence;
                
                while (peer->Read(msg, sequence)) {
                    // Update stats
                    messagesReceived_.fetch_add(1, std::memory_order_relaxed);
                    bytesReceived_.fetch_add(sizeof(FabricMessage), std::memory_order_relaxed);
                    
                    // Validate checksum
                    uint32_t expectedChecksum = CalculateCRC32(
                        &msg.payload,
                        msg.header.payloadSize
                    );
                    
                    if (expectedChecksum != msg.header.checksum) {
                        if (errorHandler_) {
                            errorHandler_(nodeId, "Checksum mismatch");
                        }
                        continue;
                    }
                    
                    // Deliver to handler
                    if (messageHandler_) {
                        messageHandler_(msg, nodeId);
                    }
                }
            }
        }
    }
}

uint32_t LoopbackTransport::CalculateCRC32(const void* data, size_t len) {
    // Simple CRC32 implementation
    static const uint32_t crcTable[256] = {
        // ... CRC table would go here
        // For now, use simple hash
    };
    
    // Simple FNV-1a hash as placeholder
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 16777619u;
    }
    return hash;
}

// Factory function
FabricTransport* CreateLoopbackTransport() {
    return new LoopbackTransport();
}

} // namespace Fabric
} // namespace RawrXD
