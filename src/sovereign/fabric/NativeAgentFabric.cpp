// ============================================================================
// NativeAgentFabric.cpp - Zero-Copy Message Passing Implementation
// ============================================================================

#include "NativeAgentFabric.hpp"
#include <cstring>
#include <algorithm>
#include <iostream>

namespace Sovereign {

NativeAgentFabric::NativeAgentFabric() = default;
NativeAgentFabric::~NativeAgentFabric() {
    Shutdown();
}

bool NativeAgentFabric::Initialize(size_t queueSize) {
    if (initialized_) Shutdown();
    
    // Allocate shared zero-copy buffer (64MB)
    sharedBufferSize_ = 64ULL << 20;
    sharedBuffer_ = new uint8_t[sharedBufferSize_];
    if (!sharedBuffer_) return false;
    
    initialized_ = true;
    return true;
}

void NativeAgentFabric::Shutdown() {
    delete[] sharedBuffer_;
    sharedBuffer_ = nullptr;
    queues_.clear();
    initialized_ = false;
}

bool NativeAgentFabric::Connect(const std::string& endpoint) {
    std::unique_lock lock(mutex_);
    
    if (queues_.find(endpoint) != queues_.end()) return false;
    
    MessageQueue queue;
    queue.owner = endpoint;
    queue.capacity = 4096;
    queues_[endpoint] = queue;
    stats_.activeConnections++;
    
    if (connectionHandler_) connectionHandler_(endpoint, true);
    return true;
}

bool NativeAgentFabric::Disconnect(const std::string& endpoint) {
    std::unique_lock lock(mutex_);
    auto it = queues_.find(endpoint);
    if (it == queues_.end()) return false;
    
    queues_.erase(it);
    stats_.activeConnections--;
    
    if (connectionHandler_) connectionHandler_(endpoint, false);
    return true;
}

bool NativeAgentFabric::Send(const FabricMessage& message) {
    std::unique_lock lock(mutex_);
    
    auto it = queues_.find(message.destination);
    if (it == queues_.end()) return false;
    
    // Check rate limit
    if (IsRateLimited(message.source)) {
        stats_.messagesDropped++;
        return false;
    }
    
    FabricMessage msg = message;
    msg.id = nextMessageId_++;
    msg.timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    it->second.messages.push_back(msg);
    stats_.messagesSent++;
    stats_.bytesTransferred += msg.payload.size();
    
    if (messageHandler_) messageHandler_(msg);
    return true;
}

bool NativeAgentFabric::Receive(const std::string& endpoint, FabricMessage& message) {
    std::unique_lock lock(mutex_);
    
    auto it = queues_.find(endpoint);
    if (it == queues_.end() || it->second.messages.empty()) return false;
    
    message = it->second.messages.front();
    it->second.messages.erase(it->second.messages.begin());
    stats_.messagesReceived++;
    
    return true;
}

bool NativeAgentFabric::SendBuffer(const std::string& endpoint, const void* data, size_t size) {
    if (size > sharedBufferSize_) return false;
    
    memcpy(sharedBuffer_, data, size);
    
    FabricMessage msg;
    msg.type = MessageType::AGENT_TO_AGENT;
    msg.destination = endpoint;
    msg.payload.assign(sharedBuffer_, sharedBuffer_ + size);
    
    return Send(msg);
}

bool NativeAgentFabric::ReceiveBuffer(const std::string& endpoint, void* data, size_t size) {
    FabricMessage msg;
    if (!Receive(endpoint, msg)) return false;
    
    size_t copySize = std::min(size, msg.payload.size());
    memcpy(data, msg.payload.data(), copySize);
    return true;
}

void* NativeAgentFabric::GetDirectBuffer(const std::string& endpoint, size_t& size) {
    size = sharedBufferSize_;
    return sharedBuffer_;
}

bool NativeAgentFabric::Broadcast(const FabricMessage& message) {
    std::unique_lock lock(mutex_);
    
    for (auto& [endpoint, queue] : queues_) {
        if (endpoint != message.source) {
            FabricMessage msg = message;
            msg.destination = endpoint;
            queue.messages.push_back(msg);
            stats_.messagesSent++;
        }
    }
    return true;
}

bool NativeAgentFabric::IsRateLimited(const std::string& endpoint) const {
    auto it = rateLimits_.find(endpoint);
    if (it == rateLimits_.end()) return false;
    
    auto tsIt = rateLimitTimestamps_.find(endpoint);
    if (tsIt == rateLimitTimestamps_.end()) return false;
    
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Remove timestamps older than 1 second
    auto& timestamps = tsIt->second;
    timestamps.erase(std::remove_if(timestamps.begin(), timestamps.end(),
        [now](uint64_t ts) { return (now - ts) > 1000; }), timestamps.end());
    
    return timestamps.size() >= it->second;
}

FabricStats NativeAgentFabric::GetStats() const {
    return stats_;
}

} // namespace Sovereign
