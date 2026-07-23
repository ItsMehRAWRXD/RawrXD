// ============================================================================
// NativeAgentFabric.hpp - Zero-Copy Message Passing Layer
// The "fiber optic metal" between agents, runtime, model, tools, and IDE
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <atomic>
#include <shared_mutex>

namespace Sovereign {

// Message priority
enum class MessagePriority {
    CRITICAL = 0,
    HIGH = 1,
    NORMAL = 2,
    LOW = 3,
    BACKGROUND = 4
};

// Message types
enum class MessageType {
    AGENT_TO_AGENT,
    AGENT_TO_TOOL,
    TOOL_TO_AGENT,
    AGENT_TO_MODEL,
    MODEL_TO_AGENT,
    AGENT_TO_IDE,
    IDE_TO_AGENT,
    TELEMETRY,
    CONTROL,
    SYSTEM
};

// Fabric message
struct FabricMessage {
    uint64_t id;
    MessageType type;
    MessagePriority priority;
    std::string source;
    std::string destination;
    std::string subject;
    std::vector<uint8_t> payload;
    uint64_t timestamp;
    uint64_t timeout;
    bool requiresAck;
    bool isResponse;
    uint64_t responseTo;
};

// Message queue
struct MessageQueue {
    std::string owner;
    std::vector<FabricMessage> messages;
    std::atomic<uint64_t> readIndex{0};
    std::atomic<uint64_t> writeIndex{0};
    size_t capacity;
};

// Fabric statistics
struct FabricStats {
    uint64_t messagesSent;
    uint64_t messagesReceived;
    uint64_t messagesDropped;
    uint64_t bytesTransferred;
    uint64_t activeConnections;
    double avgLatencyUs;
    double peakThroughput;
};

// Native agent fabric
class NativeAgentFabric {
public:
    NativeAgentFabric();
    ~NativeAgentFabric();

    bool Initialize(size_t queueSize = 4096);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // Connection management
    bool Connect(const std::string& endpoint);
    bool Disconnect(const std::string& endpoint);
    bool IsConnected(const std::string& endpoint) const;
    std::vector<std::string> GetConnectedEndpoints() const;

    // Message passing
    bool Send(const FabricMessage& message);
    bool SendAsync(const FabricMessage& message, std::function<void(bool)> callback);
    bool Receive(const std::string& endpoint, FabricMessage& message);
    bool Peek(const std::string& endpoint, FabricMessage& message) const;
    size_t GetQueueDepth(const std::string& endpoint) const;

    // Zero-copy transfer
    bool SendBuffer(const std::string& endpoint, const void* data, size_t size);
    bool ReceiveBuffer(const std::string& endpoint, void* data, size_t size);
    void* GetDirectBuffer(const std::string& endpoint, size_t& size);

    // Broadcast
    bool Broadcast(const FabricMessage& message);
    bool BroadcastToType(MessageType type, const FabricMessage& message);

    // Callbacks
    void SetMessageHandler(std::function<void(const FabricMessage&)> handler);
    void SetConnectionHandler(std::function<void(const std::string&, bool)> handler);

    // Flow control
    void SetRateLimit(const std::string& endpoint, uint64_t messagesPerSecond);
    bool IsRateLimited(const std::string& endpoint) const;

    // Statistics
    FabricStats GetStats() const;
    void ResetStats();

private:
    bool initialized_ = false;
    std::unordered_map<std::string, MessageQueue> queues_;
    std::unordered_map<std::string, uint64_t> rateLimits_;
    std::unordered_map<std::string, std::vector<uint64_t>> rateLimitTimestamps_;
    FabricStats stats_;
    mutable std::shared_mutex mutex_;
    
    std::function<void(const FabricMessage&)> messageHandler_;
    std::function<void(const std::string&, bool)> connectionHandler_;
    
    uint64_t nextMessageId_ = 1;
    uint8_t* sharedBuffer_ = nullptr;
    size_t sharedBufferSize_ = 0;
};

} // namespace Sovereign
