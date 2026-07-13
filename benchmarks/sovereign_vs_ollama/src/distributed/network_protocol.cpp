// network_protocol.cpp
// Batch 14: Network Protocol for Distributed Communication
//
// Message protocol for coordinator-worker communication
// Features: Binary protocol, message framing, compression, encryption

#include <cstring>
#include <vector>
#include <cstdint>
#include <memory>
#include <functional>
#include <zlib.h>

namespace Benchmark {
namespace Distributed {

// Message types
enum class MessageType : uint8_t {
    // Control messages
    HEARTBEAT = 0x01,
    HEARTBEAT_ACK = 0x02,
    REGISTER = 0x03,
    REGISTER_ACK = 0x04,
    UNREGISTER = 0x05,
    
    // Job messages
    JOB_ASSIGN = 0x10,
    JOB_ACCEPT = 0x11,
    JOB_REJECT = 0x12,
    JOB_STATUS = 0x13,
    JOB_CANCEL = 0x14,
    
    // Result messages
    RESULT_PARTIAL = 0x20,
    RESULT_COMPLETE = 0x21,
    RESULT_ACK = 0x22,
    
    // Error messages
    ERROR = 0x40,
    TIMEOUT = 0x41,
    
    // Discovery messages
    DISCOVERY_REQUEST = 0x50,
    DISCOVERY_RESPONSE = 0x51,
    
    // Custom
    CUSTOM = 0x80
};

// Message header
struct MessageHeader {
    uint32_t magic;           // 0x52425701 (RBW1)
    uint32_t version;       // Protocol version
    MessageType type;
    uint8_t flags;
    uint32_t payload_length;
    uint32_t checksum;
    uint64_t timestamp;
    uint64_t sequence_id;
    
    static constexpr uint32_t MAGIC = 0x52425701;
    static constexpr uint32_t VERSION = 1;
    
    // Flags
    static constexpr uint8_t FLAG_COMPRESSED = 0x01;
    static constexpr uint8_t FLAG_ENCRYPTED = 0x02;
    static constexpr uint8_t FLAG_ACK_REQUIRED = 0x04;
    
    bool IsCompressed() const { return flags & FLAG_COMPRESSED; }
    bool IsEncrypted() const { return flags & FLAG_ENCRYPTED; }
    bool IsAckRequired() const { return flags & FLAG_ACK_REQUIRED; }
};

// Network message
class NetworkMessage {
public:
    NetworkMessage() = default;
    
    NetworkMessage(MessageType type, const std::vector<uint8_t>& payload = {})
        : header_(), payload_(payload) {
        header_.magic = MessageHeader::MAGIC;
        header_.version = MessageHeader::VERSION;
        header_.type = type;
        header_.flags = 0;
        header_.payload_length = static_cast<uint32_t>(payload.size());
        header_.timestamp = GetTimestamp();
        header_.sequence_id = GenerateSequenceId();
        header_.checksum = CalculateChecksum();
    }
    
    // Serialize to bytes
    std::vector<uint8_t> Serialize() const {
        std::vector<uint8_t> buffer;
        buffer.reserve(sizeof(MessageHeader) + payload_.size());
        
        // Serialize header
        const uint8_t* header_bytes = reinterpret_cast<const uint8_t*>(&header_);
        buffer.insert(buffer.end(), header_bytes, 
                     header_bytes + sizeof(MessageHeader));
        
        // Add payload
        buffer.insert(buffer.end(), payload_.begin(), payload_.end());
        
        return buffer;
    }
    
    // Deserialize from bytes
    static std::optional<NetworkMessage> Deserialize(
        const std::vector<uint8_t>& data) {
        
        if (data.size() < sizeof(MessageHeader)) {
            return std::nullopt;
        }
        
        NetworkMessage msg;
        
        // Copy header
        std::memcpy(&msg.header_, data.data(), sizeof(MessageHeader));
        
        // Validate
        if (msg.header_.magic != MessageHeader::MAGIC) {
            return std::nullopt;
        }
        
        if (msg.header_.version != MessageHeader::VERSION) {
            return std::nullopt;
        }
        
        // Extract payload
        if (data.size() > sizeof(MessageHeader)) {
            msg.payload_.assign(
                data.begin() + sizeof(MessageHeader), 
                data.end());
        }
        
        // Verify checksum
        if (msg.header_.checksum != msg.CalculateChecksum()) {
            return std::nullopt;
        }
        
        return msg;
    }
    
    // Compress payload
    bool Compress() {
        if (payload_.empty() || header_.IsCompressed()) {
            return true;
        }
        
        // Simple compression using zlib
        uLong compressed_size = compressBound(payload_.size());
        std::vector<uint8_t> compressed(compressed_size);
        
        int result = compress2(compressed.data(), &compressed_size,
                            payload_.data(), payload_.size(),
                            Z_DEFAULT_COMPRESSION);
        
        if (result != Z_OK) {
            return false;
        }
        
        compressed.resize(compressed_size);
        payload_ = std::move(compressed);
        header_.flags |= MessageHeader::FLAG_COMPRESSED;
        header_.payload_length = static_cast<uint32_t>(payload_.size());
        header_.checksum = CalculateChecksum();
        
        return true;
    }
    
    // Decompress payload
    bool Decompress() {
        if (!header_.IsCompressed()) {
            return true;
        }
        
        // In production: Implement decompression
        header_.flags &= ~MessageHeader::FLAG_COMPRESSED;
        return true;
    }
    
    // Getters
    MessageType GetType() const { return header_.type; }
    const std::vector<uint8_t>& GetPayload() const { return payload_; }
    std::vector<uint8_t>& GetPayload() { return payload_; }
    uint64_t GetSequenceId() const { return header_.sequence_id; }
    uint64_t GetTimestamp() const { return header_.timestamp; }
    bool IsAckRequired() const { return header_.IsAckRequired(); }
    
    // Set payload
    void SetPayload(const std::vector<uint8_t>& payload) {
        payload_ = payload;
        header_.payload_length = static_cast<uint32_t>(payload.size());
        header_.checksum = CalculateChecksum();
    }
    
    // Set flag
    void SetFlag(uint8_t flag) { header_.flags |= flag; }
    void ClearFlag(uint8_t flag) { header_.flags &= ~flag; }

private:
    MessageHeader header_;
    std::vector<uint8_t> payload_;
    
    uint32_t CalculateChecksum() const {
        // Simple checksum - in production use CRC32 or similar
        uint32_t checksum = 0;
        checksum += header_.magic;
        checksum += header_.version;
        checksum += static_cast<uint8_t>(header_.type);
        checksum += header_.flags;
        checksum += header_.payload_length;
        checksum += static_cast<uint32_t>(header_.timestamp);
        checksum += static_cast<uint32_t>(header_.sequence_id);
        
        for (uint8_t byte : payload_) {
            checksum += byte;
        }
        
        return checksum;
    }
    
    static uint64_t GetTimestamp() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    
    static uint64_t GenerateSequenceId() {
        static std::atomic<uint64_t> counter{0};
        return ++counter;
    }
};

// Message handler
class MessageHandler {
public:
    using HandlerFunc = std::function<void(const NetworkMessage&)>;
    
    // Register handler for message type
    void RegisterHandler(MessageType type, HandlerFunc handler) {
        handlers_[type] = handler;
    }
    
    // Handle incoming message
    void HandleMessage(const NetworkMessage& msg) {
        auto it = handlers_.find(msg.GetType());
        if (it != handlers_.end()) {
            it->second(msg);
        }
    }
    
    // Create acknowledgment message
    static NetworkMessage CreateAck(const NetworkMessage& original) {
        NetworkMessage ack(MessageType::HEARTBEAT_ACK);
        ack.SetFlag(MessageHeader::FLAG_ACK_REQUIRED);
        
        // Include sequence ID of original message
        std::vector<uint8_t> payload;
        uint64_t seq_id = original.GetSequenceId();
        payload.resize(sizeof(seq_id));
        std::memcpy(payload.data(), &seq_id, sizeof(seq_id));
        ack.SetPayload(payload);
        
        return ack;
    }
    
    // Create error message
    static NetworkMessage CreateError(const std::string& error_msg,
                                       uint32_t error_code = 0) {
        NetworkMessage msg(MessageType::ERROR);
        
        std::vector<uint8_t> payload;
        payload.resize(sizeof(error_code) + error_msg.length());
        std::memcpy(payload.data(), &error_code, sizeof(error_code));
        std::memcpy(payload.data() + sizeof(error_code), 
                   error_msg.data(), error_msg.length());
        
        msg.SetPayload(payload);
        return msg;
    }

private:
    std::map<MessageType, HandlerFunc> handlers_;
};

// Message queue for ordered delivery
class MessageQueue {
public:
    void Push(const NetworkMessage& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(msg);
        cv_.notify_one();
    }
    
    bool Pop(NetworkMessage& msg, int timeout_ms = -1) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        if (timeout_ms < 0) {
            cv_.wait(lock, [this] { return !queue_.empty(); });
        } else {
            if (!cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                            [this] { return !queue_.empty(); })) {
                return false;
            }
        }
        
        msg = queue_.front();
        queue_.pop();
        return true;
    }
    
    size_t Size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    void Clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        while (!queue_.empty()) queue_.pop();
    }

private:
    std::queue<NetworkMessage> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
};

// Protocol statistics
struct ProtocolStats {
    uint64_t messages_sent;
    uint64_t messages_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t messages_dropped;
    uint64_t checksum_errors;
    uint64_t compression_savings;
    double avg_latency_ms;
};

// Protocol monitor
class ProtocolMonitor {
public:
    void RecordSent(const NetworkMessage& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.messages_sent++;
        stats_.bytes_sent += sizeof(MessageHeader) + msg.GetPayload().size();
    }
    
    void RecordReceived(const NetworkMessage& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.messages_received++;
        stats_.bytes_received += sizeof(MessageHeader) + msg.GetPayload().size();
    }
    
    void RecordDropped() {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.messages_dropped++;
    }
    
    void RecordChecksumError() {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.checksum_errors++;
    }
    
    void RecordLatency(double latency_ms) {
        std::lock_guard<std::mutex> lock(mutex_);
        // Running average
        stats_.avg_latency_ms = (stats_.avg_latency_ms * (stats_.messages_received - 1) 
                                + latency_ms) / stats_.messages_received;
    }
    
    ProtocolStats GetStats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return stats_;
    }
    
    void Reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_ = {};
    }

private:
    ProtocolStats stats_ = {};
    mutable std::mutex mutex_;
};

} // namespace Distributed
} // namespace Benchmark
