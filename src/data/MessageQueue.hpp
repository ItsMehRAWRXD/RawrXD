/**
 * MessageQueue.hpp
 *
 * Phase M Batch 3/5: Message Queue System
 *
 * Distributed message queue system with support for multiple backends,
 * message patterns, and guaranteed delivery.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <queue>
#include <chrono>
#include <future>

namespace Data {

// ============================================================================
// Forward Declarations
// ============================================================================

class Message;
class Queue;
class MessageQueue;
class Consumer;
class Producer;

// ============================================================================
// Message Priority
// ============================================================================

enum class MessagePriority {
    LOWEST = 0,
    LOW = 1,
    NORMAL = 2,
    HIGH = 3,
    HIGHEST = 4
};

// ============================================================================
// Message
// ============================================================================

/**
 * Message in the queue.
 */
class Message {
public:
    using PayloadType = std::vector<uint8_t>;
    using HeadersType = std::map<std::string, std::string>;
    
    struct Config {
        std::string messageId;
        std::string correlationId;
        std::string replyTo;
        std::string contentType;
        PayloadType payload;
        HeadersType headers;
        MessagePriority priority;
        std::chrono::system_clock::time_point timestamp;
        std::optional<std::chrono::system_clock::time_point> expiresAt;
        uint32_t deliveryCount;
        bool persistent;
    };
    
    explicit Message(const Config& config);
    
    // Factory methods
    static Message Create(const std::string& content);
    static Message Create(const std::vector<uint8_t>& payload);
    static Message CreateJson(const std::string& json);
    
    template<typename T>
    static Message CreateFromObject(const T& obj);
    
    // Accessors
    const std::string& GetMessageId() const { return config_.messageId; }
    const std::string& GetCorrelationId() const { return config_.correlationId; }
    const PayloadType& GetPayload() const { return config_.payload; }
    PayloadType& GetPayload() { return config_.payload; }
    const HeadersType& GetHeaders() const { return config_.headers; }
    MessagePriority GetPriority() const { return config_.priority; }
    
    // Headers
    void SetHeader(const std::string& key, const std::string& value);
    std::optional<std::string> GetHeader(const std::string& key) const;
    bool HasHeader(const std::string& key) const;
    
    // Payload helpers
    std::string GetPayloadAsString() const;
    std::string GetPayloadAsJson() const;
    template<typename T>
    T GetPayloadAsObject() const;
    
    // Properties
    bool IsExpired() const;
    void SetExpiration(std::chrono::seconds ttl);
    void SetPriority(MessagePriority priority);
    
    // Delivery
    void IncrementDeliveryCount();
    uint32_t GetDeliveryCount() const { return config_.deliveryCount; }
    
    // Serialization
    std::vector<uint8_t> Serialize() const;
    static Message Deserialize(const std::vector<uint8_t>& data);
    std::string ToJson() const;
    static Message FromJson(const std::string& json);
    
private:
    Config config_;
};

// ============================================================================
// Delivery Result
// ============================================================================

enum class DeliveryResult {
    SUCCESS,
    QUEUE_FULL,
    TIMEOUT,
    NETWORK_ERROR,
    SERIALIZATION_ERROR,
    UNKNOWN_ERROR
};

// ============================================================================
// Queue
// ============================================================================

/**
 * Message queue.
 */
class Queue {
public:
    struct Config {
        std::string name;
        bool durable;
        bool exclusive;
        bool autoDelete;
        std::map<std::string, std::string> arguments;
        std::optional<uint32_t> maxLength;
        std::optional<std::chrono::milliseconds> messageTtl;
        std::optional<std::chrono::milliseconds> autoExpire;
    };
    
    struct QueueStats {
        uint64_t messageCount;
        uint64_t consumerCount;
        uint64_t messagesPublished;
        uint64_t messagesDelivered;
        uint64_t messagesAcked;
        uint64_t messagesRejected;
        uint64_t messagesExpired;
        std::chrono::milliseconds averageWaitTime;
    };
    
    explicit Queue(const Config& config);
    
    // Queue info
    const std::string& GetName() const { return config_.name; }
    bool IsDurable() const { return config_.durable; }
    
    // Statistics
    QueueStats GetStats() const;
    void ResetStats();
    
    // Purge
    uint64_t Purge();
    
private:
    Config config_;
    QueueStats stats_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Exchange Type
// ============================================================================

enum class ExchangeType {
    DIRECT,     // Exact routing key match
    FANOUT,     // Broadcast to all queues
    TOPIC,      // Pattern matching on routing key
    HEADERS,    // Match on headers
    CONSISTENT_HASH  // Hash-based routing
};

// ============================================================================
// Exchange
// ============================================================================

/**
 * Message exchange for routing.
 */
class Exchange {
public:
    struct Config {
        std::string name;
        ExchangeType type;
        bool durable;
        bool autoDelete;
        std::map<std::string, std::string> arguments;
    };
    
    struct Binding {
        std::string queueName;
        std::string routingKey;
        std::map<std::string, std::string> headers;
    };
    
    explicit Exchange(const Config& config);
    
    // Bindings
    void BindQueue(const std::string& queueName, const std::string& routingKey = "");
    void BindQueue(const std::string& queueName, const std::string& routingKey,
                   const std::map<std::string, std::string>& headers);
    void UnbindQueue(const std::string& queueName, const std::string& routingKey = "");
    std::vector<Binding> GetBindings() const;
    
    // Routing
    std::vector<std::string> Route(const Message& message) const;
    
    // Info
    const std::string& GetName() const { return config_.name; }
    ExchangeType GetType() const { return config_.type; }
    
private:
    Config config_;
    std::vector<Binding> bindings_;
    mutable std::mutex mutex_;
    
    bool MatchRoutingKey(const std::string& pattern, const std::string& routingKey) const;
    bool MatchHeaders(const std::map<std::string, std::string>& bindingHeaders,
                      const std::map<std::string, std::string>& messageHeaders) const;
};

// ============================================================================
// Consumer
// ============================================================================

/**
 * Message consumer.
 */
class Consumer {
public:
    using MessageHandler = std::function<void(const Message&)>;
    using AckHandler = std::function<void(const Message&, bool)>;
    
    struct Config {
        std::string consumerTag;
        std::string queueName;
        bool autoAck;
        std::optional<uint32_t> prefetchCount;
        std::optional<uint32_t> prefetchSize;
        bool exclusive;
        std::map<std::string, std::string> arguments;
    };
    
    explicit Consumer(const Config& config);
    
    // Message handling
    void SetMessageHandler(MessageHandler handler);
    void SetAckHandler(AckHandler handler);
    
    // Lifecycle
    void Start();
    void Stop();
    bool IsRunning() const;
    
    // Acknowledgment
    void Ack(const Message& message);
    void Nack(const Message& message, bool requeue = true);
    void Reject(const Message& message, bool requeue = true);
    
    // Info
    const std::string& GetConsumerTag() const { return config_.consumerTag; }
    const std::string& GetQueueName() const { return config_.queueName; }
    
    // Statistics
    struct ConsumerStats {
        uint64_t messagesReceived;
        uint64_t messagesAcked;
        uint64_t messagesRejected;
        double averageProcessingTimeMs;
    };
    ConsumerStats GetStats() const;
    
private:
    Config config_;
    MessageHandler messageHandler_;
    AckHandler ackHandler_;
    std::atomic<bool> running_;
    ConsumerStats stats_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Producer
// ============================================================================

/**
 * Message producer.
 */
class Producer {
public:
    struct Config {
        std::string producerId;
        std::optional<std::string> defaultExchange;
        std::optional<std::string> defaultRoutingKey;
        bool mandatory;
        bool immediate;
        std::optional<uint32_t> deliveryMode;
        std::optional<std::string> contentType;
    };
    
    explicit Producer(const Config& config);
    
    // Publishing
    DeliveryResult Publish(const Message& message);
    DeliveryResult Publish(const Message& message, const std::string& exchange);
    DeliveryResult Publish(const Message& message, const std::string& exchange,
                           const std::string& routingKey);
    
    // Batch publishing
    std::vector<DeliveryResult> PublishBatch(const std::vector<Message>& messages);
    std::vector<DeliveryResult> PublishBatch(const std::vector<Message>& messages,
                                                  const std::string& exchange);
    
    // Async publishing
    std::future<DeliveryResult> PublishAsync(const Message& message);
    std::future<DeliveryResult> PublishAsync(const Message& message,
                                                  const std::string& exchange);
    
    // Confirmations
    void EnableConfirmations(bool enable);
    bool WaitForConfirms(std::chrono::milliseconds timeout);
    
    // Transactions
    void BeginTransaction();
    void CommitTransaction();
    void RollbackTransaction();
    bool IsInTransaction() const;
    
    // Statistics
    struct ProducerStats {
        uint64_t messagesPublished;
        uint64_t messagesConfirmed;
        uint64_t messagesReturned;
        uint64_t messagesFailed;
        double averagePublishTimeMs;
    };
    ProducerStats GetStats() const;
    
private:
    Config config_;
    bool confirmationsEnabled_;
    bool inTransaction_;
    ProducerStats stats_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Message Queue Backend
// ============================================================================

/**
 * Message queue backend interface.
 */
class MessageQueueBackend {
public:
    virtual ~MessageQueueBackend() = default;
    
    // Lifecycle
    virtual bool Connect() = 0;
    virtual void Disconnect() = 0;
    virtual bool IsConnected() const = 0;
    
    // Queue management
    virtual bool DeclareQueue(const Queue::Config& config) = 0;
    virtual bool DeleteQueue(const std::string& name, bool ifUnused = false,
                             bool ifEmpty = false) = 0;
    virtual bool QueueExists(const std::string& name) const = 0;
    virtual std::vector<std::string> ListQueues() const = 0;
    virtual Queue::QueueStats GetQueueStats(const std::string& name) const = 0;
    virtual uint64_t PurgeQueue(const std::string& name) = 0;
    
    // Exchange management
    virtual bool DeclareExchange(const Exchange::Config& config) = 0;
    virtual bool DeleteExchange(const std::string& name, bool ifUnused = false) = 0;
    virtual bool ExchangeExists(const std::string& name) const = 0;
    virtual bool BindQueue(const std::string& queueName, const std::string& exchangeName,
                           const std::string& routingKey = "") = 0;
    virtual bool UnbindQueue(const std::string& queueName, const std::string& exchangeName,
                             const std::string& routingKey = "") = 0;
    
    // Publishing
    virtual DeliveryResult Publish(const Message& message, const std::string& exchange = "",
                                    const std::string& routingKey = "") = 0;
    virtual std::vector<DeliveryResult> PublishBatch(
        const std::vector<std::pair<Message, std::string>>& messages) = 0;
    
    // Consuming
    virtual std::string Subscribe(const std::string& queueName,
                                   std::function<void(const Message&)> handler,
                                   const Consumer::Config& config) = 0;
    virtual bool Unsubscribe(const std::string& consumerTag) = 0;
    virtual bool Ack(const std::string& deliveryTag) = 0;
    virtual bool Nack(const std::string& deliveryTag, bool requeue = true) = 0;
    
    // Request/Reply
    virtual std::optional<Message> Request(const Message& request,
                                            const std::string& exchange,
                                            const std::string& routingKey,
                                            std::chrono::milliseconds timeout) = 0;
    
    // Info
    virtual std::string GetName() const = 0;
};

// ============================================================================
// RabbitMQ Backend
// ============================================================================

/**
 * RabbitMQ message queue backend.
 */
class RabbitMQBackend : public MessageQueueBackend {
public:
    struct Config {
        std::string host;
        uint16_t port;
        std::string username;
        std::string password;
        std::string vhost;
        std::chrono::seconds connectionTimeout;
        std::chrono::seconds heartbeatInterval;
        bool useSsl;
    };
    
    explicit RabbitMQBackend(const Config& config);
    
    bool Connect() override;
    void Disconnect() override;
    bool IsConnected() const override;
    
    bool DeclareQueue(const Queue::Config& config) override;
    bool DeleteQueue(const std::string& name, bool ifUnused = false,
                     bool ifEmpty = false) override;
    bool QueueExists(const std::string& name) const override;
    std::vector<std::string> ListQueues() const override;
    Queue::QueueStats GetQueueStats(const std::string& name) const override;
    uint64_t PurgeQueue(const std::string& name) override;
    
    bool DeclareExchange(const Exchange::Config& config) override;
    bool DeleteExchange(const std::string& name, bool ifUnused = false) override;
    bool ExchangeExists(const std::string& name) const override;
    bool BindQueue(const std::string& queueName, const std::string& exchangeName,
                   const std::string& routingKey = "") override;
    bool UnbindQueue(const std::string& queueName, const std::string& exchangeName,
                     const std::string& routingKey = "") override;
    
    DeliveryResult Publish(const Message& message, const std::string& exchange = "",
                           const std::string& routingKey = "") override;
    std::vector<DeliveryResult> PublishBatch(
        const std::vector<std::pair<Message, std::string>>& messages) override;
    
    std::string Subscribe(const std::string& queueName,
                          std::function<void(const Message&)> handler,
                          const Consumer::Config& config) override;
    bool Unsubscribe(const std::string& consumerTag) override;
    bool Ack(const std::string& deliveryTag) override;
    bool Nack(const std::string& deliveryTag, bool requeue = true) override;
    
    std::optional<Message> Request(const Message& request,
                                     const std::string& exchange,
                                     const std::string& routingKey,
                                     std::chrono::milliseconds timeout) override;
    
    std::string GetName() const override { return "RabbitMQ"; }
    
private:
    Config config_;
    void* connection_;  // amqp_connection_state_t*
    void* channel_;     // amqp_channel_t
    mutable std::mutex mutex_;
};

// ============================================================================
// Redis Streams Backend
// ============================================================================

/**
 * Redis Streams message queue backend.
 */
class RedisStreamsBackend : public MessageQueueBackend {
public:
    struct Config {
        std::string host;
        uint16_t port;
        std::optional<std::string> password;
        int32_t database;
        std::chrono::seconds connectionTimeout;
    };
    
    explicit RedisStreamsBackend(const Config& config);
    
    bool Connect() override;
    void Disconnect() override;
    bool IsConnected() const override;
    
    bool DeclareQueue(const Queue::Config& config) override;
    bool DeleteQueue(const std::string& name, bool ifUnused = false,
                     bool ifEmpty = false) override;
    bool QueueExists(const std::string& name) const override;
    std::vector<std::string> ListQueues() const override;
    Queue::QueueStats GetQueueStats(const std::string& name) const override;
    uint64_t PurgeQueue(const std::string& name) override;
    
    bool DeclareExchange(const Exchange::Config& config) override;
    bool DeleteExchange(const std::string& name, bool ifUnused = false) override;
    bool ExchangeExists(const std::string& name) const override;
    bool BindQueue(const std::string& queueName, const std::string& exchangeName,
                   const std::string& routingKey = "") override;
    bool UnbindQueue(const std::string& queueName, const std::string& exchangeName,
                     const std::string& routingKey = "") override;
    
    DeliveryResult Publish(const Message& message, const std::string& exchange = "",
                           const std::string& routingKey = "") override;
    std::vector<DeliveryResult> PublishBatch(
        const std::vector<std::pair<Message, std::string>>& messages) override;
    
    std::string Subscribe(const std::string& queueName,
                          std::function<void(const Message&)> handler,
                          const Consumer::Config& config) override;
    bool Unsubscribe(const std::string& consumerTag) override;
    bool Ack(const std::string& deliveryTag) override;
    bool Nack(const std::string& deliveryTag, bool requeue = true) override;
    
    std::optional<Message> Request(const Message& request,
                                     const std::string& exchange,
                                     const std::string& routingKey,
                                     std::chrono::milliseconds timeout) override;
    
    std::string GetName() const override { return "RedisStreams"; }
    
private:
    Config config_;
    void* redisContext_;
    std::map<std::string, std::thread> consumerThreads_;
    mutable std::mutex mutex_;
};

// ============================================================================
// In-Memory Backend
// ============================================================================

/**
 * In-memory message queue backend for testing.
 */
class InMemoryBackend : public MessageQueueBackend {
public:
    explicit InMemoryBackend();
    
    bool Connect() override;
    void Disconnect() override;
    bool IsConnected() const override;
    
    bool DeclareQueue(const Queue::Config& config) override;
    bool DeleteQueue(const std::string& name, bool ifUnused = false,
                     bool ifEmpty = false) override;
    bool QueueExists(const std::string& name) const override;
    std::vector<std::string> ListQueues() const override;
    Queue::QueueStats GetQueueStats(const std::string& name) const override;
    uint64_t PurgeQueue(const std::string& name) override;
    
    bool DeclareExchange(const Exchange::Config& config) override;
    bool DeleteExchange(const std::string& name, bool ifUnused = false) override;
    bool ExchangeExists(const std::string& name) const override;
    bool BindQueue(const std::string& queueName, const std::string& exchangeName,
                   const std::string& routingKey = "") override;
    bool UnbindQueue(const std::string& queueName, const std::string& exchangeName,
                     const std::string& routingKey = "") override;
    
    DeliveryResult Publish(const Message& message, const std::string& exchange = "",
                           const std::string& routingKey = "") override;
    std::vector<DeliveryResult> PublishBatch(
        const std::vector<std::pair<Message, std::string>>& messages) override;
    
    std::string Subscribe(const std::string& queueName,
                          std::function<void(const Message&)> handler,
                          const Consumer::Config& config) override;
    bool Unsubscribe(const std::string& consumerTag) override;
    bool Ack(const std::string& deliveryTag) override;
    bool Nack(const std::string& deliveryTag, bool requeue = true) override;
    
    std::optional<Message> Request(const Message& request,
                                     const std::string& exchange,
                                     const std::string& routingKey,
                                     std::chrono::milliseconds timeout) override;
    
    std::string GetName() const override { return "InMemory"; }
    
private:
    bool connected_;
    std::map<std::string, std::shared_ptr<Queue>> queues_;
    std::map<std::string, std::shared_ptr<Exchange>> exchanges_;
    std::map<std::string, std::queue<Message>> messages_;
    std::map<std::string, std::function<void(const Message&)>> consumers_;
    mutable std::mutex mutex_;
    uint64_t nextDeliveryTag_;
};

// ============================================================================
// Message Queue
// ============================================================================

/**
 * Central message queue manager.
 */
class MessageQueue {
public:
    struct Config {
        std::shared_ptr<MessageQueueBackend> backend;
        std::string defaultExchange;
        bool autoReconnect;
        std::chrono::seconds reconnectInterval;
        uint32_t maxReconnectAttempts;
    };
    
    explicit MessageQueue(const Config& config);
    ~MessageQueue();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Queue operations
    bool DeclareQueue(const std::string& name,
                        bool durable = true,
                        bool exclusive = false,
                        bool autoDelete = false);
    bool DeclareQueue(const Queue::Config& config);
    bool DeleteQueue(const std::string& name);
    bool QueueExists(const std::string& name) const;
    std::vector<std::string> ListQueues() const;
    uint64_t GetMessageCount(const std::string& queueName) const;
    uint64_t PurgeQueue(const std::string& name);
    
    // Exchange operations
    bool DeclareExchange(const std::string& name,
                         ExchangeType type = ExchangeType::DIRECT,
                         bool durable = true,
                         bool autoDelete = false);
    bool DeclareExchange(const Exchange::Config& config);
    bool DeleteExchange(const std::string& name);
    bool BindQueue(const std::string& queueName, const std::string& exchangeName,
                   const std::string& routingKey = "");
    bool UnbindQueue(const std::string& queueName, const std::string& exchangeName,
                     const std::string& routingKey = "");
    
    // Publishing
    DeliveryResult Publish(const Message& message);
    DeliveryResult Publish(const Message& message, const std::string& queueName);
    DeliveryResult PublishToExchange(const Message& message,
                                        const std::string& exchangeName,
                                        const std::string& routingKey = "");
    std::vector<DeliveryResult> PublishBatch(const std::vector<Message>& messages);
    
    // Consuming
    std::string Subscribe(const std::string& queueName,
                          std::function<void(const Message&)> handler);
    std::string Subscribe(const std::string& queueName,
                          std::function<void(const Message&)> handler,
                          const Consumer::Config& config);
    bool Unsubscribe(const std::string& consumerTag);
    
    // Request/Reply pattern
    std::optional<Message> Request(const Message& request,
                                     const std::string& queueName,
                                     std::chrono::milliseconds timeout);
    std::string StartReplyServer(const std::string& queueName,
                                  std::function<Message(const Message&)> handler);
    void StopReplyServer(const std::string& serverId);
    
    // Pub/Sub pattern
    bool PublishToTopic(const std::string& topic, const Message& message);
    std::string SubscribeToTopic(const std::string& topic,
                                    std::function<void(const Message&)> handler);
    
    // Work queue pattern
    bool PublishTask(const std::string& queueName, const Message& task);
    std::string StartWorker(const std::string& queueName,
                            std::function<void(const Message&)> handler);
    void StopWorker(const std::string& workerId);
    
    // RPC pattern
    template<typename RequestType, typename ResponseType>
    std::optional<ResponseType> Call(const std::string& serviceName,
                                        const RequestType& request,
                                        std::chrono::milliseconds timeout);
    
    template<typename RequestType, typename ResponseType>
    std::string RegisterService(const std::string& serviceName,
                                 std::function<ResponseType(const RequestType&)> handler);
    
    // Health check
    bool HealthCheck() const;
    
    // Statistics
    struct MQStats {
        uint64_t messagesPublished;
        uint64_t messagesConsumed;
        uint64_t messagesFailed;
        uint32_t activeConsumers;
        uint32_t activeQueues;
        uint32_t activeExchanges;
    };
    MQStats GetStats() const;
    void ResetStats();
    
private:
    Config config_;
    bool initialized_;
    mutable std::mutex mutex_;
    
    MQStats stats_;
    mutable std::mutex statsMutex_;
    
    std::map<std::string, std::string> replyServers_;
    std::map<std::string, std::string> workers_;
    std::map<std::string, std::string> rpcServices_;
    
    void ReconnectLoop();
    std::thread reconnectThread_;
    std::atomic<bool> stopReconnect_;
};

} // namespace Data
