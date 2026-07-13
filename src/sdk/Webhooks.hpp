/**
 * Webhooks.hpp
 *
 * Phase Q Batch 3/5: Webhooks & Events
 *
 * Event subscription system with webhook delivery, retry logic,
 * and event filtering for real-time integrations.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>

namespace SDK {

// ============================================================================
// Forward Declarations
// ============================================================================

class Event;
class EventBus;
class WebhookEndpoint;
class WebhookDelivery;
class EventFilter;
class RetryPolicy;

// ============================================================================
// Event Types
// ============================================================================

enum class EventType {
    // Tenant events
    TENANT_CREATED,
    TENANT_UPDATED,
    TENANT_DELETED,
    TENANT_SUSPENDED,
    TENANT_ACTIVATED,
    
    // Model events
    MODEL_LOADED,
    MODEL_UNLOADED,
    MODEL_UPDATED,
    MODEL_ERROR,
    
    // Inference events
    INFERENCE_STARTED,
    INFERENCE_COMPLETED,
    INFERENCE_FAILED,
    INFERENCE_CANCELLED,
    
    // Workflow events
    WORKFLOW_STARTED,
    WORKFLOW_COMPLETED,
    WORKFLOW_FAILED,
    WORKFLOW_CANCELLED,
    ACTIVITY_STARTED,
    ACTIVITY_COMPLETED,
    ACTIVITY_FAILED,
    
    // System events
    SYSTEM_ALERT,
    SYSTEM_MAINTENANCE,
    SYSTEM_ERROR,
    SYSTEM_RECOVERY,
    
    // Billing events
    SUBSCRIPTION_CREATED,
    SUBSCRIPTION_UPDATED,
    SUBSCRIPTION_CANCELLED,
    PAYMENT_SUCCEEDED,
    PAYMENT_FAILED,
    INVOICE_GENERATED
};

std::string EventTypeToString(EventType type);
EventType EventTypeFromString(const std::string& str);

// ============================================================================
// Event
// ============================================================================

class Event {
public:
    struct Metadata {
        std::string eventId;
        EventType type;
        std::string tenantId;
        std::optional<std::string> userId;
        std::chrono::system_clock::time_point timestamp;
        std::string version = "1.0";
        std::map<std::string, std::string> custom;
    };
    
    Event(const Metadata& metadata, const std::string& payload);
    
    // Accessors
    const Metadata& GetMetadata() const { return metadata_; }
    const std::string& GetPayload() const { return payload_; }
    const std::string& GetEventId() const { return metadata_.eventId; }
    EventType GetType() const { return metadata_.type; }
    std::string GetTypeString() const { return EventTypeToString(metadata_.type); }
    
    // Serialization
    std::string ToJson() const;
    static Event FromJson(const std::string& json);
    
    // Payload helpers
    template<typename T>
    T GetPayloadAs() const;
    
    // Validation
    bool IsValid() const;
    
private:
    Metadata metadata_;
    std::string payload_;
};

// ============================================================================
// Event Filter
// ============================================================================

class EventFilter {
public:
    enum class Operator {
        EQUALS,
        NOT_EQUALS,
        CONTAINS,
        STARTS_WITH,
        ENDS_WITH,
        GREATER_THAN,
        LESS_THAN,
        IN,
        NOT_IN,
        EXISTS,
        MATCHES_REGEX
    };
    
    struct Condition {
        std::string field;  // e.g., "type", "tenantId", "payload.status"
        Operator op;
        std::variant<std::string, int, float, bool, std::vector<std::string>> value;
    };
    
    EventFilter();
    
    // Builder pattern
    EventFilter& Where(const std::string& field, Operator op, const std::string& value);
    EventFilter& Where(const std::string& field, Operator op, int value);
    EventFilter& Where(const std::string& field, Operator op, float value);
    EventFilter& Where(const std::string& field, Operator op, bool value);
    EventFilter& WhereIn(const std::string& field, const std::vector<std::string>& values);
    EventFilter& WhereExists(const std::string& field);
    
    EventFilter& And(const EventFilter& other);
    EventFilter& Or(const EventFilter& other);
    EventFilter& Not();
    
    // Evaluation
    bool Matches(const Event& event) const;
    
    // Serialization
    std::string ToJson() const;
    static EventFilter FromJson(const std::string& json);
    
private:
    std::vector<Condition> conditions_;
    std::vector<std::pair<std::string, EventFilter>> subFilters_; // "AND", "OR", "NOT"
    
    bool EvaluateCondition(const Condition& condition, const Event& event) const;
    std::optional<std::string> GetFieldValue(const std::string& field, 
                                              const Event& event) const;
};

// ============================================================================
// Webhook Endpoint
// ============================================================================

class WebhookEndpoint {
public:
    struct Config {
        std::string endpointId;
        std::string url;
        std::string description;
        std::vector<EventType> eventTypes;
        std::optional<EventFilter> filter;
        std::map<std::string, std::string> headers;
        std::optional<std::string> secret;  // For HMAC signature
        bool active = true;
        
        // Retry configuration
        uint32_t maxRetries = 3;
        std::chrono::seconds retryInterval{60};
        std::chrono::seconds timeout{30};
        
        // Rate limiting
        uint32_t rateLimitPerSecond = 10;
    };
    
    explicit WebhookEndpoint(const Config& config);
    
    // Configuration
    const Config& GetConfig() const { return config_; }
    void UpdateConfig(const Config& config);
    
    // State
    bool IsActive() const { return config_.active; }
    void Activate();
    void Deactivate();
    
    // Event matching
    bool ShouldReceiveEvent(const Event& event) const;
    
    // Statistics
    struct Stats {
        uint64_t eventsSent;
        uint64_t eventsFailed;
        uint64_t retriesAttempted;
        double averageResponseTimeMs;
        std::chrono::system_clock::time_point lastSuccess;
        std::chrono::system_clock::time_point lastFailure;
        uint32_t consecutiveFailures;
    };
    Stats GetStats() const;
    void UpdateStats(const Stats& stats);
    
    // Health
    bool IsHealthy() const;
    std::chrono::system_clock::time_point GetLastSuccess() const;
    
private:
    Config config_;
    Stats stats_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Webhook Delivery
// ============================================================================

class WebhookDelivery {
public:
    enum class Status {
        PENDING,
        IN_PROGRESS,
        DELIVERED,
        FAILED,
        RETRYING,
        EXHAUSTED
    };
    
    struct Attempt {
        uint32_t attemptNumber;
        std::chrono::system_clock::time_point timestamp;
        std::optional<std::chrono::milliseconds> responseTime;
        std::optional<int> httpStatus;
        std::optional<std::string> error;
        std::string requestBody;
        std::optional<std::string> responseBody;
    };
    
    WebhookDelivery(const std::string& deliveryId,
                    const Event& event,
                    std::shared_ptr<WebhookEndpoint> endpoint);
    
    // Delivery lifecycle
    void Start();
    void RecordAttempt(const Attempt& attempt);
    void MarkDelivered();
    void MarkFailed(const std::string& error);
    void ScheduleRetry(std::chrono::system_clock::time_point when);
    
    // Accessors
    const std::string& GetDeliveryId() const { return deliveryId_; }
    const Event& GetEvent() const { return event_; }
    Status GetStatus() const { return status_; }
    const std::vector<Attempt>& GetAttempts() const { return attempts_; }
    uint32_t GetAttemptCount() const { return static_cast<uint32_t>(attempts_.size()); }
    std::optional<std::chrono::system_clock::time_point> GetNextRetry() const { return nextRetry_; }
    
    // Retry logic
    bool ShouldRetry() const;
    std::chrono::system_clock::time_point CalculateNextRetry() const;
    
    // Serialization
    std::string ToJson() const;
    static WebhookDelivery FromJson(const std::string& json);
    
private:
    std::string deliveryId_;
    Event event_;
    std::shared_ptr<WebhookEndpoint> endpoint_;
    Status status_;
    std::vector<Attempt> attempts_;
    std::optional<std::chrono::system_clock::time_point> nextRetry_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Webhook Delivery Queue
// ============================================================================

class WebhookDeliveryQueue {
public:
    explicit WebhookDeliveryQueue(size_t maxSize = 10000);
    
    // Queue operations
    void Enqueue(std::shared_ptr<WebhookDelivery> delivery);
    std::shared_ptr<WebhookDelivery> Dequeue();
    std::shared_ptr<WebhookDelivery> Peek() const;
    
    // Retry queue
    void EnqueueForRetry(std::shared_ptr<WebhookDelivery> delivery,
                         std::chrono::system_clock::time_point when);
    std::vector<std::shared_ptr<WebhookDelivery>> GetDueRetries();
    
    // Management
    bool IsEmpty() const;
    size_t Size() const;
    void Clear();
    
    // Statistics
    struct Stats {
        size_t pendingCount;
        size_t retryCount;
        uint64_t totalEnqueued;
        uint64_t totalDequeued;
    };
    Stats GetStats() const;
    
private:
    std::queue<std::shared_ptr<WebhookDelivery>> queue_;
    std::multimap<std::chrono::system_clock::time_point, 
                  std::shared_ptr<WebhookDelivery>> retryQueue_;
    size_t maxSize_;
    mutable std::mutex mutex_;
    
    uint64_t totalEnqueued_;
    uint64_t totalDequeued_;
};

// ============================================================================
// Webhook Dispatcher
// ============================================================================

class WebhookDispatcher {
public:
    struct Config {
        uint32_t workerThreads = 4;
        std::chrono::seconds pollInterval{1};
        bool enableSignature = true;
        std::string signatureHeader = "X-Webhook-Signature";
        std::string versionHeader = "X-Webhook-Version";
    };
    
    explicit WebhookDispatcher(const Config& config);
    ~WebhookDispatcher();
    
    // Lifecycle
    void Start();
    void Stop();
    bool IsRunning() const;
    
    // Dispatch
    void Dispatch(const Event& event);
    void DispatchToEndpoint(const Event& event, 
                            std::shared_ptr<WebhookEndpoint> endpoint);
    
    // Endpoint management
    void RegisterEndpoint(std::shared_ptr<WebhookEndpoint> endpoint);
    void UnregisterEndpoint(const std::string& endpointId);
    std::shared_ptr<WebhookEndpoint> GetEndpoint(const std::string& endpointId) const;
    std::vector<std::shared_ptr<WebhookEndpoint>> GetEndpoints() const;
    
    // Delivery management
    std::shared_ptr<WebhookDelivery> GetDelivery(const std::string& deliveryId) const;
    std::vector<std::shared_ptr<WebhookDelivery>> GetDeliveriesForEvent(
        const std::string& eventId) const;
    std::vector<std::shared_ptr<WebhookDelivery>> GetPendingDeliveries() const;
    
    // Retry management
    void RetryDelivery(const std::string& deliveryId);
    void CancelDelivery(const std::string& deliveryId);
    
    // Statistics
    struct Stats {
        uint64_t eventsReceived;
        uint64_t deliveriesAttempted;
        uint64_t deliveriesSucceeded;
        uint64_t deliveriesFailed;
        uint64_t retriesScheduled;
        double averageDeliveryTimeMs;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    std::atomic<bool> running_;
    
    std::map<std::string, std::shared_ptr<WebhookEndpoint>> endpoints_;
    std::map<std::string, std::shared_ptr<WebhookDelivery>> deliveries_;
    WebhookDeliveryQueue queue_;
    mutable std::mutex mutex_;
    
    std::vector<std::thread> workers_;
    std::thread retryThread_;
    
    Stats stats_;
    mutable std::mutex statsMutex_;
    
    void WorkerLoop();
    void RetryLoop();
    void ProcessDelivery(std::shared_ptr<WebhookDelivery> delivery);
    bool SendWebhook(std::shared_ptr<WebhookDelivery> delivery);
    std::string GenerateSignature(const std::string& payload, 
                                    const std::string& secret) const;
    void UpdateStats(const WebhookDelivery& delivery);
};

// ============================================================================
// Event Bus (Internal)
// ============================================================================

class EventBus {
public:
    using EventHandler = std::function<void(const Event&)>;
    using SubscriptionId = uint64_t;
    
    EventBus();
    ~EventBus();
    
    // Subscription
    SubscriptionId Subscribe(EventType type, EventHandler handler);
    SubscriptionId Subscribe(const EventFilter& filter, EventHandler handler);
    void Unsubscribe(SubscriptionId id);
    
    // Publishing
    void Publish(const Event& event);
    void PublishAsync(const Event& event);
    
    // Request/Response pattern
    template<typename Request, typename Response>
    std::future<Response> Request(const Request& request);
    
    template<typename Request, typename Response>
    void HandleRequest(std::function<Response(const Request&)> handler);
    
    // Stream processing
    using StreamProcessor = std::function<void(const std::vector<Event>&)>;
    void SubscribeToStream(const EventFilter& filter, 
                           StreamProcessor processor,
                           std::chrono::milliseconds window);
    
    // Statistics
    struct Stats {
        uint64_t eventsPublished;
        uint64_t eventsDelivered;
        uint64_t activeSubscriptions;
        uint64_t droppedEvents;
    };
    Stats GetStats() const;
    
private:
    struct Subscription {
        SubscriptionId id;
        std::optional<EventType> type;
        std::optional<EventFilter> filter;
        EventHandler handler;
    };
    
    std::map<SubscriptionId, Subscription> subscriptions_;
    std::map<EventType, std::vector<SubscriptionId>> typeIndex_;
    SubscriptionId nextId_;
    
    std::queue<Event> eventQueue_;
    std::thread dispatchThread_;
    std::atomic<bool> running_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    
    Stats stats_;
    mutable std::mutex statsMutex_;
    
    void DispatchLoop();
    void DispatchEvent(const Event& event);
};

// ============================================================================
// Event Store
// ============================================================================

class EventStore {
public:
    struct Config {
        std::string storagePath;
        std::chrono::seconds retentionPeriod{7 * 24 * 60 * 60}; // 7 days
        size_t maxEvents = 1000000;
        bool compressOldEvents = true;
    };
    
    explicit EventStore(const Config& config);
    
    // Storage
    void Store(const Event& event);
    void StoreBatch(const std::vector<Event>& events);
    
    // Querying
    std::vector<Event> Query(const EventFilter& filter,
                             std::chrono::system_clock::time_point from,
                             std::chrono::system_clock::time_point to) const;
    std::vector<Event> QueryByType(EventType type,
                                   std::chrono::system_clock::time_point from,
                                   std::chrono::system_clock::time_point to) const;
    std::optional<Event> GetEvent(const std::string& eventId) const;
    
    // Aggregation
    std::map<EventType, uint64_t> GetEventCounts(
        std::chrono::system_clock::time_point from,
        std::chrono::system_clock::time_point to) const;
    
    // Maintenance
    void Compact();
    void PurgeOldEvents();
    
    // Statistics
    struct Stats {
        uint64_t totalEventsStored;
        uint64_t totalEventsRetrieved;
        size_t storageSizeBytes;
        std::chrono::system_clock::time_point oldestEvent;
        std::chrono::system_clock::time_point newestEvent;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    
    // Simple file-based storage (in production, use proper database)
    std::map<std::string, Event> events_;
    std::map<EventType, std::vector<std::string>> typeIndex_;
    std::map<std::chrono::system_clock::time_point, std::vector<std::string>> timeIndex_;
    mutable std::mutex mutex_;
    
    void LoadFromDisk();
    void SaveToDisk();
    std::string GetEventPath(const std::string& eventId) const;
};

// ============================================================================
// Webhook Manager
// ============================================================================

class WebhookManager {
public:
    struct Config {
        WebhookDispatcher::Config dispatcherConfig;
        EventStore::Config storeConfig;
        bool enableEventStore = true;
        bool enableInternalBus = true;
    };
    
    explicit WebhookManager(const Config& config);
    ~WebhookManager();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Event publishing
    void PublishEvent(const Event& event);
    void PublishEvent(EventType type, const std::string& payload);
    void PublishEvent(EventType type, 
                      const std::string& tenantId,
                      const std::string& payload);
    
    // Webhook endpoint management
    std::string CreateEndpoint(const WebhookEndpoint::Config& config);
    void UpdateEndpoint(const std::string& endpointId, 
                        const WebhookEndpoint::Config& config);
    void DeleteEndpoint(const std::string& endpointId);
    std::shared_ptr<WebhookEndpoint> GetEndpoint(const std::string& endpointId) const;
    std::vector<std::shared_ptr<WebhookEndpoint>> ListEndpoints() const;
    std::vector<std::shared_ptr<WebhookEndpoint>> ListEndpointsForTenant(
        const std::string& tenantId) const;
    
    // Delivery monitoring
    std::shared_ptr<WebhookDelivery> GetDelivery(const std::string& deliveryId) const;
    std::vector<std::shared_ptr<WebhookDelivery>> ListDeliveries(
        const std::string& endpointId) const;
    std::vector<std::shared_ptr<WebhookDelivery>> ListFailedDeliveries() const;
    void RetryDelivery(const std::string& deliveryId);
    
    // Internal subscriptions
    EventBus::SubscriptionId SubscribeToEvents(EventType type, 
                                               EventBus::EventHandler handler);
    EventBus::SubscriptionId SubscribeToEvents(const EventFilter& filter,
                                               EventBus::EventHandler handler);
    void Unsubscribe(EventBus::SubscriptionId id);
    
    // Health check
    bool IsHealthy() const;
    std::vector<std::string> GetUnhealthyEndpoints() const;
    
    // Statistics
    struct Stats {
        WebhookDispatcher::Stats dispatcherStats;
        EventStore::Stats storeStats;
        EventBus::Stats busStats;
        uint64_t totalEndpoints;
        uint64_t activeEndpoints;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    
    std::unique_ptr<WebhookDispatcher> dispatcher_;
    std::unique_ptr<EventStore> eventStore_;
    std::unique_ptr<EventBus> eventBus_;
};

} // namespace SDK
