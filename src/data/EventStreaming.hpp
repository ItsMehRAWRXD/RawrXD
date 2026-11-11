/**
 * EventStreaming.hpp
 *
 * Phase M Batch 4/5: Data Streaming & Event Processing
 *
 * Event streaming infrastructure with support for stream processing,
 * event sourcing, and complex event processing (CEP).
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

class Event;
class EventStream;
class StreamProcessor;
class EventSourcing;
class ComplexEventProcessing;

// ============================================================================
// Event
// ============================================================================

/**
 * Event in the streaming system.
 */
class Event {
public:
    using PayloadType = std::vector<uint8_t>;
    using HeadersType = std::map<std::string, std::string>;
    
    struct Config {
        std::string eventId;
        std::string eventType;
        std::string streamId;
        std::string partitionKey;
        uint64_t sequenceNumber;
        PayloadType payload;
        HeadersType headers;
        std::chrono::system_clock::time_point timestamp;
        std::optional<std::string> correlationId;
        std::optional<std::string> causationId;
        std::map<std::string, std::string> metadata;
    };
    
    explicit Event(const Config& config);
    
    // Factory methods
    static Event Create(const std::string& eventType, const std::string& payload);
    static Event Create(const std::string& eventType, const std::vector<uint8_t>& payload);
    
    template<typename T>
    static Event CreateFromObject(const std::string& eventType, const T& obj);
    
    // Accessors
    const std::string& GetEventId() const { return config_.eventId; }
    const std::string& GetEventType() const { return config_.eventType; }
    const std::string& GetStreamId() const { return config_.streamId; }
    const std::string& GetPartitionKey() const { return config_.partitionKey; }
    uint64_t GetSequenceNumber() const { return config_.sequenceNumber; }
    const PayloadType& GetPayload() const { return config_.payload; }
    PayloadType& GetPayload() { return config_.payload; }
    const HeadersType& GetHeaders() const { return config_.headers; }
    std::chrono::system_clock::time_point GetTimestamp() const { return config_.timestamp; }
    
    // Payload helpers
    std::string GetPayloadAsString() const;
    std::string GetPayloadAsJson() const;
    template<typename T>
    T GetPayloadAsObject() const;
    
    // Headers
    void SetHeader(const std::string& key, const std::string& value);
    std::optional<std::string> GetHeader(const std::string& key) const;
    
    // Metadata
    void SetMetadata(const std::string& key, const std::string& value);
    std::optional<std::string> GetMetadata(const std::string& key) const;
    
    // Serialization
    std::vector<uint8_t> Serialize() const;
    static Event Deserialize(const std::vector<uint8_t>& data);
    std::string ToJson() const;
    static Event FromJson(const std::string& json);
    
    // Comparison
    bool operator==(const Event& other) const;
    bool operator<(const Event& other) const;
    
private:
    Config config_;
};

// ============================================================================
// Event Stream
// ============================================================================

/**
 * Event stream.
 */
class EventStream {
public:
    struct Config {
        std::string streamId;
        std::string streamName;
        uint32_t partitionCount;
        std::chrono::hours retentionPeriod;
        std::optional<uint64_t> maxSizeBytes;
        bool enableCompression;
        std::string compressionCodec;
    };
    
    struct StreamStats {
        uint64_t totalEvents;
        uint64_t eventsPerSecond;
        uint64_t bytesPerSecond;
        uint64_t consumerLag;
        std::chrono::milliseconds averageLatency;
        std::map<uint32_t, uint64_t> eventsPerPartition;
    };
    
    explicit EventStream(const Config& config);
    
    // Stream info
    const std::string& GetStreamId() const { return config_.streamId; }
    const std::string& GetStreamName() const { return config_.streamName; }
    uint32_t GetPartitionCount() const { return config_.partitionCount; }
    
    // Event operations
    bool Append(const Event& event);
    bool AppendBatch(const std::vector<Event>& events);
    
    // Reading
    std::vector<Event> ReadFrom(uint64_t sequenceNumber, size_t maxEvents = 100);
    std::vector<Event> ReadFromTimestamp(std::chrono::system_clock::time_point timestamp,
                                              size_t maxEvents = 100);
    std::vector<Event> ReadFromOffset(const std::string& partitionKey,
                                          uint64_t offset,
                                          size_t maxEvents = 100);
    
    // Subscription
    using EventHandler = std::function<void(const Event&)>;
    std::string Subscribe(EventHandler handler);
    std::string SubscribeFrom(uint64_t sequenceNumber, EventHandler handler);
    std::string SubscribeToPartition(const std::string& partitionKey, EventHandler handler);
    bool Unsubscribe(const std::string& subscriptionId);
    
    // Partitioning
    uint32_t GetPartitionForKey(const std::string& key) const;
    std::vector<std::string> GetPartitionKeys() const;
    
    // Statistics
    StreamStats GetStats() const;
    void ResetStats();
    
    // Management
    bool Truncate(std::chrono::system_clock::time_point before);
    bool Compact();
    uint64_t GetSize() const;
    
private:
    Config config_;
    std::vector<std::queue<Event>> partitions_;
    std::map<std::string, std::pair<uint32_t, uint64_t>> offsets_;
    std::map<std::string, EventHandler> subscribers_;
    StreamStats stats_;
    mutable std::mutex mutex_;
    uint64_t nextSequenceNumber_;
};

// ============================================================================
// Stream Processor
// ============================================================================

/**
 * Stream processor for event transformations.
 */
class StreamProcessor {
public:
    using EventTransformer = std::function<std::vector<Event>(const Event&)>;
    using EventFilter = std::function<bool(const Event&)>;
    using EventAggregator = std::function<Event(const std::vector<Event>&)>;
    
    struct Config {
        std::string processorId;
        std::string inputStream;
        std::string outputStream;
        std::chrono::milliseconds processingInterval;
        std::optional<uint32_t> parallelism;
        bool enableCheckpointing;
        std::chrono::seconds checkpointInterval;
    };
    
    explicit StreamProcessor(const Config& config);
    
    // Processing chain
    StreamProcessor& Filter(EventFilter filter);
    StreamProcessor& Map(EventTransformer transformer);
    StreamProcessor& FlatMap(EventTransformer transformer);
    StreamProcessor& Aggregate(std::chrono::milliseconds windowSize,
                                 EventAggregator aggregator);
    StreamProcessor& Join(const std::string& otherStream,
                            std::function<Event(const Event&, const Event&)> joiner);
    StreamProcessor& Window(std::chrono::milliseconds windowSize,
                              std::chrono::milliseconds slideSize);
    
    // Lifecycle
    bool Start();
    void Stop();
    bool IsRunning() const;
    void Pause();
    void Resume();
    
    // Checkpointing
    bool Checkpoint();
    bool RestoreFromCheckpoint(const std::string& checkpointId);
    std::vector<std::string> ListCheckpoints() const;
    
    // Statistics
    struct ProcessorStats {
        uint64_t eventsProcessed;
        uint64_t eventsEmitted;
        uint64_t eventsFiltered;
        uint64_t errors;
        double eventsPerSecond;
        double averageLatencyMs;
        std::chrono::system_clock::time_point lastCheckpoint;
    };
    ProcessorStats GetStats() const;
    void ResetStats();
    
private:
    Config config_;
    std::vector<EventFilter> filters_;
    std::vector<EventTransformer> transformers_;
    std::optional<EventAggregator> aggregator_;
    std::optional<std::chrono::milliseconds> windowSize_;
    std::optional<std::chrono::milliseconds> slideSize_;
    
    std::atomic<bool> running_;
    std::atomic<bool> paused_;
    std::thread processingThread_;
    ProcessorStats stats_;
    mutable std::mutex mutex_;
    
    void ProcessingLoop();
    void ProcessEvent(const Event& event);
};

// ============================================================================
// Event Store
// ============================================================================

/**
 * Event store for event sourcing.
 */
class EventStore {
public:
    struct Config {
        std::string storagePath;
        bool enableSnapshots;
        uint32_t snapshotFrequency;
        bool enableEncryption;
        std::string encryptionKey;
    };
    
    explicit EventStore(const Config& config);
    
    // Event operations
    bool Append(const std::string& aggregateId, const Event& event);
    bool AppendBatch(const std::string& aggregateId, const std::vector<Event>& events);
    
    // Reading
    std::vector<Event> GetEvents(const std::string& aggregateId);
    std::vector<Event> GetEventsFrom(const std::string& aggregateId, uint64_t fromVersion);
    std::vector<Event> GetEventsTo(const std::string& aggregateId, uint64_t toVersion);
    std::vector<Event> GetEventsRange(const std::string& aggregateId,
                                          uint64_t fromVersion,
                                          uint64_t toVersion);
    
    // Snapshots
    bool SaveSnapshot(const std::string& aggregateId, uint64_t version,
                      const std::vector<uint8_t>& snapshot);
    std::optional<std::pair<uint64_t, std::vector<uint8_t>>> GetLatestSnapshot(
        const std::string& aggregateId);
    
    // Aggregate info
    uint64_t GetLatestVersion(const std::string& aggregateId);
    bool AggregateExists(const std::string& aggregateId) const;
    std::vector<std::string> ListAggregates() const;
    
    // Projections
    using Projection = std::function<void(const Event&, void* state)>;
    void RegisterProjection(const std::string& name, Projection projection);
    bool Project(const std::string& projectionName, const std::string& aggregateId);
    bool ProjectAll(const std::string& projectionName);
    
    // Statistics
    struct StoreStats {
        uint64_t totalEvents;
        uint64_t totalAggregates;
        uint64_t totalSnapshots;
        uint64_t storageSizeBytes;
    };
    StoreStats GetStats() const;
    
private:
    Config config_;
    std::map<std::string, std::vector<Event>> aggregates_;
    std::map<std::string, std::vector<std::pair<uint64_t, std::vector<uint8_t>>>> snapshots_;
    std::map<std::string, Projection> projections_;
    mutable std::mutex mutex_;
    
    void PersistEvents(const std::string& aggregateId);
    void LoadEvents(const std::string& aggregateId);
};

// ============================================================================
// Event Sourcing
// ============================================================================

/**
 * Event sourcing framework.
 */
class EventSourcing {
public:
    struct Aggregate {
        std::string aggregateId;
        std::string aggregateType;
        uint64_t version;
        std::vector<Event> uncommittedEvents;
        std::optional<std::vector<uint8_t>> snapshot;
    };
    
    using CommandHandler = std::function<std::vector<Event>(const Aggregate&, const Event&)>;
    using EventHandler = std::function<void(Aggregate&, const Event&)>;
    
    explicit EventSourcing(std::shared_ptr<EventStore> eventStore);
    
    // Aggregate registration
    void RegisterAggregate(const std::string& aggregateType,
                           CommandHandler commandHandler,
                           EventHandler eventHandler);
    
    // Commands
    std::vector<Event> ExecuteCommand(const std::string& aggregateId,
                                         const std::string& aggregateType,
                                         const Event& command);
    
    // Queries
    Aggregate GetAggregate(const std::string& aggregateId);
    std::optional<Aggregate> GetAggregateAtVersion(const std::string& aggregateId,
                                                       uint64_t version);
    
    // Snapshotting
    void EnableSnapshotting(const std::string& aggregateType, uint32_t frequency);
    bool CreateSnapshot(const std::string& aggregateId);
    
    // Rebuilding
    bool RebuildAggregate(const std::string& aggregateId);
    bool RebuildAllAggregates(const std::string& aggregateType);
    
private:
    std::shared_ptr<EventStore> eventStore_;
    std::map<std::string, std::pair<CommandHandler, EventHandler>> aggregates_;
    std::map<std::string, uint32_t> snapshotFrequencies_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Complex Event Processing
// ============================================================================

/**
 * Complex Event Processing (CEP) engine.
 */
class ComplexEventProcessing {
public:
    // Event pattern
    struct Pattern {
        std::string name;
        std::vector<PatternElement> elements;
        std::function<bool(const std::vector<Event>&)> condition;
        std::function<Event(const std::vector<Event>&)> transform;
        std::chrono::milliseconds window;
        bool continuous;
    };
    
    struct PatternElement {
        enum class Type {
            EVENT,
            SEQUENCE,
            FOLLOWED_BY,
            NOT_NEXT,
            NOT_WITHIN,
            OR,
            AND
        };
        
        Type type;
        std::string eventType;
        std::function<bool(const Event&)> predicate;
        std::optional<std::chrono::milliseconds> within;
        std::optional<uint32_t> times;
    };
    
    // Rule
    struct Rule {
        std::string ruleId;
        std::string name;
        Pattern pattern;
        std::vector<Action> actions;
        bool enabled;
        uint32_t priority;
    };
    
    struct Action {
        enum class Type {
            EMIT_EVENT,
            CALL_FUNCTION,
            SEND_NOTIFICATION,
            TRIGGER_WORKFLOW
        };
        
        Type type;
        std::map<std::string, std::string> parameters;
    };
    
    explicit ComplexEventProcessing();
    
    // Rule management
    std::string RegisterRule(const Rule& rule);
    bool UpdateRule(const std::string& ruleId, const Rule& rule);
    bool DeleteRule(const std::string& ruleId);
    bool EnableRule(const std::string& ruleId);
    bool DisableRule(const std::string& ruleId);
    std::optional<Rule> GetRule(const std::string& ruleId) const;
    std::vector<Rule> ListRules() const;
    
    // Event processing
    void ProcessEvent(const Event& event);
    void ProcessEvents(const std::vector<Event>& events);
    
    // Pattern matching
    std::vector<std::vector<Event>> MatchPattern(const Pattern& pattern,
                                                      const std::vector<Event>& events);
    
    // Windowing
    void SetEventWindow(std::chrono::milliseconds window);
    void ClearEventWindow();
    
    // Statistics
    struct CEPStats {
        uint64_t eventsProcessed;
        uint64_t patternsMatched;
        uint64_t rulesTriggered;
        uint64_t eventsEmitted;
        double averageProcessingTimeMs;
    };
    CEPStats GetStats() const;
    void ResetStats();
    
private:
    std::map<std::string, Rule> rules_;
    std::vector<Event> eventBuffer_;
    std::optional<std::chrono::milliseconds> window_;
    CEPStats stats_;
    mutable std::mutex mutex_;
    
    void EvaluateRules(const Event& event);
    void EvaluatePattern(const Pattern& pattern, const std::vector<Event>& events);
    void ExecuteActions(const std::vector<Action>& actions,
                        const std::vector<Event>& matchedEvents);
    void CleanupOldEvents();
};

// ============================================================================
// Stream Analytics
// ============================================================================

/**
 * Stream analytics for real-time metrics.
 */
class StreamAnalytics {
public:
    struct MetricDefinition {
        std::string name;
        std::string eventType;
        std::function<double(const Event&)> extractor;
        std::function<double(const std::vector<double>&)> aggregation;
        std::chrono::milliseconds windowSize;
    };
    
    struct MetricValue {
        std::string metricName;
        double value;
        std::chrono::system_clock::time_point timestamp;
        std::map<std::string, std::string> dimensions;
    };
    
    explicit StreamAnalytics();
    
    // Metric registration
    void RegisterMetric(const MetricDefinition& metric);
    void UnregisterMetric(const std::string& name);
    
    // Event processing
    void ProcessEvent(const Event& event);
    void ProcessEvents(const std::vector<Event>& events);
    
    // Query metrics
    std::vector<MetricValue> GetMetricHistory(const std::string& metricName,
                                                std::chrono::system_clock::time_point from,
                                                std::chrono::system_clock::time_point to);
    std::optional<MetricValue> GetCurrentValue(const std::string& metricName);
    std::map<std::string, double> GetCurrentValues();
    
    // Alerts
    using AlertCondition = std::function<bool(const MetricValue&)>;
    using AlertHandler = std::function<void(const MetricValue&)>;
    
    void RegisterAlert(const std::string& metricName,
                       AlertCondition condition,
                       AlertHandler handler);
    void UnregisterAlert(const std::string& alertId);
    
    // Statistics
    struct AnalyticsStats {
        uint64_t eventsProcessed;
        uint64_t metricsCalculated;
        uint64_t alertsTriggered;
        std::map<std::string, uint64_t> metricsByType;
    };
    AnalyticsStats GetStats() const;
    
private:
    std::map<std::string, MetricDefinition> metrics_;
    std::map<std::string, std::vector<MetricValue>> metricHistory_;
    std::map<std::string, std::pair<AlertCondition, AlertHandler>> alerts_;
    AnalyticsStats stats_;
    mutable std::mutex mutex_;
    
    void CalculateMetrics(const Event& event);
    void CheckAlerts(const MetricValue& metric);
    void CleanupOldMetrics();
};

// ============================================================================
// Event Streaming Platform
// ============================================================================

/**
 * Central event streaming platform.
 */
class EventStreamingPlatform {
public:
    struct Config {
        std::string storageBackend;
        std::string storagePath;
        bool enableReplication;
        uint32_t replicationFactor;
        bool enableCompression;
        std::chrono::hours defaultRetention;
    };
    
    explicit EventStreamingPlatform(const Config& config);
    ~EventStreamingPlatform();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Stream management
    std::shared_ptr<EventStream> CreateStream(const std::string& name,
                                                const EventStream::Config& config);
    bool DeleteStream(const std::string& streamId);
    std::shared_ptr<EventStream> GetStream(const std::string& streamId);
    std::vector<std::string> ListStreams() const;
    
    // Stream processing
    std::shared_ptr<StreamProcessor> CreateProcessor(
        const StreamProcessor::Config& config);
    bool DeleteProcessor(const std::string& processorId);
    
    // Event sourcing
    std::shared_ptr<EventSourcing> GetEventSourcing();
    
    // CEP
    std::shared_ptr<ComplexEventProcessing> GetCEP();
    
    // Analytics
    std::shared_ptr<StreamAnalytics> GetAnalytics();
    
    // Cross-stream operations
    std::vector<Event> JoinStreams(const std::string& stream1,
                                     const std::string& stream2,
                                     std::function<bool(const Event&, const Event&)> joinCondition);
    
    // Health check
    bool HealthCheck() const;
    
    // Statistics
    struct PlatformStats {
        uint32_t activeStreams;
        uint32_t activeProcessors;
        uint64_t totalEvents;
        uint64_t eventsPerSecond;
        uint64_t storageUsedBytes;
    };
    PlatformStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    std::map<std::string, std::shared_ptr<EventStream>> streams_;
    std::map<std::string, std::shared_ptr<StreamProcessor>> processors_;
    std::shared_ptr<EventStore> eventStore_;
    std::shared_ptr<EventSourcing> eventSourcing_;
    std::shared_ptr<ComplexEventProcessing> cep_;
    std::shared_ptr<StreamAnalytics> analytics_;
    mutable std::mutex mutex_;
};

} // namespace Data
