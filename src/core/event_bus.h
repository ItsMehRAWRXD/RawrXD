#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <mutex>
#include <any>
#include <chrono>

namespace RawrXD {

// Event types for the IDE
enum class EventType {
    // Lifecycle
    AppStarting,
    AppReady,
    AppShuttingDown,
    
    // Workspace
    WorkspaceOpened,
    WorkspaceClosed,
    WorkspaceChanged,
    FileCreated,
    FileModified,
    FileDeleted,
    FileRenamed,
    
    // Editor
    DocumentOpened,
    DocumentClosed,
    DocumentModified,
    DocumentSaved,
    CursorMoved,
    SelectionChanged,
    
    // Extensions
    ExtensionActivated,
    ExtensionDeactivated,
    ExtensionLoaded,
    ExtensionUnloaded,
    CommandRegistered,
    CommandExecuted,
    
    // Tasks
    TaskStarted,
    TaskProgress,
    TaskCompleted,
    TaskFailed,
    TaskCancelled,
    ProblemDetected,
    
    // Settings
    SettingsChanged,
    ProfileSwitched,
    
    // UI
    ThemeChanged,
    LayoutChanged,
    PanelOpened,
    PanelClosed,
    NotificationShown,
    
    // AI/Agent
    InferenceStarted,
    InferenceCompleted,
    InferenceFailed,
    AgentActivated,
    AgentDeactivated,
    
    // Debug
    DebugSessionStarted,
    DebugSessionStopped,
    BreakpointHit,
    
    // Git
    GitStatusChanged,
    GitBranchChanged,
    
    // Custom
    Custom
};

// Event priority
enum class EventPriority {
    Critical,   // Immediate processing
    High,       // Process before next frame
    Normal,     // Standard processing
    Low,        // Can be deferred
    Background  // Process when idle
};

// Event data base class
struct EventData {
    std::chrono::steady_clock::time_point timestamp;
    std::string source;  // Component that fired the event
    
    EventData() : timestamp(std::chrono::steady_clock::now()) {}
    virtual ~EventData() = default;
};

// Specific event data structures
struct FileEventData : EventData {
    std::string path;
    std::string oldPath;  // For rename events
    bool isDirectory = false;
};

struct DocumentEventData : EventData {
    std::string uri;
    std::string languageId;
    int version = 0;
};

struct TaskEventData : EventData {
    std::string taskId;
    std::string taskLabel;
    int exitCode = 0;
    std::string output;
    std::vector<std::string> problems;
};

struct SettingsEventData : EventData {
    std::string key;
    std::string oldValue;
    std::string newValue;
    std::string scope;
};

struct CommandEventData : EventData {
    std::string commandId;
    std::vector<std::string> args;
    bool handled = false;
};

struct ExtensionEventData : EventData {
    std::string extensionId;
    std::string extensionName;
    std::string version;
};

struct WorkspaceEventData : EventData {
    std::string path;
    std::string name;
    int folderCount = 0;
};

// Event handler type
using EventHandler = std::function<void(EventType, const EventData&)>;
using TypedEventHandler<T> = std::function<void(const T&)>;

// Event subscription token for unsubscribe
class EventSubscription {
public:
    EventSubscription() : id_(0), bus_(nullptr) {}
    EventSubscription(uint64_t id, class EventBus* bus) : id_(id), bus_(bus) {}
    ~EventSubscription();
    
    EventSubscription(const EventSubscription&) = delete;
    EventSubscription& operator=(const EventSubscription&) = delete;
    
    EventSubscription(EventSubscription&& other) noexcept;
    EventSubscription& operator=(EventSubscription&& other) noexcept;
    
    void Unsubscribe();
    bool IsActive() const { return id_ != 0 && bus_ != nullptr; }
    
private:
    uint64_t id_;
    class EventBus* bus_;
};

// Event Bus - Central dispatcher for all IDE events
class EventBus {
public:
    static EventBus& Instance();
    
    // Publish events
    void Publish(EventType type, const EventData& data, EventPriority priority = EventPriority::Normal);
    void PublishImmediate(EventType type, const EventData& data);  // Synchronous
    
    // Subscribe to events
    EventSubscription Subscribe(EventType type, EventHandler handler);
    EventSubscription SubscribeAll(EventHandler handler);  // All events
    
    // Typed subscriptions (convenience)
    template<typename T>
    EventSubscription Subscribe(EventType type, std::function<void(const T&)> handler) {
        return Subscribe(type, [handler](EventType t, const EventData& data) {
            if (auto* typed = dynamic_cast<const T*>(&data)) {
                handler(*typed);
            }
        });
    }
    
    // Unsubscribe
    void Unsubscribe(uint64_t subscriptionId);
    
    // Processing
    void ProcessEvents();  // Process queued events
    void ProcessEvents(EventPriority maxPriority);  // Process up to priority level
    void ClearQueue();
    
    // Stats
    size_t GetQueueSize() const;
    size_t GetSubscriberCount(EventType type) const;
    
private:
    EventBus() = default;
    ~EventBus() = default;
    
    struct Subscription {
        uint64_t id;
        EventType type;
        EventHandler handler;
    };
    
    struct QueuedEvent {
        EventType type;
        std::shared_ptr<EventData> data;
        EventPriority priority;
    };
    
    std::map<EventType, std::vector<Subscription>> subscribers_;
    std::vector<Subscription> allEventSubscribers_;
    std::vector<QueuedEvent> eventQueue_;
    
    mutable std::mutex subscribersMutex_;
    mutable std::mutex queueMutex_;
    
    uint64_t nextSubscriptionId_ = 1;
    
    uint64_t GenerateSubscriptionId();
    void DispatchEvent(EventType type, const EventData& data);
};

// Scoped event batching - suppress events during bulk operations
class EventBatch {
public:
    EventBatch();
    ~EventBatch();
    
    EventBatch(const EventBatch&) = delete;
    EventBatch& operator=(const EventBatch&) = delete;
    
    void Commit();  // Fire accumulated events
    void Cancel();  // Discard accumulated events
    
private:
    std::vector<std::pair<EventType, std::shared_ptr<EventData>>> accumulatedEvents_;
    bool active_ = false;
};

// Event logging for debugging
class EventLogger {
public:
    static void Enable();
    static void Disable();
    static bool IsEnabled();
    
    static void LogEvent(EventType type, const EventData& data);
    static std::vector<std::string> GetRecentEvents(size_t count = 100);
    
private:
    static bool enabled_;
    static std::vector<std::string> recentEvents_;
    static std::mutex mutex_;
};

// Convenience macros
#define RAWRXD_PUBLISH_EVENT(type, data) \
    RawrXD::EventBus::Instance().Publish(type, data)

#define RAWRXD_PUBLISH_EVENT_IMMEDIATE(type, data) \
    RawrXD::EventBus::Instance().PublishImmediate(type, data)

#define RAWRXD_SUBSCRIBE_EVENT(type, handler) \
    RawrXD::EventBus::Instance().Subscribe(type, handler)

} // namespace RawrXD