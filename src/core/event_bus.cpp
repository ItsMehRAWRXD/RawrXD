#include "event_bus.h"
#include <windows.h>
#include <sstream>
#include <iomanip>

namespace RawrXD {

// EventSubscription implementation
EventSubscription::~EventSubscription() {
    if (bus_ && id_ != 0) {
        bus_->Unsubscribe(id_);
    }
}

EventSubscription::EventSubscription(EventSubscription&& other) noexcept
    : id_(other.id_), bus_(other.bus_) {
    other.id_ = 0;
    other.bus_ = nullptr;
}

EventSubscription& EventSubscription::operator=(EventSubscription&& other) noexcept {
    if (this != &other) {
        if (bus_ && id_ != 0) {
            bus_->Unsubscribe(id_);
        }
        id_ = other.id_;
        bus_ = other.bus_;
        other.id_ = 0;
        other.bus_ = nullptr;
    }
    return *this;
}

void EventSubscription::Unsubscribe() {
    if (bus_ && id_ != 0) {
        bus_->Unsubscribe(id_);
        id_ = 0;
        bus_ = nullptr;
    }
}

// EventBus implementation
EventBus& EventBus::Instance() {
    static EventBus instance;
    return instance;
}

void EventBus::Publish(EventType type, const EventData& data, EventPriority priority) {
    if (EventLogger::IsEnabled()) {
        EventLogger::LogEvent(type, data);
    }
    
    std::lock_guard<std::mutex> lock(queueMutex_);
    
    // Clone the event data
    auto clonedData = std::make_shared<EventData>(data);
    
    QueuedEvent event;
    event.type = type;
    event.data = clonedData;
    event.priority = priority;
    
    // Insert in priority order
    auto it = eventQueue_.begin();
    while (it != eventQueue_.end() && static_cast<int>(it->priority) <= static_cast<int>(priority)) {
        ++it;
    }
    eventQueue_.insert(it, std::move(event));
}

void EventBus::PublishImmediate(EventType type, const EventData& data) {
    if (EventLogger::IsEnabled()) {
        EventLogger::LogEvent(type, data);
    }
    
    DispatchEvent(type, data);
}

EventSubscription EventBus::Subscribe(EventType type, EventHandler handler) {
    std::lock_guard<std::mutex> lock(subscribersMutex_);
    
    uint64_t id = GenerateSubscriptionId();
    
    Subscription sub;
    sub.id = id;
    sub.type = type;
    sub.handler = handler;
    
    subscribers_[type].push_back(sub);
    
    return EventSubscription(id, this);
}

EventSubscription EventBus::SubscribeAll(EventHandler handler) {
    std::lock_guard<std::mutex> lock(subscribersMutex_);
    
    uint64_t id = GenerateSubscriptionId();
    
    Subscription sub;
    sub.id = id;
    sub.type = static_cast<EventType>(-1);  // Special marker for all events
    sub.handler = handler;
    
    allEventSubscribers_.push_back(sub);
    
    return EventSubscription(id, this);
}

void EventBus::Unsubscribe(uint64_t subscriptionId) {
    std::lock_guard<std::mutex> lock(subscribersMutex_);
    
    // Remove from typed subscribers
    for (auto& [type, subs] : subscribers_) {
        subs.erase(
            std::remove_if(subs.begin(), subs.end(),
                [subscriptionId](const Subscription& s) { return s.id == subscriptionId; }),
            subs.end()
        );
    }
    
    // Remove from all-event subscribers
    allEventSubscribers_.erase(
        std::remove_if(allEventSubscribers_.begin(), allEventSubscribers_.end(),
            [subscriptionId](const Subscription& s) { return s.id == subscriptionId; }),
        allEventSubscribers_.end()
    );
}

void EventBus::ProcessEvents() {
    std::vector<QueuedEvent> eventsToProcess;
    
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        eventsToProcess = std::move(eventQueue_);
        eventQueue_.clear();
    }
    
    for (const auto& event : eventsToProcess) {
        if (event.data) {
            DispatchEvent(event.type, *event.data);
        }
    }
}

void EventBus::ProcessEvents(EventPriority maxPriority) {
    std::vector<QueuedEvent> eventsToProcess;
    std::vector<QueuedEvent> remainingEvents;
    
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        
        for (auto& event : eventQueue_) {
            if (static_cast<int>(event.priority) <= static_cast<int>(maxPriority)) {
                eventsToProcess.push_back(std::move(event));
            } else {
                remainingEvents.push_back(std::move(event));
            }
        }
        
        eventQueue_ = std::move(remainingEvents);
    }
    
    for (const auto& event : eventsToProcess) {
        if (event.data) {
            DispatchEvent(event.type, *event.data);
        }
    }
}

void EventBus::ClearQueue() {
    std::lock_guard<std::mutex> lock(queueMutex_);
    eventQueue_.clear();
}

size_t EventBus::GetQueueSize() const {
    std::lock_guard<std::mutex> lock(queueMutex_);
    return eventQueue_.size();
}

size_t EventBus::GetSubscriberCount(EventType type) const {
    std::lock_guard<std::mutex> lock(subscribersMutex_);
    
    auto it = subscribers_.find(type);
    if (it != subscribers_.end()) {
        return it->second.size();
    }
    return 0;
}

uint64_t EventBus::GenerateSubscriptionId() {
    return nextSubscriptionId_++;
}

void EventBus::DispatchEvent(EventType type, const EventData& data) {
    std::vector<Subscription> handlers;
    std::vector<Subscription> allHandlers;
    
    {
        std::lock_guard<std::mutex> lock(subscribersMutex_);
        
        auto it = subscribers_.find(type);
        if (it != subscribers_.end()) {
            handlers = it->second;
        }
        
        allHandlers = allEventSubscribers_;
    }
    
    // Call typed handlers
    for (const auto& sub : handlers) {
        try {
            sub.handler(type, data);
        } catch (...) {
            // Log error but continue dispatching
            OutputDebugStringA("Event handler exception\n");
        }
    }
    
    // Call all-event handlers
    for (const auto& sub : allHandlers) {
        try {
            sub.handler(type, data);
        } catch (...) {
            OutputDebugStringA("All-event handler exception\n");
        }
    }
}

// EventLogger implementation
bool EventLogger::enabled_ = false;
std::vector<std::string> EventLogger::recentEvents_;
std::mutex EventLogger::mutex_;

void EventLogger::Enable() {
    enabled_ = true;
}

void EventLogger::Disable() {
    enabled_ = false;
}

bool EventLogger::IsEnabled() {
    return enabled_;
}

void EventLogger::LogEvent(EventType type, const EventData& data) {
    if (!enabled_) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::stringstream ss;
    auto time = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(time);
    
    ss << std::put_time(std::localtime(&time_t), "%H:%M:%S");
    ss << " [" << static_cast<int>(type) << "] ";
    ss <> " from: " << data.source;
    
    std::string logEntry = ss.str();
    
    recentEvents_.push_back(logEntry);
    if (recentEvents_.size() > 1000) {
        recentEvents_.erase(recentEvents_.begin());
    }
}

std::vector<std::string> EventLogger::GetRecentEvents(size_t count) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t start = recentEvents_.size() > count ? recentEvents_.size() - count : 0;
    return std::vector<std::string>(
        recentEvents_.begin() + start,
        recentEvents_.end()
    );
}

// EventBatch implementation
thread_local EventBatch* currentBatch = nullptr;

EventBatch::EventBatch() {
    active_ = true;
    currentBatch = this;
}

EventBatch::~EventBatch() {
    if (active_) {
        Commit();
    }
    currentBatch = nullptr;
}

void EventBatch::Commit() {
    if (!active_) return;
    
    for (const auto& [type, data] : accumulatedEvents_) {
        EventBus::Instance().Publish(type, *data);
    }
    
    accumulatedEvents_.clear();
    active_ = false;
}

void EventBatch::Cancel() {
    accumulatedEvents_.clear();
    active_ = false;
}

} // namespace RawrXD