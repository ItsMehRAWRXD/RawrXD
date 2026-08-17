#pragma once

//==============================================================================
// EventBus.h - Minimal Event Bus for RawrXD Unified
// Phase 15B: Quick implementation to unblock build
//==============================================================================

#include <functional>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

namespace RawrXD {

// Event types
enum class EventType {
    None = 0,
    CompileStarted,
    CompileCompleted,
    CompileError,
    ModelLoaded,
    ModelUnloaded,
    InferenceStarted,
    InferenceCompleted,
    ContextUpdated,
    FileModified,
    AgentAction,
    TaskStarted,
    TaskCompleted
};

// Base event structure
struct Event {
    EventType type = EventType::None;
    std::string source;
    std::string data;
    uint64_t timestamp = 0;
};

// Event listener callback
typedef std::function<void(const Event&)> EventCallback;

// Simple EventBus implementation
class EventBus {
public:
    static EventBus& Instance() {
        static EventBus instance;
        return instance;
    }

    // Subscribe to event type
    void Subscribe(EventType type, EventCallback callback) {
        listeners_[type].push_back(callback);
    }

    // Publish event
    void Publish(const Event& event) {
        auto it = listeners_.find(event.type);
        if (it != listeners_.end()) {
            for (auto& callback : it->second) {
                callback(event);
            }
        }
    }

    // Publish with type
    void Publish(EventType type, const std::string& data = "") {
        Event event;
        event.type = type;
        event.data = data;
        event.timestamp = GetTickCount64();
        Publish(event);
    }
    
    // FireEvent alias for compatibility
    void FireEvent(EventType type, const std::string& data = "") {
        Publish(type, data);
    }

    std::map<EventType, std::vector<EventCallback>> listeners_;
};

} // namespace RawrXD
